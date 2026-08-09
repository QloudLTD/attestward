package mapping

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// PipelineStep is the subset of an Azure Pipelines step's fields the
// matcher reads. A step is exactly one of: a task step (Task set, written
// "TaskName@Version" — see ADOTaskMatcher's doc comment for how Version is
// matched), an inline-shell step (exactly one of Script/Bash/Pwsh/
// PowerShell set — Azure Pipelines' four inline-shell step shorthands), or
// a `template:` reference to another file (Template set) — see
// PipelineFile's doc comment for why a template step's content is
// unreachable here. DisplayName may be set alongside any of the above and
// feeds workflow_name_patterns matching the same way the pipeline's own
// Name does.
type PipelineStep struct {
	Task        string `yaml:"task"`
	Script      string `yaml:"script"`
	Bash        string `yaml:"bash"`
	Pwsh        string `yaml:"pwsh"`
	PowerShell  string `yaml:"powershell"`
	Template    string `yaml:"template"`
	DisplayName string `yaml:"displayName"`
}

// runText returns the step's inline-shell text for run_patterns matching —
// whichever of Script/Bash/Pwsh/PowerShell is set (a well-formed step has
// at most one) — or "" for a task or template step.
func (s PipelineStep) runText() string {
	switch {
	case s.Script != "":
		return s.Script
	case s.Bash != "":
		return s.Bash
	case s.Pwsh != "":
		return s.Pwsh
	case s.PowerShell != "":
		return s.PowerShell
	default:
		return ""
	}
}

// PipelineJobEntry is one entry of a `jobs:` list — either a real job (Job
// set, with its own Steps) or a `template:` reference to another file this
// matcher cannot see the content of (Template set).
//
// A deployment job (`- deployment: <name>`, whose steps live under
// strategy.runOnce/canary/rolling.deploy.steps rather than a plain
// `steps:` list) is not represented by this struct at all: none of its
// keys (deployment, environment, strategy) bind to Job/Template/Steps, so
// it decodes as an all-empty PipelineJobEntry and MatchPipeline silently
// does not see its steps — unlike a `template:` reference, there is no
// field here to recognize a deployment job by, so it isn't (and can't
// currently be) recorded as an UnresolvedTemplateRef either. This is a
// known, documented gap (see MatchPipeline's doc comment), not template
// resolution's job to cover; deployment-job traversal is deferred to a
// follow-up.
type PipelineJobEntry struct {
	Job      string         `yaml:"job"`
	Template string         `yaml:"template"`
	Steps    []PipelineStep `yaml:"steps"`
}

// PipelineStageEntry is one entry of a `stages:` list — either a real stage
// (Stage set, with its own Jobs) or a `template:` reference, same shape as
// PipelineJobEntry.
type PipelineStageEntry struct {
	Stage    string             `yaml:"stage"`
	Template string             `yaml:"template"`
	Jobs     []PipelineJobEntry `yaml:"jobs"`
}

// PipelineExtends is a pipeline's root-level `extends:` block — Microsoft's
// mandated-template pattern (e.g. `extends: {template: v1/pipeline.yml@templates}`),
// where the entire pipeline body is supplied by another file rather than
// any of Steps/Jobs/Stages being present at all. Template is recorded as
// an UnresolvedTemplateRef the same as any other template reference — see
// PipelineFile's doc comment.
type PipelineExtends struct {
	Template string `yaml:"template"`
}

// PipelineFile is the minimal slice of an Azure Pipelines YAML file's
// structure MatchPipeline needs: the pipeline's own name, and steps
// wherever Azure Pipelines allows them to appear — directly at the top
// level (single-stage, single-job pipelines), nested under a job, or
// nested under a job nested under a stage — plus a root-level `extends:`,
// the standard enterprise mandated-template pattern where the whole
// pipeline body lives in another file. Deliberately NOT strict-decoded
// (unlike this package's mapping loaders): a real pipeline file is
// external, uncontrolled content from a scanned repo with many fields this
// package has no opinion about (trigger:, pool:, variables:, resources:,
// ...) — rejecting one for using a field this struct doesn't model would be
// a bug, not a safety feature. Mirrors WorkflowFile's identical rationale
// for GitHub Actions workflows.
//
// Unlike WorkflowFile.Jobs (a GitHub Actions map keyed by job ID), Azure
// Pipelines' jobs/stages are YAML lists — decoding preserves file order, so
// MatchPipeline needs no equivalent of scannermatch.go's sortedJobKeys to
// stay deterministic.
//
// A `template:` reference (step-, job-, or stage-level, or the root-level
// `extends:`) points at content this struct cannot see — this package does
// no I/O, so it cannot fetch and inline the referenced file the way a
// collector with API access might. MatchPipeline records each one as an
// UnresolvedTemplateRef instead of silently ignoring it.
//
// One known gap NOT covered by the above: a deployment job's steps
// (`- deployment: <name>`, steps nested under strategy.runOnce/canary/
// rolling) are invisible to this struct entirely — see
// PipelineJobEntry's doc comment for why that's a silent, not an
// unresolved-flagged, gap, and MatchPipeline's doc comment for the same
// caveat restated at the matcher level.
type PipelineFile struct {
	Name    string               `yaml:"name"`
	Steps   []PipelineStep       `yaml:"steps"`
	Jobs    []PipelineJobEntry   `yaml:"jobs"`
	Stages  []PipelineStageEntry `yaml:"stages"`
	Extends PipelineExtends      `yaml:"extends"`
}

// ParsePipelineFile parses raw Azure Pipelines YAML into the minimal
// structure MatchPipeline needs. Non-strict on purpose — see PipelineFile's
// doc comment.
func ParsePipelineFile(data []byte) (PipelineFile, error) {
	var pf PipelineFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return PipelineFile{}, fmt.Errorf("parse pipeline file: %w", err)
	}
	return pf, nil
}

// UnresolvedTemplateRef is one `template:` reference MatchPipeline could
// not evaluate. This package does no I/O and cannot fetch template file
// content the way a collector might, so a signature genuinely implemented
// via a templated step/job/stage this matcher never sees would otherwise
// look indistinguishable from "not present at all". Recording each one
// lets a caller (e.g. a future Azure DevOps pipelinehistory collector)
// avoid asserting a confident "no scanner found" from a partial view — the
// same distinction internal/collect/github/actionssecurity's
// resolveReusableWorkflows draws for GitHub reusable-workflow references
// it can't safely resolve either (see its unresolvedExternalWorkflow).
type UnresolvedTemplateRef struct {
	// Ref is the template reference exactly as written (e.g.
	// "templates/build-steps.yml" or "templates/jobs.yml@self").
	Ref string
}

// MatchPipeline is MatchWorkflow's counterpart for Azure Pipelines YAML: it
// checks every signature in the registry against pl and returns every
// signature that matched, each at the confidence of its strongest matcher
// (ado_tasks > run_patterns > workflow_name_patterns — the same ladder as
// MatchWorkflow's actions > run_patterns > workflow_name_patterns; the
// first one that fires wins, so a signature isn't awarded multiple entries
// for matching more than one way). It also returns every `template:`
// reference found anywhere in pl — step, job-entry, or stage-entry
// position, or the pipeline's own root-level `extends:` — as an
// UnresolvedTemplateRef — see that type's doc comment. Pure function: no
// I/O, no Azure DevOps API — pl is parsed pipeline content the caller
// already has, from wherever it came from.
//
// Known gap: a deployment job's steps (`- deployment: <name>` list
// entries) are not traversed at all — PipelineJobEntry has no field for
// one, so they decode as empty and contribute neither a match nor an
// UnresolvedTemplateRef. See PipelineJobEntry's doc comment; traversal
// support is deferred to a follow-up rather than attempted here.
func (r *ScannerSignatureRegistry) MatchPipeline(pl PipelineFile) ([]ScannerMatch, []UnresolvedTemplateRef) {
	steps, unresolved := collectPipelineSteps(pl)

	var matches []ScannerMatch
	for _, sig := range r.Signatures {
		if m, ok := matchPipelineSignature(sig, pl, steps); ok {
			matches = append(matches, m)
		}
	}
	return matches, unresolved
}

// collectPipelineSteps flattens every step Azure Pipelines allows
// (top-level, job-nested, stage/job-nested) into one ordered slice, and
// collects every template: reference found along the way (step-level,
// job-entry-level, stage-entry-level, and the pipeline's own root-level
// extends:) instead of descending into it.
func collectPipelineSteps(pl PipelineFile) (steps []PipelineStep, unresolved []UnresolvedTemplateRef) {
	appendSteps := func(ss []PipelineStep) {
		for _, s := range ss {
			if s.Template != "" {
				unresolved = append(unresolved, UnresolvedTemplateRef{Ref: s.Template})
				continue
			}
			steps = append(steps, s)
		}
	}
	appendJob := func(j PipelineJobEntry) {
		if j.Template != "" {
			unresolved = append(unresolved, UnresolvedTemplateRef{Ref: j.Template})
			return
		}
		appendSteps(j.Steps)
	}

	if pl.Extends.Template != "" {
		unresolved = append(unresolved, UnresolvedTemplateRef{Ref: pl.Extends.Template})
	}

	appendSteps(pl.Steps)
	for _, j := range pl.Jobs {
		appendJob(j)
	}
	for _, st := range pl.Stages {
		if st.Template != "" {
			unresolved = append(unresolved, UnresolvedTemplateRef{Ref: st.Template})
			continue
		}
		for _, j := range st.Jobs {
			appendJob(j)
		}
	}

	return steps, unresolved
}

func matchPipelineSignature(sig ScannerSignature, pl PipelineFile, steps []PipelineStep) (ScannerMatch, bool) {
	for _, step := range steps {
		if step.Task == "" {
			continue
		}
		if m, ok := matchADOTask(sig, step.Task); ok {
			return m, true
		}
	}

	for _, step := range steps {
		text := step.runText()
		if text == "" {
			continue
		}
		for i, re := range sig.runPatternRegexps {
			if re.MatchString(text) {
				return newScannerMatch(sig, ConfidenceMedium, "run_pattern:"+sig.Detect.RunPatterns[i]), true
			}
		}
	}

	names := make([]string, 0, len(steps)+1)
	names = append(names, pl.Name)
	for _, step := range steps {
		if step.DisplayName != "" {
			names = append(names, step.DisplayName)
		}
	}
	for i, re := range sig.workflowNamePatternRegexps {
		for _, name := range names {
			if re.MatchString(name) {
				return newScannerMatch(sig, ConfidenceLow, "workflow_name_pattern:"+sig.Detect.WorkflowNamePatterns[i]), true
			}
		}
	}

	return ScannerMatch{}, false
}

// matchADOTask checks one step's `task:` reference against sig's
// ado_tasks matchers: case-insensitive on the exact task-name string
// before the last `@` (no dot-segment splitting — see ADOTaskMatcher's
// doc comment for why a fully-qualified marketplace ref or a GUID
// deliberately doesn't cross-match a short name), and, if Major is set,
// an exact match against only the major-version segment (the text before
// the first `.`) of the post-`@` version — so a full version pin like
// `@1.2.3` still matches major: "1".
func matchADOTask(sig ScannerSignature, taskRef string) (ScannerMatch, bool) {
	name, version := splitADOTaskRef(taskRef)
	major := adoTaskMajorSegment(version)
	for _, tm := range sig.Detect.ADOTasks {
		if strings.EqualFold(name, tm.Task) && (tm.Major == "" || major == tm.Major) {
			return newScannerMatch(sig, ConfidenceHigh, "ado_task:"+taskRef), true
		}
	}
	return ScannerMatch{}, false
}

// splitADOTaskRef splits a step's `task:` value ("TaskName@Version") into
// its task name and version string, splitting on the LAST `@` rather than
// the first — an ADO task name never legitimately contains `@`, but the
// last occurrence is the conservative choice if one somehow did, mirroring
// splitActionRef's own "don't panic on malformed external content"
// stance. No `@` at all yields an empty version, which — after
// adoTaskMajorSegment — matches any ADOTaskMatcher with an empty Major
// (same "empty means any" rule as ActionMatcher.Version).
func splitADOTaskRef(taskRef string) (name, version string) {
	i := strings.LastIndex(taskRef, "@")
	if i < 0 {
		return taskRef, ""
	}
	return taskRef[:i], taskRef[i+1:]
}

// adoTaskMajorSegment returns the major-version segment of an ADO task's
// version string — the text before its first `.`, or the whole string if
// it has none. Azure Pipelines allows pinning a task to a full version
// (Microsoft's own docs use forms like "GoTool@0.3.1"), not just a bare
// major like "@1"; comparing only this segment against
// ADOTaskMatcher.Major lets major: "0" still match "0.3.1".
func adoTaskMajorSegment(version string) string {
	major, _, _ := strings.Cut(version, ".")
	return major
}
