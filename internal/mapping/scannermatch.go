package mapping

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// MatchConfidence reflects which matcher fired, not a property of the
// signature itself — see scanner-signatures.yaml's header comment for why
// actions > run_patterns > workflow_name_patterns in strength.
type MatchConfidence string

// The three confidence tiers, in strength order.
const (
	ConfidenceHigh   MatchConfidence = "high"
	ConfidenceMedium MatchConfidence = "medium"
	ConfidenceLow    MatchConfidence = "low"
)

// ScannerMatch is one signature's detection result against a single
// workflow file.
type ScannerMatch struct {
	SignatureID string
	Name        string
	Category    ScannerCategory
	Confidence  MatchConfidence
	// MatchedOn names the exact matcher that fired (e.g.
	// "action:github/codeql-action/analyze" or "run_pattern:\bsemgrep\b")
	// — carried into check facts so a reader can audit why a scanner was
	// judged present without re-deriving the match themselves.
	MatchedOn string
}

// WorkflowFile is the minimal slice of a GitHub Actions workflow YAML's
// structure the matcher needs (jobs -> steps -> uses/run, plus the
// top-level name and trigger list). Deliberately NOT strict-decoded (unlike
// this package's mapping loaders): a real workflow file is external,
// uncontrolled content from a scanned repo with many fields this package
// has no opinion about (permissions:, env:, step id:/with:, ...) —
// rejecting one for using a field this struct doesn't model would be a
// bug, not a safety feature.
type WorkflowFile struct {
	Name string                 `yaml:"name"`
	Jobs map[string]WorkflowJob `yaml:"jobs"`
	// On is the workflow's trigger list (`on:`), left untyped since GitHub
	// Actions allows it as a bare string, a list of strings, or a map keyed
	// by event name — callers needing to inspect it (e.g. "does this run on
	// pull_request?") must type-switch themselves; this package's own
	// MatchWorkflow doesn't use it at all.
	On any `yaml:"on"`
}

// WorkflowJob is one job's steps, plus its own top-level `uses:` — a job
// can itself be a *reusable workflow* call (`jobs.<id>.uses:
// owner/repo/.github/workflows/file.yml@ref`), a completely different
// mechanism from a step's `uses:` (which references an action, not a
// workflow) but syntactically identical for matching purposes: both are
// "owner/repo/path@ref" strings checked against the same ActionMatcher
// slugs. Some tools (e.g. OSV-Scanner's officially recommended
// integration) are predominantly consumed this way rather than as a step.
type WorkflowJob struct {
	Uses  string         `yaml:"uses"`
	Steps []WorkflowStep `yaml:"steps"`
}

// WorkflowStep is the subset of a step's fields the matcher reads.
type WorkflowStep struct {
	Uses string `yaml:"uses"`
	Run  string `yaml:"run"`
}

// ParseWorkflowFile parses raw GitHub Actions workflow YAML into the
// minimal structure MatchWorkflow needs. Non-strict on purpose — see
// WorkflowFile's doc comment.
func ParseWorkflowFile(data []byte) (WorkflowFile, error) {
	var wf WorkflowFile
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return WorkflowFile{}, fmt.Errorf("parse workflow file: %w", err)
	}
	return wf, nil
}

// splitActionRef splits a step's `uses:` value ("owner/repo/path@ref") into
// its slug (before `@`) and ref (after `@`, empty if there's no `@` at
// all — technically invalid GitHub Actions syntax, but this matcher
// shouldn't panic on malformed external content).
func splitActionRef(uses string) (slug, ref string) {
	slug, ref, _ = strings.Cut(uses, "@")
	return slug, ref
}

// MatchWorkflow checks every signature in the registry against wf and
// returns every signature that matched, each at the confidence of its
// strongest matcher (actions > run_patterns > workflow_name_patterns — the
// first one that fires wins; a signature isn't awarded multiple entries
// for matching more than one way). Pure function: no I/O, no GitHub API —
// wf is parsed workflow content the caller already has, from wherever it
// came from.
func (r *ScannerSignatureRegistry) MatchWorkflow(wf WorkflowFile) []ScannerMatch {
	var matches []ScannerMatch
	for _, sig := range r.Signatures {
		if m, ok := matchSignature(sig, wf); ok {
			matches = append(matches, m)
		}
	}
	return matches
}

func matchSignature(sig ScannerSignature, wf WorkflowFile) (ScannerMatch, bool) {
	// wf.Jobs is a map — Go randomizes map iteration order, and which
	// step's exact text ends up in a ScannerMatch's MatchedOn matters: it's
	// carried into check facts, which land in a *signed* evidence pack, so
	// two scans of identical workflow content must always produce
	// byte-identical output. Sorting job keys first makes iteration
	// (and therefore MatchedOn) deterministic without changing which
	// signatures match or at what confidence — only which one of several
	// otherwise-equal matches gets reported when more than one exists.
	jobNames := sortedJobKeys(wf.Jobs)

	for _, name := range jobNames {
		job := wf.Jobs[name]
		if job.Uses != "" {
			if m, ok := matchActionRef(sig, job.Uses); ok {
				return m, true
			}
		}
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}
			if m, ok := matchActionRef(sig, step.Uses); ok {
				return m, true
			}
		}
	}

	for _, name := range jobNames {
		for _, step := range wf.Jobs[name].Steps {
			if step.Run == "" {
				continue
			}
			for i, re := range sig.runPatternRegexps {
				if re.MatchString(step.Run) {
					return newScannerMatch(sig, ConfidenceMedium, "run_pattern:"+sig.Detect.RunPatterns[i]), true
				}
			}
		}
	}

	for i, re := range sig.workflowNamePatternRegexps {
		if re.MatchString(wf.Name) {
			return newScannerMatch(sig, ConfidenceLow, "workflow_name_pattern:"+sig.Detect.WorkflowNamePatterns[i]), true
		}
	}

	return ScannerMatch{}, false
}

func sortedJobKeys(jobs map[string]WorkflowJob) []string {
	names := make([]string, 0, len(jobs))
	for name := range jobs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// matchActionRef checks one "owner/repo/path@ref" reference (a step's
// action `uses:` or a job's reusable-workflow `uses:` — syntactically
// identical, see WorkflowJob's doc comment) against sig's action matchers.
func matchActionRef(sig ScannerSignature, uses string) (ScannerMatch, bool) {
	slug, ref := splitActionRef(uses)
	for _, am := range sig.Detect.Actions {
		if slug == am.Slug && (am.Version == "" || ref == am.Version) {
			return newScannerMatch(sig, ConfidenceHigh, "action:"+uses), true
		}
	}
	return ScannerMatch{}, false
}

func newScannerMatch(sig ScannerSignature, confidence MatchConfidence, matchedOn string) ScannerMatch {
	return ScannerMatch{
		SignatureID: sig.ID,
		Name:        sig.Name,
		Category:    sig.Category,
		Confidence:  confidence,
		MatchedOn:   matchedOn,
	}
}
