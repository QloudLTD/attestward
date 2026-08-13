package cihistory

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gopkg.in/yaml.v3"
)

// mergedJob is one top-level entry of a merged .gitlab-ci.yml.
//
// Deliberately NOT strict-decoded, the same judgment mapping.WorkflowFile
// and mapping.PipelineFile both make: a merged configuration is external,
// uncontrolled content full of keys this package has no opinion about
// (image:, stage:, variables:, needs:, ...), and rejecting one for using a
// field this struct does not model would be a bug, not a safety feature.
type mergedJob struct {
	Artifacts struct {
		Reports map[string]any `yaml:"reports"`
	} `yaml:"artifacts"`
	Rules        []map[string]any `yaml:"rules"`
	Script       scriptLines      `yaml:"script"`
	BeforeScript scriptLines      `yaml:"before_script"`
	AfterScript  scriptLines      `yaml:"after_script"`
}

// scriptLines is GitLab's script field, which the schema allows to be a
// single string, a list of strings, or a list containing nested lists
// (GitLab 16.4+ permits one level of nesting for readability). A plain
// []string decode fails outright on the first form and silently drops the
// third, so the whole matcher would go quiet on a config that is perfectly
// valid — hence the custom unmarshaller rather than trusting one shape.
type scriptLines []string

// UnmarshalYAML accepts every shape GitLab's `script:` schema allows.
func (s *scriptLines) UnmarshalYAML(node *yaml.Node) error {
	var out []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		switch n.Kind {
		case yaml.ScalarNode:
			out = append(out, n.Value)
		case yaml.SequenceNode:
			for _, child := range n.Content {
				walk(child)
			}
		}
	}
	walk(node)
	*s = out
	return nil
}

// canNeverRun reports whether GitLab would never add this job to a pipeline.
//
// GitLab's stock SAST template ships eleven entries whose entire rules list is
// `- when: never` with no condition — ten retired analyzers (bandit-sast,
// gosec-sast, eslint-sast, ...) kept for compatibility, plus the `sast`
// configuration-only stub; Dependency Scanning ships its own stub the same
// way. Every one of them declares the report type exactly like a real
// analyzer, so without this guard any project including the template would be
// credited with scanners it cannot run — and a project that had DISABLED its
// only real analyzer would still read as configured.
//
// A rule carrying any condition (`if:`, `changes:`, `exists:`) counts as
// runnable even when its `when` is never. Deciding otherwise would mean
// evaluating GitLab's rule engine, and being wrong in that direction mints a
// false verified-fail — the failure this codebase exists to avoid.
func (j mergedJob) canNeverRun() bool {
	if len(j.Rules) == 0 {
		return false
	}
	for _, rule := range j.Rules {
		if rule["when"] != "never" {
			return false
		}
		for _, cond := range []string{"if", "changes", "exists"} {
			if _, present := rule[cond]; present {
				return false
			}
		}
	}
	return true
}

func (j mergedJob) declaresReport(reportType string) bool {
	_, declared := j.Artifacts.Reports[reportType]
	return declared
}

// scriptText joins every shell line the job runs, so a run_pattern matches
// across the whole job rather than only its `script:` — a scanner invoked
// from `before_script:` is still invoked.
func (j mergedJob) scriptText() string {
	all := make([]string, 0, len(j.BeforeScript)+len(j.Script)+len(j.AfterScript))
	all = append(all, j.BeforeScript...)
	all = append(all, j.Script...)
	all = append(all, j.AfterScript...)
	return strings.Join(all, "\n")
}

// MatchMergedConfig finds every job in a merged GitLab CI configuration that
// evidences a scanner of the given category.
//
// reportType is GitLab's own `artifacts: reports:` key for the category
// (ReportTypeSAST / ReportTypeDependencyScanning); category selects which
// signatures from the registry are eligible for the two weaker tiers. Both
// are passed because they are genuinely independent: GitLab's report
// declaration is not a registry concept, and a registry signature carries no
// GitLab report type.
//
// ok is false when the merged document is empty or does not parse. That is
// NOT the same as "no scanner configured", and callers must not report it as
// one: the merged YAML is GitLab's own output, so a parse failure means this
// build's expectations are wrong rather than the project's config being bad
// — the identical judgment internal/collect/gitlab/actionssecurity's
// idTokenJobs makes.
func MatchMergedConfig(mergedYAML string, reportType string, category mapping.ScannerCategory, registry *mapping.ScannerSignatureRegistry) (jobs []ScannerJob, ok bool) {
	if strings.TrimSpace(mergedYAML) == "" {
		return nil, false
	}
	// Decoded one node at a time rather than straight into
	// map[string]mergedJob, because a merged configuration's top level is not
	// uniformly job-shaped: `stages:` is a sequence and `variables:` is a map
	// of scalars, and a whole-document decode into a struct-valued map fails
	// outright on the first of them — which would have made every real
	// project's configuration read as unparseable.
	var doc map[string]yaml.Node
	if err := yaml.Unmarshal([]byte(mergedYAML), &doc); err != nil {
		return nil, false
	}

	compiled := compileSignatures(category, registry)

	// The source is a Go map, so iteration order is randomized. Facts land
	// in a signed evidence pack, and two scans of identical configuration
	// must produce byte-identical output — the same reason
	// mapping.MatchWorkflow sorts its own job keys.
	names := make([]string, 0, len(doc))
	for name := range doc {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		// A hidden job (".sast-analyzer") is a YAML anchor for other jobs to
		// extend, not a job GitLab ever adds to a pipeline.
		if strings.HasPrefix(name, ".") {
			continue
		}
		node := doc[name]
		if node.Kind != yaml.MappingNode {
			continue // stages:, a scalar — not a job
		}
		var job mergedJob
		if err := node.Decode(&job); err != nil {
			continue
		}
		if job.canNeverRun() {
			continue
		}
		if match, found := matchJob(name, job, reportType, compiled); found {
			jobs = append(jobs, match)
		}
	}
	return jobs, true
}

// matchJob applies the three tiers in strength order and returns the first
// that fires, so one job is never reported twice for matching two ways.
func matchJob(name string, job mergedJob, reportType string, compiled []compiledSignature) (ScannerJob, bool) {
	if job.declaresReport(reportType) {
		return ScannerJob{
			Name: name, Tool: "GitLab " + reportType + " report", Confidence: ConfidenceHigh,
			MatchedOn: "artifacts.reports." + reportType,
		}, true
	}

	script := job.scriptText()
	if script != "" {
		for _, sig := range compiled {
			for i, re := range sig.runPatterns {
				if re.MatchString(script) {
					return ScannerJob{
						Name: name, Tool: sig.name, Confidence: ConfidenceMedium,
						MatchedOn: "run_pattern:" + sig.runPatternSources[i],
					}, true
				}
			}
		}
	}

	for _, sig := range compiled {
		for i, re := range sig.namePatterns {
			if re.MatchString(name) {
				return ScannerJob{
					Name: name, Tool: sig.name, Confidence: ConfidenceLow,
					MatchedOn: "job_name_pattern:" + sig.namePatternSources[i],
				}, true
			}
		}
	}

	return ScannerJob{}, false
}

// compiledSignature holds one registry signature's patterns compiled for
// GitLab matching. internal/mapping compiles its own copies at load time but
// keeps them unexported and reachable only through MatchWorkflow /
// MatchPipeline, neither of which takes GitLab CI's shape — see the package
// doc comment for why a `gitlab_jobs:` registry matcher is separately-scoped
// work rather than something to add here.
type compiledSignature struct {
	name               string
	runPatterns        []*regexp.Regexp
	runPatternSources  []string
	namePatterns       []*regexp.Regexp
	namePatternSources []string
}

// compileSignatures compiles the eligible signatures' patterns.
//
// A pattern that does not compile is SKIPPED rather than failing the scan:
// internal/mapping's own loader already rejects a malformed regex at load
// time (loudly, at startup), so reaching this branch means the registry
// changed under a compiled binary — and losing one pattern is better than
// losing every check that depends on the registry.
func compileSignatures(category mapping.ScannerCategory, registry *mapping.ScannerSignatureRegistry) []compiledSignature {
	if registry == nil {
		return nil
	}
	var out []compiledSignature
	for _, sig := range registry.Signatures {
		if sig.Category != category {
			continue
		}
		cs := compiledSignature{name: sig.Name}
		for _, p := range sig.Detect.RunPatterns {
			if re, err := regexp.Compile(p); err == nil {
				cs.runPatterns = append(cs.runPatterns, re)
				cs.runPatternSources = append(cs.runPatternSources, p)
			}
		}
		for _, p := range sig.Detect.WorkflowNamePatterns {
			if re, err := regexp.Compile(p); err == nil {
				cs.namePatterns = append(cs.namePatterns, re)
				cs.namePatternSources = append(cs.namePatternSources, p)
			}
		}
		if len(cs.runPatterns) > 0 || len(cs.namePatterns) > 0 {
			out = append(out, cs)
		}
	}
	return out
}

// StrongestConfidence returns the best confidence among the matched jobs, and
// false when there are none.
func StrongestConfidence(jobs []ScannerJob) (Confidence, bool) {
	if len(jobs) == 0 {
		return "", false
	}
	best := jobs[0].Confidence
	for _, j := range jobs[1:] {
		if j.Confidence.Stronger(best) {
			best = j.Confidence
		}
	}
	return best, true
}

// JobsToFacts renders matched jobs for a CheckResult's Facts.
func JobsToFacts(jobs []ScannerJob) []map[string]any {
	out := make([]map[string]any, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, map[string]any{
			"job": j.Name, "tool": j.Tool,
			"confidence": string(j.Confidence), "matched_on": j.MatchedOn,
		})
	}
	return out
}

// CoverageToFacts renders per-release coverage for a CheckResult's Facts.
func CoverageToFacts(coverage []Coverage) []map[string]any {
	out := make([]map[string]any, 0, len(coverage))
	for _, c := range coverage {
		out = append(out, map[string]any{
			"tag": c.Release.TagName, "commit": c.Release.CommitSHA, "coverage": string(c.Status),
		})
	}
	return out
}

// DescribeJobNames renders the matched job names for a Reason string.
func DescribeJobNames(jobs []ScannerJob) string {
	names := make([]string, 0, len(jobs))
	for _, j := range jobs {
		names = append(names, j.Name)
	}
	return strings.Join(names, ", ")
}

// MissingCoverageTags names the releases with no matched run at all.
func MissingCoverageTags(coverage []Coverage) []string {
	var out []string
	for _, c := range coverage {
		if c.Status == CoverageMissing {
			out = append(out, c.Release.TagName)
		}
	}
	return out
}

// FailedCoverageTags names the releases whose only matched runs failed.
func FailedCoverageTags(coverage []Coverage) []string {
	var out []string
	for _, c := range coverage {
		if c.Status == CoverageFailed {
			out = append(out, c.Release.TagName)
		}
	}
	return out
}

// Plural is the shared "1 release" / "3 releases" helper the two collectors'
// Reason strings both need.
func Plural(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}
