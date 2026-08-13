// Package cihistory is the GitLab counterpart of
// internal/collect/github/runhistory: the shared machinery C05
// (sast-history) and C06 (sca-history) both need to answer "is a scanner
// configured, and did it actually run" against GitLab CI.
//
// It is a within-platform shared package, not a cross-platform one — ADR-0005
// forbids internal/collect/gitlab reaching into internal/collect/github, and
// nothing here imports another platform's tree. What it does import is
// internal/mapping, which is platform-neutral (it holds the
// scanner-signature registry that GitHub and Azure DevOps both already read).
//
// # How a GitLab CI scanner is detected, and why not by job name
//
// GitLab defines a security scanner job by what it PUBLISHES, not what it is
// called: a job that emits SAST findings declares
// `artifacts: reports: sast:`, and one that emits dependency findings
// declares `artifacts: reports: dependency_scanning:`. That declaration is
// the contract GitLab itself reads to ingest a report, so it is a stronger
// and more general signal than any name convention — it catches the stock
// templates AND a hand-written job wrapping a third-party tool that emits
// GitLab's report format, and it cannot be faked by naming a job "sast".
//
// The merged CI configuration from GET /projects/:id/ci/lint is where that
// declaration is readable, because GitLab has already expanded every
// `include:` into it. Reading the raw .gitlab-ci.yml instead would see
// `include: template: Jobs/SAST.gitlab-ci.yml` and no jobs at all.
//
// Two whole classes of entry in that merged document must be excluded, and
// both were confirmed against a live lint of a project running the stock
// templates (2026-08-13, gitlab.com/qloud-ltd-group/attestward-fixtures,
// recorded as ci-lint-security-templates.json):
//
//   - Hidden jobs — keys starting with "." (`.sast-analyzer`,
//     `.ds-analyzer`). These are YAML anchors for other jobs to extend; they
//     never run.
//   - Unconditionally disabled jobs — `rules: [{when: never}]` with no
//     condition. GitLab's own SAST template ships ELEVEN of these: the
//     `sast` configuration-only stub, plus ten retired analyzers kept for
//     compatibility (bandit-sast, brakeman-sast, eslint-sast,
//     flawfinder-sast, gosec-sast, mobsf-android-sast, mobsf-ios-sast,
//     nodejs-scan-sast, phpcs-security-audit-sast, security-code-scan-sast).
//     The Dependency Scanning template ships its own `dependency_scanning`
//     stub the same way.
//
// Counted exactly, against the live template (2026-08-13): twenty-one
// entries declare `artifacts: reports: sast:`, and thirteen of them can
// never run — the two hidden anchors and the eleven above. Without both
// exclusions, every project that merely includes the template would be
// credited with thirteen scanners it does not have, and a project that had
// deliberately disabled its only real analyzer would still read as
// configured. What survives is the eight that genuinely can run
// (gitlab-advanced-sast, gitlab-advanced-sast-cpp, gitlab-advanced-sast-ext,
// kubesec-sast, pmd-apex-sast, semgrep-sast, sobelow-sast, spotbugs-sast),
// each carrying real `if:`/`exists:` rules; Dependency Scanning's own five
// entries reduce to three the same way.
//
// # The confidence ladder
//
// Three tiers, matching internal/collect/github/runhistory's actions >
// run_patterns > workflow_name_patterns ladder as closely as GitLab's
// vocabulary allows:
//
//   - High: a runnable job declares the report type. GitLab's own contract,
//     see above.
//   - Medium: a job's script text matches a signature's run_patterns from
//     mappings/scanner-signatures.yaml — a real CLI invocation (`snyk test`,
//     `semgrep`, `sonar-scanner`) that does not necessarily emit a GitLab
//     report. This exists so a project using a third-party scanner is not
//     reported as having none.
//   - Low: a job's NAME matches a signature's workflow_name_patterns. A
//     naming convention, not evidence of tool usage — the same weight its
//     GitHub twin gives a workflow name.
//
// ⚠ The registry's own regexes are compiled here rather than reused:
// internal/mapping keeps its compiled forms unexported and offers
// MatchWorkflow/MatchPipeline, neither of which takes GitLab CI's shape. A
// GitLab matcher inside internal/mapping (the `gitlab_jobs:` schema field
// that would parallel #149's `ado_tasks:`) is real, separately-scoped
// registry work tracked in issue #1; this package reads the registry's
// EXPORTED pattern strings, which is data (ADR-0003), and does the GitLab-
// shaped matching itself.
//
// # Run history
//
// GET /projects/:id/jobs answers cadence and per-release coverage from one
// walk: it returns every job newest-first with its name, status, finished_at
// and its pipeline's commit SHA (verified live 2026-08-13, recorded as
// jobs-security-pipelines.json). The walk stops as soon as it reaches a job
// older than the lookback window, so a long-lived project does not page its
// whole CI history — and it stops at a page bound too, which callers must
// surface rather than treat as a complete read (see JobWalk.Truncated).
package cihistory

import (
	"path/filepath"
	"sort"
	"time"
)

// ReportTypeSAST and ReportTypeDependencyScanning are the two
// `artifacts: reports:` keys this build detects, spelled exactly as GitLab
// spells them in a merged CI configuration and in a job's artifacts listing.
// Secret detection is deliberately absent: it is C04's subject, and a
// project running ONLY secret detection must not read as having SAST.
const (
	ReportTypeSAST               = "sast"
	ReportTypeDependencyScanning = "dependency_scanning"
)

// Confidence mirrors mapping.MatchConfidence's three tiers — duplicated as
// this package's own type rather than aliased, so the meaning of each tier
// on GitLab (see the package doc comment) is documented where it is used.
type Confidence string

// The three tiers, in strength order.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Stronger reports whether c outranks other.
func (c Confidence) Stronger(other Confidence) bool { return confidenceRank[c] > confidenceRank[other] }

var confidenceRank = map[Confidence]int{ConfidenceLow: 1, ConfidenceMedium: 2, ConfidenceHigh: 3}

// ScannerJob is one job in the merged CI configuration that this build
// judges to be a scanner of the requested category.
type ScannerJob struct {
	// Name is the job's key in the merged configuration — the same string
	// GET /projects/:id/jobs reports as a run's `name`, which is what makes
	// run linkage possible without a second lookup.
	Name string
	// Tool names the tool, when a registry signature identified it
	// ("Snyk"), or GitLab's own report type when the evidence was the
	// report declaration itself.
	Tool string
	// Confidence is which matcher fired; see the package doc comment.
	Confidence Confidence
	// MatchedOn names the exact evidence, for Facts — "artifacts.reports.sast",
	// "run_pattern:snyk (test|monitor)", or "job_name_pattern:(?i)\\bsnyk\\b".
	MatchedOn string
}

// JobRun is one entry of GET /projects/:id/jobs, reduced to what cadence and
// per-release coverage read.
type JobRun struct {
	Name string
	// Status is GitLab's job status: success, failed, canceled, skipped,
	// running, created, manual, pending.
	Status string
	// FinishedAt is zero for a job that has not finished. A job still
	// running is not evidence that a scan happened.
	FinishedAt time.Time
	// PipelineSHA is the commit the job's pipeline ran against — the key
	// per-release coverage joins on.
	PipelineSHA string
	// ReportTypes are the artifacts:reports: types this job actually
	// published, when GitLab still holds them. Artifacts expire (30 days by
	// default), so an empty list is never evidence that nothing was
	// published — it is only ever used to ADD a run, never to discard one.
	ReportTypes []string
}

// Succeeded reports whether this run is evidence a scan completed.
func (r JobRun) Succeeded() bool { return r.Status == "success" }

// Release is one release in scope, reduced to what this package joins on.
type Release struct {
	TagName    string
	CommitSHA  string
	ReleasedAt time.Time
}

// Coverage is one release's scanner-run outcome.
type Coverage struct {
	Release Release
	Status  CoverageStatus
}

// CoverageStatus is how a release fared.
type CoverageStatus string

// The three outcomes, matching internal/collect/github/runhistory's own
// vocabulary so a reader moving between the two platforms reads the same
// words.
const (
	// CoverageRan is at least one matched job that finished successfully on
	// the release's commit.
	CoverageRan CoverageStatus = "ran"
	// CoverageFailed is at least one matched job on the release's commit,
	// none of which succeeded.
	CoverageFailed CoverageStatus = "failed"
	// CoverageMissing is no matched job on the release's commit at all.
	CoverageMissing CoverageStatus = "missing"
)

// Cadence summarises scanner activity across the lookback window.
type Cadence struct {
	Runs           int
	RunsPerWeek    float64
	LongestGapDays float64
}

// -----------------------------------------------------------------------
// release lookback
// -----------------------------------------------------------------------

// FilterReleasesInLookback duplicates internal/collect/github/runhistory's
// identical function rather than importing it, for the reason
// internal/collect/gitlab/provenance's own copy states: ADR-0005 keeps every
// platform package independent, and the pattern match, newest-first sort and
// count-or-date cutoff are small enough that duplicating costs less than a
// cross-platform dependency.
//
// ⚠ Both cutoffs apply and whichever bites first wins — the count bound is
// checked BEFORE the date bound, so an eleventh release inside the window is
// excluded rather than the window silently widening.
func FilterReleasesInLookback(releases []Release, tagPattern string, lookbackReleases, lookbackMonths int, now time.Time) []Release {
	var matched []Release
	for _, r := range releases {
		if ok, err := filepath.Match(tagPattern, r.TagName); err == nil && ok {
			matched = append(matched, r)
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].ReleasedAt.After(matched[j].ReleasedAt) })

	cutoff := now.AddDate(0, -lookbackMonths, 0)
	out := make([]Release, 0, len(matched))
	for _, r := range matched {
		if len(out) >= lookbackReleases {
			break
		}
		if r.ReleasedAt.Before(cutoff) {
			break
		}
		out = append(out, r)
	}
	return out
}

// -----------------------------------------------------------------------
// coverage and cadence
// -----------------------------------------------------------------------

// LinkRunsToReleases decides, per release, whether a matched scanner job ran
// on that release's commit.
//
// The join key is the commit SHA, not the branch or the tag: a release is cut
// from a commit, and the question this answers is whether THAT code was
// scanned. A run on a later commit of the same branch does not evidence it.
func LinkRunsToReleases(releases []Release, runs []JobRun) []Coverage {
	byCommit := map[string][]JobRun{}
	for _, run := range runs {
		byCommit[run.PipelineSHA] = append(byCommit[run.PipelineSHA], run)
	}

	out := make([]Coverage, 0, len(releases))
	for _, rel := range releases {
		status := CoverageMissing
		for _, run := range byCommit[rel.CommitSHA] {
			if run.Succeeded() {
				status = CoverageRan
				break
			}
			status = CoverageFailed
		}
		out = append(out, Coverage{Release: rel, Status: status})
	}
	return out
}

// ComputeCadence summarises how regularly a scanner ran across the window.
//
// LongestGapDays measures from the window's start to the first run, between
// consecutive runs, and from the last run to now — a scanner that ran daily
// for a week eleven months ago and never again has a huge gap, which is the
// whole point. Only finished runs are counted; a job still in flight has not
// scanned anything yet.
func ComputeCadence(runs []JobRun, windowStart, now time.Time) Cadence {
	var times []time.Time
	for _, r := range runs {
		if r.FinishedAt.IsZero() || r.FinishedAt.Before(windowStart) {
			continue
		}
		times = append(times, r.FinishedAt)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })

	windowDays := now.Sub(windowStart).Hours() / 24
	c := Cadence{Runs: len(times)}
	if windowDays > 0 {
		c.RunsPerWeek = float64(len(times)) / (windowDays / 7)
	}

	prev := windowStart
	for _, t := range times {
		if gap := t.Sub(prev).Hours() / 24; gap > c.LongestGapDays {
			c.LongestGapDays = gap
		}
		prev = t
	}
	if gap := now.Sub(prev).Hours() / 24; gap > c.LongestGapDays {
		c.LongestGapDays = gap
	}
	return c
}
