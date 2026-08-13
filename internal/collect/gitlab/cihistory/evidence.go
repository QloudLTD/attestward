package cihistory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// maxJobPages bounds the newest-first job walk.
//
// The walk normally stops on its own the moment it reaches a job older than
// the lookback window. This bound is the other stop condition, for a project
// whose CI volume is high enough that a year of history is more than 2,000
// jobs — reading all of it would dominate a scan of the whole group. Hitting
// it is reported through JobWalk.Truncated rather than swallowed, because a
// truncated pool can undercount and a check that certified an absence from
// one would be asserting more than it read.
const maxJobPages = 20

// jobsPerPage is GitLab's maximum page size — the same value the shared
// client uses, for the same reason: fewer round trips.
const jobsPerPage = 100

// CILintResponse is GET /projects/:id/ci/lint, reduced to what this package
// reads.
//
// Errors is quoted verbatim into a not-checkable Reason rather than
// paraphrased: the lint API answers 200 with valid=false both for a project
// with no CI configuration at all and for one whose configuration exists but
// has an unresolvable include, and guessing between them would put an
// unsupported claim in the pack.
type CILintResponse struct {
	Valid      bool     `json:"valid"`
	Errors     []string `json:"errors"`
	MergedYAML string   `json:"merged_yaml"`
}

// FetchCILint reads the merged CI configuration.
func FetchCILint(ctx context.Context, client *gitlabcollect.Client, projID string) (CILintResponse, error) {
	var l CILintResponse
	err := gitlabcollect.GetJSON(ctx, client, "/projects/"+projID+"/ci/lint", nil, &l)
	return l, err
}

// releaseRaw is GET /projects/:id/releases, reduced to what this package
// reads. commit.id is the whole reason this type exists separately from
// internal/collect/gitlab/provenance's own release struct: that one reads
// assets and never needed the commit, and per-release scanner coverage joins
// on nothing else.
type releaseRaw struct {
	TagName    string    `json:"tag_name"`
	ReleasedAt time.Time `json:"released_at"`
	Commit     struct {
		ID string `json:"id"`
	} `json:"commit"`
}

// FetchReleases lists the project's releases with the commit each was cut
// from. Verified live 2026-08-13: the Releases API returns a full `commit`
// object per release, so no second call is needed to resolve a tag to a SHA
// — unlike GitHub, where runhistory.ResolveReleaseCommit has to walk
// git/ref then git/tags.
func FetchReleases(ctx context.Context, client *gitlabcollect.Client, projID string) ([]Release, error) {
	raw, err := gitlabcollect.GetJSONPaged[releaseRaw](ctx, client, "/projects/"+projID+"/releases", nil)
	if err != nil {
		return nil, err
	}
	out := make([]Release, 0, len(raw))
	for _, r := range raw {
		out = append(out, Release{TagName: r.TagName, CommitSHA: r.Commit.ID, ReleasedAt: r.ReleasedAt})
	}
	return out, nil
}

// jobRaw is one entry of GET /projects/:id/jobs. Shape confirmed live
// 2026-08-13 against a project running GitLab's stock security templates and
// recorded as jobs-security-pipelines.json.
type jobRaw struct {
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	FinishedAt *time.Time `json:"finished_at"`
	Pipeline   struct {
		SHA string `json:"sha"`
	} `json:"pipeline"`
	Artifacts []struct {
		FileType string `json:"file_type"`
	} `json:"artifacts"`
}

// JobWalk is the result of the bounded jobs read.
type JobWalk struct {
	Runs []JobRun
	// Truncated is true when the walk stopped at maxJobPages rather than
	// because it had reached the far side of the lookback window — the pool
	// is then incomplete, and a caller must not certify an absence from it.
	Truncated bool
}

// FetchJobsInWindow walks GET /projects/:id/jobs newest-first and returns
// every job that finished on or after windowStart.
//
// It pages by hand rather than through gitlabcollect.GetJSONPaged because it
// needs to STOP early. GitLab returns jobs in descending id order (verified
// live), so the first job older than the window means every remaining job is
// older too — and a project with years of CI history would otherwise page its
// entire job table on every scan just to answer a twelve-month question.
//
// A job with no finished_at (still queued or running) is skipped rather than
// counted: it has not scanned anything yet. It does NOT stop the walk —
// pending jobs sit at the newest end, and stopping there would return an
// empty pool for any project with CI in flight.
func FetchJobsInWindow(ctx context.Context, client *gitlabcollect.Client, projID string, windowStart time.Time) (JobWalk, error) {
	var walk JobWalk
	for page := 1; ; page++ {
		if page > maxJobPages {
			walk.Truncated = true
			return walk, nil
		}
		query := url.Values{
			"per_page": {strconv.Itoa(jobsPerPage)},
			"page":     {strconv.Itoa(page)},
		}
		var batch []jobRaw
		if err := gitlabcollect.GetJSON(ctx, client, "/projects/"+projID+"/jobs", query, &batch); err != nil {
			return JobWalk{}, err
		}
		for _, j := range batch {
			if j.FinishedAt == nil {
				continue
			}
			if j.FinishedAt.Before(windowStart) {
				return walk, nil
			}
			walk.Runs = append(walk.Runs, JobRun{
				Name:        j.Name,
				Status:      j.Status,
				FinishedAt:  *j.FinishedAt,
				PipelineSHA: j.Pipeline.SHA,
				ReportTypes: fileTypes(j),
			})
		}
		if len(batch) < jobsPerPage {
			return walk, nil
		}
	}
}

func fileTypes(j jobRaw) []string {
	out := make([]string, 0, len(j.Artifacts))
	for _, a := range j.Artifacts {
		out = append(out, a.FileType)
	}
	return out
}

// SelectRuns narrows a job pool to the runs that evidence a scan of the
// given category.
//
// Two independent signals, unioned:
//
//   - the job's name is one of the scanner jobs found in the merged CI
//     configuration, and
//   - the job published an artifact of the report type, whatever it is
//     called.
//
// The second only ever ADDS runs, which is why it is safe despite being
// unreliable: GitLab expires job artifacts (30 days by default), so a job
// that scanned eleven months ago reports no artifacts today. Reading that
// absence as "did not scan" would be a false negative; reading its presence
// as "did scan" is sound, and it rescues a run whose job was since renamed
// out of the current configuration.
func SelectRuns(runs []JobRun, jobs []ScannerJob, reportType string) []JobRun {
	names := map[string]bool{}
	for _, j := range jobs {
		names[j.Name] = true
	}
	var out []JobRun
	for _, r := range runs {
		if names[r.Name] || hasReportType(r, reportType) {
			out = append(out, r)
		}
	}
	return out
}

func hasReportType(r JobRun, reportType string) bool {
	for _, t := range r.ReportTypes {
		if t == reportType {
			return true
		}
	}
	return false
}

// Evidence is one project's CI-side evidence for a scanner category —
// everything C05 and C06 both need, gathered once and segmented by which
// call each check's status depends on.
//
// Each phase carries its own error rather than a single fatal one: a project
// with no releases must still get a cadence answer, and an unreadable job
// listing must not cost tool-configured its lint evidence.
type Evidence struct {
	// Lint is the merged CI configuration, and LintErr its fetch failure.
	Lint    CILintResponse
	LintErr error
	// ConfigParsed is false when the merged configuration was empty or did
	// not parse — NOT the same as "no scanner configured", see
	// MatchMergedConfig.
	ConfigParsed bool
	// Jobs are the scanner jobs found in the merged configuration.
	Jobs []ScannerJob

	Releases    []Release
	ReleasesErr error

	// Runs are the matched scanner runs inside the lookback window,
	// Truncated reports an incomplete walk, and RunsErr its fetch failure.
	Runs      []JobRun
	Truncated bool
	RunsErr   error

	Coverage []Coverage
	Cadence  Cadence

	// WindowStart and Now bound the lookback window the two run-history
	// checks were computed over, for Facts.
	WindowStart time.Time
	Now         time.Time

	// Per-phase provenance, so a check cites only the calls behind its own
	// status.
	LintProv     []model.Provenance
	ReleasesProv []model.Provenance
	JobsProv     []model.Provenance
}

// Gather reads one project's CI configuration, releases and job history and
// derives the coverage and cadence both C05 and C06 report.
//
// segment must return the provenance recorded since its own previous call —
// the closure convention internal/collect/github/actionssecurity established
// and every gitlab collector now uses.
func Gather(
	ctx context.Context,
	client *gitlabcollect.Client,
	projID string,
	tagPattern string,
	lookbackReleases, lookbackMonths int,
	now time.Time,
	reportType string,
	category mapping.ScannerCategory,
	registry *mapping.ScannerSignatureRegistry,
	segment func() []model.Provenance,
) Evidence {
	ev := Evidence{Now: now, WindowStart: now.AddDate(0, -lookbackMonths, 0)}

	ev.Lint, ev.LintErr = FetchCILint(ctx, client, projID)
	ev.LintProv = segment()
	if ev.LintErr == nil {
		ev.Jobs, ev.ConfigParsed = MatchMergedConfig(ev.Lint.MergedYAML, reportType, category, registry)
	}

	releases, err := FetchReleases(ctx, client, projID)
	ev.ReleasesErr = err
	ev.ReleasesProv = segment()
	if err == nil {
		ev.Releases = FilterReleasesInLookback(releases, tagPattern, lookbackReleases, lookbackMonths, now)
	}

	walk, err := FetchJobsInWindow(ctx, client, projID, ev.WindowStart)
	ev.RunsErr = err
	ev.JobsProv = segment()
	if err == nil {
		ev.Truncated = walk.Truncated
		ev.Runs = SelectRuns(walk.Runs, ev.Jobs, reportType)
		ev.Coverage = LinkRunsToReleases(ev.Releases, ev.Runs)
		ev.Cadence = ComputeCadence(ev.Runs, ev.WindowStart, now)
	}
	return ev
}

// ConfigUnavailableReason explains why the merged CI configuration could not
// be used as evidence, quoting GitLab's own errors rather than paraphrasing
// them into a guess about which of the two 200-with-valid=false cases this is.
func (e Evidence) ConfigUnavailableReason() string {
	if e.LintErr != nil {
		return fmt.Sprintf("could not lint the project's CI configuration: %v", e.LintErr)
	}
	detail := "GitLab reported no detail"
	if len(e.Lint.Errors) > 0 {
		detail = strings.Join(e.Lint.Errors, "; ")
	}
	return "GitLab returned no usable merged CI configuration for this project, so which jobs it runs is " +
		"unknown — either the project has no CI configuration, or an included file failed to resolve: " + detail
}

// treeEntry is one entry of GET /projects/:id/repository/tree.
type treeEntry struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

// FetchDependencyManifests lists the dependency lockfiles and manifests in
// the project's repository.
//
// The recognised filenames are not this build's invention: they are read
// verbatim off GitLab's OWN Dependency Scanning template, whose three
// analyzer jobs gate on `exists:` globs naming exactly these files (captured
// live 2026-08-13 into ci-lint-security-templates.json — see
// dependencyManifestNames). Scoping the check to files GitLab itself says it
// can scan is what keeps it from reporting a gap no producer could close.
func FetchDependencyManifests(ctx context.Context, client *gitlabcollect.Client, projID string) ([]string, error) {
	entries, err := gitlabcollect.GetJSONPaged[treeEntry](ctx, client, "/projects/"+projID+"/repository/tree",
		url.Values{"recursive": {"true"}})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.Type != "blob" {
			continue
		}
		if dependencyManifestNames[baseName(e.Path)] {
			out = append(out, e.Path)
		}
	}
	return out, nil
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// dependencyManifestNames are the files GitLab's own Dependency Scanning
// template gates its analyzers on, transcribed from the three `exists:`
// globs in a live merged configuration (2026-08-13):
//
//	.gemnasium-shared-rule:        **/{Gemfile.lock,composer.lock,gems.locked,go.sum,
//	                                   npm-shrinkwrap.json,package-lock.json,yarn.lock,
//	                                   pnpm-lock.yaml,packages.lock.json,conan.lock}
//	.gemnasium-maven-shared-rule:  **/{build.gradle,build.gradle.kts,build.sbt,pom.xml}
//	.gemnasium-python-shared-rule: **/{requirements.txt,requirements.pip,Pipfile,
//	                                   Pipfile.lock,requires.txt,setup.py,poetry.lock,uv.lock}
//
// ⚠ Transcribed, not derived at runtime from the project's own merged
// configuration, even though that would track GitLab's changes automatically:
// a project that includes NO Dependency Scanning template has no such rule to
// read, and that is precisely the project this check most needs to describe.
//
// ⚠ go.mod is absent because GitLab's own rule does not name it — Gemnasium
// scans go.sum. A Go module with no go.sum is genuinely unscannable by this
// analyzer, which is a real GitLab limitation this check does not claim to
// cover rather than one it invents a finding about.
var dependencyManifestNames = map[string]bool{
	"Gemfile.lock": true, "composer.lock": true, "gems.locked": true, "go.sum": true,
	"npm-shrinkwrap.json": true, "package-lock.json": true, "yarn.lock": true,
	"pnpm-lock.yaml": true, "packages.lock.json": true, "conan.lock": true,
	"build.gradle": true, "build.gradle.kts": true, "build.sbt": true, "pom.xml": true,
	"requirements.txt": true, "requirements.pip": true, "Pipfile": true,
	"Pipfile.lock": true, "requires.txt": true, "setup.py": true,
	"poetry.lock": true, "uv.lock": true,
}

// DependencyManifestNames exposes the transcribed table so a test can pin it
// against an independent literal — see dependencyManifestNames for the source.
func DependencyManifestNames() map[string]bool {
	out := make(map[string]bool, len(dependencyManifestNames))
	for k, v := range dependencyManifestNames {
		out[k] = v
	}
	return out
}

// DecodeJobs decodes a recorded GET /projects/:id/jobs body, so a test can
// drive SelectRuns and the cadence/coverage functions off the real recorded
// response rather than a hand-written approximation of it.
func DecodeJobs(body []byte) ([]JobRun, error) {
	var raw []jobRaw
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("collect/gitlab/cihistory: decode jobs: %w", err)
	}
	out := make([]JobRun, 0, len(raw))
	for _, j := range raw {
		run := JobRun{Name: j.Name, Status: j.Status, PipelineSHA: j.Pipeline.SHA, ReportTypes: fileTypes(j)}
		if j.FinishedAt != nil {
			run.FinishedAt = *j.FinishedAt
		}
		out = append(out, run)
	}
	return out, nil
}
