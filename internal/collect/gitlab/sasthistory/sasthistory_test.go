package sasthistory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/collect/gitlab/cihistory"
	"gitlab.com/sioakeim/attestward/internal/collect/gitlab/gitlabfixture"
	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// now is the clock every fixture below is dated against, so the lookback
// window is deterministic. The recorded jobs listing ran on 2026-08-13, so
// this sits a day after it.
var now = time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)

func init() {
	// Pin the clock for every test in this package. gatherEvidence is the
	// single seam through which the collector reads it, and every assertion
	// about the lookback window below would otherwise drift with the calendar.
	gatherEvidence = func(
		ctx context.Context, client *gitlabcollect.Client, projID string, scope collect.Scope,
		registry *mapping.ScannerSignatureRegistry, reportType string,
		category mapping.ScannerCategory, segment func() []model.Provenance,
	) cihistory.Evidence {
		return cihistory.Gather(ctx, client, projID, scope.ReleaseTagPattern,
			scope.LookbackReleases, scope.LookbackMonths, now, reportType, category, registry, segment)
	}
}

// -----------------------------------------------------------------------
// fixture plumbing
// -----------------------------------------------------------------------

// fixture is one project's worth of API responses. Every field is a raw JSON
// body except the *Status fields, which serve that status with an error body
// instead.
type fixture struct {
	lint       string
	lintStatus int

	releases       string
	releasesStatus int

	jobs       string
	jobsStatus int

	// jobPages, when set, is served page by page — the only way to exercise
	// the walk's early stop and its page bound.
	jobPages []string
}

// recordedLint is the real GET /projects/:id/ci/lint response from a project
// running GitLab's stock SAST, Dependency Scanning and Secret Detection
// templates, captured live 2026-08-13.
func recordedLint(t *testing.T) string {
	t.Helper()
	return string(gitlabfixture.MustLoad(t, "ci-lint-security-templates.json"))
}

// recordedJobs is the real GET /projects/:id/jobs response from the same
// project, captured the same day.
func recordedJobs(t *testing.T) string {
	t.Helper()
	return string(gitlabfixture.MustLoad(t, "jobs-security-pipelines.json"))
}

// scannedRelease is a release cut from the commit five of the recorded jobs
// ran against, so the recorded run history genuinely covers it.
const scannedCommit = "de81ee9991957c92b877a27848ac2630497aae0d"

// unscannedCommit is a SHA no recorded job ran against.
const unscannedCommit = "0000000000000000000000000000000000000000"

func releaseJSON(tag, sha string, daysAgo int) string {
	return fmt.Sprintf(`{"tag_name":%q,"released_at":%q,"commit":{"id":%q}}`,
		tag, now.AddDate(0, 0, -daysAgo).Format(time.RFC3339), sha)
}

func (f fixture) handler() http.Handler {
	mux := http.NewServeMux()
	const base = "/api/v4/projects/g%2Fp"

	serve := func(path, body string, status int, fallback string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if status != 0 {
				w.WriteHeader(status)
				_, _ = fmt.Fprintf(w, `{"message":"%d test failure"}`, status)
				return
			}
			if body == "" {
				body = fallback
			}
			_, _ = fmt.Fprint(w, body)
		})
	}

	serve(base+"/ci/lint", f.lint, f.lintStatus, `{"valid":true,"errors":[],"merged_yaml":"build:\n  script:\n  - make\n"}`)
	serve(base+"/releases", f.releases, f.releasesStatus, `[]`)

	mux.HandleFunc(base+"/jobs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if f.jobsStatus != 0 {
			w.WriteHeader(f.jobsStatus)
			_, _ = fmt.Fprintf(w, `{"message":"%d test failure"}`, f.jobsStatus)
			return
		}
		if len(f.jobPages) > 0 {
			page := 1
			if p := r.URL.Query().Get("page"); p != "" {
				_, _ = fmt.Sscanf(p, "%d", &page)
			}
			if page <= len(f.jobPages) {
				_, _ = fmt.Fprint(w, f.jobPages[page-1])
				return
			}
			_, _ = fmt.Fprint(w, `[]`)
			return
		}
		body := f.jobs
		if body == "" {
			body = `[]`
		}
		_, _ = fmt.Fprint(w, body)
	})

	return mux
}

func collectAll(t *testing.T, f fixture) []model.CheckResult {
	t.Helper()
	server := httptest.NewServer(f.handler())
	t.Cleanup(server.Close)
	c := NewForTest(server.URL, "token", func() (*gitlabcollect.Client, error) {
		return gitlabcollect.NewClientForTest(server.URL, "token", http.DefaultTransport)
	})
	results, err := c.Collect(context.Background(), collect.Scope{
		Org: "g", Repos: []string{"p"},
		ReleaseTagPattern: "v*", LookbackReleases: 10, LookbackMonths: 12,
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return results
}

func collectWith(t *testing.T, f fixture) map[string]model.CheckResult {
	t.Helper()
	byID := map[string]model.CheckResult{}
	for _, r := range collectAll(t, f) {
		byID[r.CheckID] = r
	}
	if len(byID) != len(checkIDs) {
		t.Fatalf("got %d distinct check IDs, want %d", len(byID), len(checkIDs))
	}
	return byID
}

// assertStatuses pins the WHOLE map for a state rather than one check at a
// time: a bare count check, or a per-check assertion that omits a sibling,
// lets a silent status change in the unasserted check through.
func assertStatuses(t *testing.T, got map[string]model.CheckResult, want map[string]model.Status) {
	t.Helper()
	if len(want) != len(checkIDs) {
		t.Fatalf("the expectation names %d checks, want all %d", len(want), len(checkIDs))
	}
	for _, id := range checkIDs {
		r, ok := got[id]
		if !ok {
			t.Fatalf("no result for %s", id)
		}
		if r.Status != want[id] {
			t.Errorf("%s status = %q, want %q; reason=%q", id, r.Status, want[id], r.Reason)
		}
	}
}

// -----------------------------------------------------------------------
// the named states, reused by the rubric guard
// -----------------------------------------------------------------------

func cleanProject(t *testing.T) fixture {
	return fixture{
		lint:     recordedLint(t),
		releases: `[` + releaseJSON("v1.0.0", scannedCommit, 1) + `]`,
		jobs:     recordedJobs(t),
	}
}

// unscannedReleaseProject runs SAST but cut its release from a commit no
// SAST job ever ran against.
func unscannedReleaseProject(t *testing.T) fixture {
	f := cleanProject(t)
	f.releases = `[` + releaseJSON("v1.0.0", unscannedCommit, 1) + `]`
	return f
}

// failedRunProject has a SAST job on the release commit that did not succeed.
func failedRunProject(t *testing.T) fixture {
	f := cleanProject(t)
	f.jobs = fmt.Sprintf(`[{"name":"semgrep-sast","status":"failed","finished_at":%q,
		"pipeline":{"sha":%q},"artifacts":[]}]`,
		now.AddDate(0, 0, -2).Format(time.RFC3339), scannedCommit)
	return f
}

// noScannerProject has a perfectly readable CI configuration with no scanner
// in it at all.
func noScannerProject(*testing.T) fixture {
	return fixture{
		lint:     `{"valid":true,"errors":[],"merged_yaml":"build:\n  script:\n  - make\ntest:\n  script:\n  - go test ./...\n"}`,
		releases: `[` + releaseJSON("v1.0.0", unscannedCommit, 1) + `]`,
	}
}

// nameOnlyScannerProject names a job after a scanner without running one —
// the low-confidence tier, which caps both tool-configured and cadence.
func nameOnlyScannerProject(*testing.T) fixture {
	return fixture{
		lint: `{"valid":true,"errors":[],"merged_yaml":"semgrep:\n  script:\n  - make check\n"}`,
		jobs: fmt.Sprintf(`[{"name":"semgrep","status":"success","finished_at":%q,
			"pipeline":{"sha":%q},"artifacts":[]}]`,
			now.AddDate(0, 0, -2).Format(time.RFC3339), scannedCommit),
		releases: `[` + releaseJSON("v1.0.0", scannedCommit, 1) + `]`,
	}
}

// configuredButNeverRanProject has a scanner in CI and no run history for it
// inside the window.
func configuredButNeverRanProject(t *testing.T) fixture {
	return fixture{lint: recordedLint(t), releases: `[]`, jobs: `[]`}
}

// unreadableProject is every endpoint refusing.
var unreadableProject = fixture{lintStatus: 403, releasesStatus: 403, jobsStatus: 403}

// -----------------------------------------------------------------------
// the states, asserted whole
// -----------------------------------------------------------------------

func TestCleanProject(t *testing.T) {
	got := collectWith(t, cleanProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured: model.StatusVerifiedPass,
		idRanPerRelease:  model.StatusVerifiedPass,
		idCadence:        model.StatusVerifiedPass,
		idDefaultSetup:   model.StatusNotCheckable,
	})
	if !strings.Contains(got[idToolConfigured].Reason, "semgrep-sast") {
		t.Errorf("tool-configured reason does not name the matched job: %q", got[idToolConfigured].Reason)
	}
}

func TestUnscannedReleaseFails(t *testing.T) {
	got := collectWith(t, unscannedReleaseProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured: model.StatusVerifiedPass,
		idRanPerRelease:  model.StatusVerifiedFail,
		idCadence:        model.StatusVerifiedPass,
		idDefaultSetup:   model.StatusNotCheckable,
	})
	if !strings.Contains(got[idRanPerRelease].Reason, "v1.0.0") {
		t.Errorf("ran-per-release reason does not name the uncovered release: %q", got[idRanPerRelease].Reason)
	}
}

func TestFailedRunOnTheReleaseCommitIsPartialNotFail(t *testing.T) {
	got := collectWith(t, failedRunProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured: model.StatusVerifiedPass,
		idRanPerRelease:  model.StatusPartial,
		idCadence:        model.StatusVerifiedPass,
		idDefaultSetup:   model.StatusNotCheckable,
	})
}

func TestNoScannerConfigured(t *testing.T) {
	got := collectWith(t, noScannerProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured: model.StatusVerifiedFail,
		idRanPerRelease:  model.StatusVerifiedFail,
		// Nothing configured means there is no cadence to compute — reporting
		// a zero-run fail here would say the same thing twice, and this one
		// would be about a scanner that does not exist.
		idCadence:      model.StatusNotCheckable,
		idDefaultSetup: model.StatusNotCheckable,
	})
	if !strings.Contains(got[idCadence].Reason, "no SAST scanner is configured") {
		t.Errorf("cadence reason = %q, want it to name the absent configuration", got[idCadence].Reason)
	}
}

func TestNameOnlyMatchIsPartial(t *testing.T) {
	got := collectWith(t, nameOnlyScannerProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured: model.StatusPartial,
		// A name-only match still links to the release commit, so coverage
		// itself is evidenced — the weak identification caps the two checks
		// that judge the TOOL, not the one that judges the run.
		idRanPerRelease: model.StatusVerifiedPass,
		idCadence:       model.StatusPartial,
		idDefaultSetup:  model.StatusNotCheckable,
	})
}

func TestConfiguredButNeverRanIsACadenceFail(t *testing.T) {
	got := collectWith(t, configuredButNeverRanProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured: model.StatusVerifiedPass,
		// No releases in the window, so there is nothing for ran-per-release
		// to evaluate — that is not the same as a scanner never running,
		// which is exactly what cadence is for.
		idRanPerRelease: model.StatusNotCheckable,
		idCadence:       model.StatusVerifiedFail,
		idDefaultSetup:  model.StatusNotCheckable,
	})
}

func TestUnreadableProjectIsNotCheckableEverywhere(t *testing.T) {
	got := collectWith(t, unreadableProject)
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured: model.StatusNotCheckable,
		idRanPerRelease:  model.StatusNotCheckable,
		idCadence:        model.StatusNotCheckable,
		idDefaultSetup:   model.StatusNotCheckable,
	})
}

// TestUnreadableJobHistoryDoesNotCostToolConfiguredItsEvidence pins the
// per-phase error boundary: the lint response is what tool-configured reads,
// and a jobs listing that 403s must not drag it to not-checkable.
func TestUnreadableJobHistoryDoesNotCostToolConfiguredItsEvidence(t *testing.T) {
	f := cleanProject(t)
	f.jobsStatus = 403
	got := collectWith(t, f)
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured: model.StatusVerifiedPass,
		idRanPerRelease:  model.StatusNotCheckable,
		idCadence:        model.StatusNotCheckable,
		idDefaultSetup:   model.StatusNotCheckable,
	})
}

// -----------------------------------------------------------------------
// the lint response's two 200-with-valid=false shapes
// -----------------------------------------------------------------------

// TestNoCIConfigurationIsNotCheckableNotAFail is the false-fail this
// collector must not produce. A project with no .gitlab-ci.yml at all gets a
// 200 from the lint API with an empty merged_yaml, and reading that as "no
// scanner configured" would assert an absence over an evidence gap.
func TestNoCIConfigurationIsNotCheckableNotAFail(t *testing.T) {
	f := fixture{lint: `{"valid":false,"errors":["Please provide content of .gitlab-ci.yml"],"merged_yaml":null}`}
	got := collectWith(t, f)
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured: model.StatusNotCheckable,
		idRanPerRelease:  model.StatusNotCheckable,
		idCadence:        model.StatusNotCheckable,
		idDefaultSetup:   model.StatusNotCheckable,
	})
	if !strings.Contains(got[idToolConfigured].Reason, "Please provide content of .gitlab-ci.yml") {
		t.Errorf("reason = %q, want GitLab's own error quoted rather than paraphrased", got[idToolConfigured].Reason)
	}
}

// TestJobLevelLintErrorStillYieldsEvidence: a configuration that is invalid
// for a reason unrelated to its jobs still comes back with a populated
// merged_yaml (confirmed live during C08's own verification), so a stage typo
// must not cost this collector its evidence.
func TestJobLevelLintErrorStillYieldsEvidence(t *testing.T) {
	f := cleanProject(t)
	f.lint = `{"valid":false,"errors":["scan job: chosen stage nonexistent does not exist"],` +
		`"merged_yaml":"scan:\n  script:\n  - /analyzer run\n  artifacts:\n    reports:\n      sast: gl-sast-report.json\n"}`
	got := collectWith(t, f)
	if got[idToolConfigured].Status != model.StatusVerifiedPass {
		t.Errorf("tool-configured = %q, want verified-pass despite an unrelated lint error", got[idToolConfigured].Status)
	}
}

// -----------------------------------------------------------------------
// the job-history walk
// -----------------------------------------------------------------------

// jobPage renders n identical finished jobs, so a page reaches the walk's
// full-page threshold and it asks for another.
func jobPage(n int, name, sha string) string {
	entries := make([]string, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, fmt.Sprintf(`{"name":%q,"status":"success","finished_at":%q,
			"pipeline":{"sha":%q},"artifacts":[]}`, name, now.AddDate(0, 0, -1).Format(time.RFC3339), sha))
	}
	return "[" + strings.Join(entries, ",") + "]"
}

// TestTruncatedWalkTaintsCadenceButNotCoveredReleases pins the asymmetry the
// two checks deliberately have. Coverage is monotone in the run pool, so a
// release already reading "ran" cannot be invalidated by runs this build did
// not fetch; a run COUNT is not monotone, so any truncation taints cadence.
func TestTruncatedWalkTaintsCadenceButNotCoveredReleases(t *testing.T) {
	pages := make([]string, 25) // more than the walk's 20-page bound
	for i := range pages {
		pages[i] = jobPage(100, "semgrep-sast", scannedCommit)
	}
	f := fixture{
		lint:     recordedLint(t),
		releases: `[` + releaseJSON("v1.0.0", scannedCommit, 1) + `]`,
		jobPages: pages,
	}
	got := collectWith(t, f)
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured: model.StatusVerifiedPass,
		idRanPerRelease:  model.StatusVerifiedPass,
		idCadence:        model.StatusNotCheckable,
		idDefaultSetup:   model.StatusNotCheckable,
	})
	if !strings.Contains(got[idCadence].Reason, "page bound") {
		t.Errorf("cadence reason = %q, want it to name the truncation", got[idCadence].Reason)
	}
}

// TestTruncatedWalkTaintsAnUncoveredRelease is the other half: with the
// release reading "missing", the incomplete pool cannot certify that
// absence, so ran-per-release goes not-checkable rather than fail.
func TestTruncatedWalkTaintsAnUncoveredRelease(t *testing.T) {
	pages := make([]string, 25)
	for i := range pages {
		pages[i] = jobPage(100, "semgrep-sast", scannedCommit)
	}
	f := fixture{
		lint:     recordedLint(t),
		releases: `[` + releaseJSON("v1.0.0", unscannedCommit, 1) + `]`,
		jobPages: pages,
	}
	got := collectWith(t, f)
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured: model.StatusVerifiedPass,
		idRanPerRelease:  model.StatusNotCheckable,
		idCadence:        model.StatusNotCheckable,
		idDefaultSetup:   model.StatusNotCheckable,
	})
}

// jobPageAt renders n identical jobs finished at a given time.
func jobPageAt(n int, name, sha string, finished time.Time) string {
	entries := make([]string, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, fmt.Sprintf(`{"name":%q,"status":"success","finished_at":%q,
			"pipeline":{"sha":%q},"artifacts":[]}`, name, finished.Format(time.RFC3339), sha))
	}
	return "[" + strings.Join(entries, ",") + "]"
}

// TestWalkStopsAtTheWindowEdge proves the early stop, and does it through a
// consequence rather than a count.
//
// Mutation testing found the count alone proves nothing: ComputeCadence
// already drops any run older than the window, so a walk that read past the
// edge still reported the same number. What it would NOT survive is a project
// with more than 2,000 jobs of HISTORY: page 2 here is a full page of
// two-year-old jobs, so a walk that does not stop pages on to its bound,
// reports Truncated, and turns a perfectly answerable cadence into
// not-checkable. That false not-checkable is the real cost of losing the stop.
func TestWalkStopsAtTheWindowEdge(t *testing.T) {
	pages := make([]string, 25) // more than the walk's 20-page bound
	pages[0] = jobPage(100, "semgrep-sast", scannedCommit)
	for i := 1; i < len(pages); i++ {
		pages[i] = jobPageAt(100, "semgrep-sast", scannedCommit, now.AddDate(-2, 0, 0))
	}
	f := fixture{lint: recordedLint(t), jobPages: pages, releases: `[]`}

	got := collectWith(t, f)
	if got[idCadence].Status != model.StatusVerifiedPass {
		t.Fatalf("cadence = %q, want verified-pass — the walk should have stopped at the window edge on "+
			"page 2 and never reached its page bound; reason=%q", got[idCadence].Status, got[idCadence].Reason)
	}
	if runs, _ := got[idCadence].Facts["runs"].(int); runs != 100 {
		t.Errorf("runs = %v, want exactly the 100 in-window jobs from page 1", got[idCadence].Facts["runs"])
	}
}

// -----------------------------------------------------------------------
// releases
// -----------------------------------------------------------------------

// TestReleasesOutsideTheWindowAreNotEvaluated guards against a release from
// three years ago dragging ran-per-release to a fail forever.
func TestReleasesOutsideTheWindowAreNotEvaluated(t *testing.T) {
	f := cleanProject(t)
	f.releases = `[` + releaseJSON("v0.1.0", unscannedCommit, 3*365) + `]`
	got := collectWith(t, f)
	if got[idRanPerRelease].Status != model.StatusNotCheckable {
		t.Errorf("ran-per-release = %q, want not-checkable — the only release predates the window",
			got[idRanPerRelease].Status)
	}
}

// TestNonMatchingTagsAreNotEvaluated: a tag outside the configured pattern
// was never in scope, however recent it is.
func TestNonMatchingTagsAreNotEvaluated(t *testing.T) {
	f := cleanProject(t)
	f.releases = `[` + releaseJSON("nightly-2026-08-13", unscannedCommit, 1) + `]`
	got := collectWith(t, f)
	if got[idRanPerRelease].Status != model.StatusNotCheckable {
		t.Errorf("ran-per-release = %q, want not-checkable — no tag matches v*", got[idRanPerRelease].Status)
	}
}

// TestCoverageJoinsOnTheReleaseCommitNotTheBranch is the claim the rubric
// makes and the one most likely to rot: a scan of a LATER commit on the same
// branch does not evidence that the released code was scanned.
func TestCoverageJoinsOnTheReleaseCommitNotTheBranch(t *testing.T) {
	f := cleanProject(t)
	f.releases = `[` + releaseJSON("v1.0.0", unscannedCommit, 1) + `]`
	f.jobs = fmt.Sprintf(`[{"name":"semgrep-sast","status":"success","finished_at":%q,
		"pipeline":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"artifacts":[]}]`,
		now.AddDate(0, 0, -1).Format(time.RFC3339))
	got := collectWith(t, f)
	if got[idRanPerRelease].Status != model.StatusVerifiedFail {
		t.Errorf("ran-per-release = %q, want verified-fail — the successful run was on another commit",
			got[idRanPerRelease].Status)
	}
}

// -----------------------------------------------------------------------
// provenance, plumbing, titles
// -----------------------------------------------------------------------

// TestProvenanceIsSegmentedPerCheck: each check carries the calls its own
// status depends on and no others.
func TestProvenanceIsSegmentedPerCheck(t *testing.T) {
	got := collectWith(t, cleanProject(t))
	contains := func(r model.CheckResult, fragment string) bool {
		for _, p := range r.Provenance {
			if strings.Contains(p.Endpoint, fragment) {
				return true
			}
		}
		return false
	}
	if !contains(got[idToolConfigured], "/ci/lint") {
		t.Errorf("tool-configured provenance omits the lint call: %+v", got[idToolConfigured].Provenance)
	}
	if contains(got[idToolConfigured], "/jobs") || contains(got[idToolConfigured], "/releases") {
		t.Errorf("tool-configured provenance cites calls its status does not depend on: %+v",
			got[idToolConfigured].Provenance)
	}
	if !contains(got[idRanPerRelease], "/releases") || !contains(got[idRanPerRelease], "/jobs") {
		t.Errorf("ran-per-release provenance is missing one of its evidence calls: %+v",
			got[idRanPerRelease].Provenance)
	}
	if contains(got[idCadence], "/releases") {
		t.Errorf("cadence provenance cites the releases call, which it does not read: %+v",
			got[idCadence].Provenance)
	}
	if len(got[idDefaultSetup].Provenance) != 0 {
		t.Errorf("default-setup carries provenance for a check that makes no call: %+v",
			got[idDefaultSetup].Provenance)
	}
}

// TestDefaultSetupNeverVariesWithTheProject: its reason is a platform fact,
// so an unreadable project must not turn it into a scan failure message.
func TestDefaultSetupNeverVariesWithTheProject(t *testing.T) {
	clean := collectWith(t, cleanProject(t))[idDefaultSetup]
	broken := collectWith(t, unreadableProject)[idDefaultSetup]
	if clean.Reason != broken.Reason {
		t.Errorf("default-setup reason varies with the project:\n clean:  %q\n broken: %q", clean.Reason, broken.Reason)
	}
	if !strings.Contains(clean.Reason, "Auto DevOps") || !strings.Contains(clean.Reason, "scan execution policies") {
		t.Errorf("default-setup reason does not name the two mechanisms it was weighed against: %q", clean.Reason)
	}
}

func TestClientBuildFailureIsNotCheckable(t *testing.T) {
	c := NewForTest("https://example.invalid", "token", func() (*gitlabcollect.Client, error) {
		return nil, fmt.Errorf("boom")
	})
	results, err := c.Collect(context.Background(), collect.Scope{Org: "g", Repos: []string{"p"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != len(checkIDs) {
		t.Fatalf("got %d results, want %d", len(results), len(checkIDs))
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", r.CheckID, r.Status)
		}
	}
}

func TestID(t *testing.T) {
	if got := New("https://gitlab.example", "t").ID(); got != collectorID {
		t.Errorf("ID() = %q, want %q", got, collectorID)
	}
}

func TestEveryResultIsPlatformAndRepoStamped(t *testing.T) {
	for _, r := range collectAll(t, cleanProject(t)) {
		if r.Scope.Platform != platform {
			t.Errorf("%s Scope.Platform = %q, want %q", r.CheckID, r.Scope.Platform, platform)
		}
		if r.Scope.Repo != "p" {
			t.Errorf("%s Scope.Repo = %q, want the project these checks are about", r.CheckID, r.Scope.Repo)
		}
		if r.Title != checkTitles[r.CheckID] {
			t.Errorf("%s Title = %q, want %q", r.CheckID, r.Title, checkTitles[r.CheckID])
		}
	}
}

// TestNoTitleNamesAGitHubMechanism is the check the C07 and C10 reviews both
// had to make by eye: a title inherited from a GitHub twin names a mechanism
// GitLab does not have, and is wrong regardless of what the check reports.
// C05.sast.default-setup's twin title ("CodeQL default setup is configured")
// is exactly that case.
func TestNoTitleNamesAGitHubMechanism(t *testing.T) {
	for id, title := range checkTitles {
		for _, banned := range []string{"CodeQL", "Dependabot", "GitHub", "GITHUB_TOKEN", "Actions", "workflow"} {
			if strings.Contains(title, banned) {
				t.Errorf("%s title %q names %q, a GitHub mechanism", id, title, banned)
			}
		}
	}
}

// TestNoRubricNamesAGitHubMechanism extends the same guard to the text
// `attestward checks docs` publishes — a rubric is read far more often than
// a title, and the same inherited vocabulary lands there just as easily. The
// two deliberate mentions are exempted by name: default-setup's rubric has
// to say which GitHub mechanism it has no equivalent of, and ran-per-release
// cites the twin's own issue number for the monotonicity narrowing.
func TestNoRubricNamesAGitHubMechanism(t *testing.T) {
	exempt := map[string]bool{idDefaultSetup: true, idRanPerRelease: true}
	for id, rubric := range checkRubrics {
		if exempt[id] {
			continue
		}
		for status, text := range rubric {
			for _, banned := range []string{"CodeQL", "Dependabot", "GITHUB_TOKEN", "GitHub Actions", "workflow"} {
				if strings.Contains(text, banned) {
					t.Errorf("%s/%s rubric names %q, a GitHub mechanism", id, status, banned)
				}
			}
		}
	}
}

// TestFactsAreJSONSerialisable: Facts land in a signed pack, and a value the
// encoder cannot render fails the whole scan at output time rather than here.
func TestFactsAreJSONSerialisable(t *testing.T) {
	for _, r := range collectAll(t, cleanProject(t)) {
		if _, err := json.Marshal(r); err != nil {
			t.Errorf("%s does not marshal: %v", r.CheckID, err)
		}
	}
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue
// #10). The matrix is the named states above, which together reach every
// status all four checks can emit.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	truncatedCovered := fixture{
		lint: recordedLint(t), releases: `[` + releaseJSON("v1.0.0", scannedCommit, 1) + `]`,
		jobPages: repeatPages(25, jobPage(100, "semgrep-sast", scannedCommit)),
	}

	states := []struct {
		name string
		f    fixture
	}{
		{"clean", cleanProject(t)},
		{"release cut from an unscanned commit", unscannedReleaseProject(t)},
		{"the scanner ran and failed", failedRunProject(t)},
		{"no scanner configured at all", noScannerProject(t)},
		{"a job named like a scanner", nameOnlyScannerProject(t)},
		{"configured but never ran", configuredButNeverRanProject(t)},
		{"every endpoint refusing", unreadableProject},
		{"job history truncated", truncatedCovered},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			all = append(all, collectAll(t, st.f)...)
		})
	}
	collecttest.AssertRubricsMatchObservedBehaviour(t, platform, collectorID, all)
}

func repeatPages(n int, body string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = body
	}
	return out
}
