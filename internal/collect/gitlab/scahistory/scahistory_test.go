package scahistory

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

// now is the clock every fixture below is dated against. The recorded
// vulnerability listing was created 2026-08-10, so this sits three days after
// it — inside the 30-day triage window, which is what makes the recorded
// findings a PASS and lets the stale case be reached by moving the clock
// rather than by editing the fixture.
var now = time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)

func init() {
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

type fixture struct {
	lint       string
	lintStatus int

	releases       string
	releasesStatus int

	jobs       string
	jobsStatus int

	dependencies       string
	dependenciesStatus int

	tree       string
	treeStatus int

	vulnerabilities       string
	vulnerabilitiesStatus int
}

func recordedLint(t *testing.T) string {
	t.Helper()
	return string(gitlabfixture.MustLoad(t, "ci-lint-security-templates.json"))
}

func recordedJobs(t *testing.T) string {
	t.Helper()
	return string(gitlabfixture.MustLoad(t, "jobs-security-pipelines.json"))
}

func recordedDependencies(t *testing.T) string {
	t.Helper()
	return string(gitlabfixture.MustLoad(t, "dependencies.json"))
}

func recordedTree(t *testing.T) string {
	t.Helper()
	return string(gitlabfixture.MustLoad(t, "repository-tree.json"))
}

func recordedVulnerabilities(t *testing.T) string {
	t.Helper()
	return string(gitlabfixture.MustLoad(t, "vulnerabilities-all-states.json"))
}

const scannedCommit = "de81ee9991957c92b877a27848ac2630497aae0d"
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
				// The Free-tier body GitLab actually returns, recorded as
				// 403-not-entitled.json — the branch that must never become a
				// fail.
				_, _ = fmt.Fprint(w, `{"message":"403 Forbidden"}`)
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
	serve(base+"/jobs", f.jobs, f.jobsStatus, `[]`)
	serve(base+"/dependencies", f.dependencies, f.dependenciesStatus, `[]`)
	serve(base+"/repository/tree", f.tree, f.treeStatus, `[]`)
	serve(base+"/vulnerabilities", f.vulnerabilities, f.vulnerabilitiesStatus, `[]`)

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

// assertStatuses pins the WHOLE map for a state — see the C05 twin's
// identical helper for why a per-check assertion is not enough.
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

// entitledCleanProject is the real recorded Ultimate project: stock
// Dependency Scanning template, a release on a scanned commit, dependencies
// reported from package-lock.json, and a vulnerability listing whose only
// open critical dependency finding is three days old.
func entitledCleanProject(t *testing.T) fixture {
	return fixture{
		lint:            recordedLint(t),
		releases:        `[` + releaseJSON("v1.0.0", scannedCommit, 1) + `]`,
		jobs:            recordedJobs(t),
		dependencies:    recordedDependencies(t),
		tree:            recordedTree(t),
		vulnerabilities: recordedVulnerabilities(t),
	}
}

// freeTierProject is the whole point of this package's entitlement rule: the
// CI-backed checks answer normally, and the two Ultimate-gated ones report
// not-checkable rather than reading a 403 as "no vulnerable dependencies".
func freeTierProject(t *testing.T) fixture {
	f := entitledCleanProject(t)
	f.dependenciesStatus = http.StatusForbidden
	f.vulnerabilitiesStatus = http.StatusForbidden
	return f
}

// staleCriticalProject dates the recorded findings far enough back that the
// open critical one is past the triage window.
func staleCriticalProject(t *testing.T) fixture {
	f := entitledCleanProject(t)
	f.vulnerabilities = fmt.Sprintf(`[{"title":"Prototype Pollution in something",
		"state":"detected","severity":"critical","report_type":"dependency_scanning","created_at":%q}]`,
		now.AddDate(0, 0, -60).Format(time.RFC3339))
	return f
}

// unknownStateProject carries a vulnerability state this build has never
// seen — neither bucketed nor ignored.
func unknownStateProject(t *testing.T) fixture {
	f := entitledCleanProject(t)
	f.vulnerabilities = `[{"title":"Something","state":"quarantined","severity":"critical",
		"report_type":"dependency_scanning","created_at":"2026-08-10T00:00:00Z"}]`
	return f
}

// uncoveredManifestProject has a manifest GitLab reported nothing from.
func uncoveredManifestProject(t *testing.T) fixture {
	f := entitledCleanProject(t)
	f.tree = `[{"type":"blob","path":"package-lock.json"},{"type":"blob","path":"api/go.sum"}]`
	return f
}

// noScannerProject has a readable CI configuration with no dependency
// scanner in it.
func noScannerProject(t *testing.T) fixture {
	f := entitledCleanProject(t)
	f.lint = `{"valid":true,"errors":[],"merged_yaml":"build:\n  script:\n  - make\n"}`
	f.releases = `[` + releaseJSON("v1.0.0", unscannedCommit, 1) + `]`
	f.jobs = `[]`
	return f
}

// nameOnlyScannerProject names a job after a scanner without running one.
func nameOnlyScannerProject(t *testing.T) fixture {
	f := entitledCleanProject(t)
	f.lint = `{"valid":true,"errors":[],"merged_yaml":"snyk:\n  script:\n  - make deps\n"}`
	f.jobs = fmt.Sprintf(`[{"name":"snyk","status":"success","finished_at":%q,
		"pipeline":{"sha":%q},"artifacts":[]}]`, now.AddDate(0, 0, -1).Format(time.RFC3339), scannedCommit)
	return f
}

// failedRunProject has a dependency-scanning job on the release commit that
// did not succeed.
func failedRunProject(t *testing.T) fixture {
	f := entitledCleanProject(t)
	f.jobs = fmt.Sprintf(`[{"name":"gemnasium-dependency_scanning","status":"failed","finished_at":%q,
		"pipeline":{"sha":%q},"artifacts":[]}]`, now.AddDate(0, 0, -2).Format(time.RFC3339), scannedCommit)
	return f
}

// noManifestsProject has an entitled dependency listing and a repository with
// nothing to scan.
func noManifestsProject(t *testing.T) fixture {
	f := entitledCleanProject(t)
	f.tree = `[{"type":"blob","path":"main.go"},{"type":"tree","path":"docs"}]`
	f.dependencies = `[]`
	return f
}

var unreadableProject = fixture{
	lintStatus: 403, releasesStatus: 403, jobsStatus: 403,
	dependenciesStatus: 403, treeStatus: 403, vulnerabilitiesStatus: 403,
}

// -----------------------------------------------------------------------
// the states, asserted whole
// -----------------------------------------------------------------------

func TestEntitledCleanProject(t *testing.T) {
	got := collectWith(t, entitledCleanProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured:   model.StatusVerifiedPass,
		idRanPerRelease:    model.StatusVerifiedPass,
		idManifestCoverage: model.StatusVerifiedPass,
		idDependencyReview: model.StatusNotCheckable,
		idAlertsTriaged:    model.StatusVerifiedPass,
	})
}

// TestFreeTierIsNotCheckableNotAPass is the single most important test in
// this package, and the false pass docs/gitlab-security-apis.md §1 exists to
// prevent. A Free project's 403 must never read as "no vulnerable
// dependencies" or "every manifest is covered" — and the two Free-tier
// checks must still answer normally, since nothing about them is gated.
func TestFreeTierIsNotCheckableNotAPass(t *testing.T) {
	got := collectWith(t, freeTierProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured:   model.StatusVerifiedPass,
		idRanPerRelease:    model.StatusVerifiedPass,
		idManifestCoverage: model.StatusNotCheckable,
		idDependencyReview: model.StatusNotCheckable,
		idAlertsTriaged:    model.StatusNotCheckable,
	})
	for _, id := range []string{idManifestCoverage, idAlertsTriaged} {
		if !strings.Contains(got[id].Reason, "403") {
			t.Errorf("%s reason does not name the 403 it is standing on: %q", id, got[id].Reason)
		}
		if !strings.Contains(got[id].Reason, "not entitled") && !strings.Contains(got[id].Reason, "Free project is not entitled") {
			t.Errorf("%s reason does not name the entitlement possibility: %q", id, got[id].Reason)
		}
	}
}

func TestStaleCriticalFindingFails(t *testing.T) {
	got := collectWith(t, staleCriticalProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured:   model.StatusVerifiedPass,
		idRanPerRelease:    model.StatusVerifiedPass,
		idManifestCoverage: model.StatusVerifiedPass,
		idDependencyReview: model.StatusNotCheckable,
		idAlertsTriaged:    model.StatusVerifiedFail,
	})
}

func TestUnrecognisedVulnerabilityStateIsPartial(t *testing.T) {
	got := collectWith(t, unknownStateProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured:   model.StatusVerifiedPass,
		idRanPerRelease:    model.StatusVerifiedPass,
		idManifestCoverage: model.StatusVerifiedPass,
		idDependencyReview: model.StatusNotCheckable,
		idAlertsTriaged:    model.StatusPartial,
	})
	if !strings.Contains(got[idAlertsTriaged].Reason, "quarantined") {
		t.Errorf("reason does not name the state it could not interpret: %q", got[idAlertsTriaged].Reason)
	}
}

func TestUncoveredManifestIsPartialNeverAFail(t *testing.T) {
	got := collectWith(t, uncoveredManifestProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured:   model.StatusVerifiedPass,
		idRanPerRelease:    model.StatusVerifiedPass,
		idManifestCoverage: model.StatusPartial,
		idDependencyReview: model.StatusNotCheckable,
		idAlertsTriaged:    model.StatusVerifiedPass,
	})
	if !strings.Contains(got[idManifestCoverage].Reason, "api/go.sum") {
		t.Errorf("reason does not name the uncovered manifest: %q", got[idManifestCoverage].Reason)
	}
}

func TestNoScannerConfigured(t *testing.T) {
	got := collectWith(t, noScannerProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured:   model.StatusVerifiedFail,
		idRanPerRelease:    model.StatusVerifiedFail,
		idManifestCoverage: model.StatusVerifiedPass,
		idDependencyReview: model.StatusNotCheckable,
		idAlertsTriaged:    model.StatusVerifiedPass,
	})
}

func TestNameOnlyMatchIsPartial(t *testing.T) {
	got := collectWith(t, nameOnlyScannerProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured:   model.StatusPartial,
		idRanPerRelease:    model.StatusVerifiedPass,
		idManifestCoverage: model.StatusVerifiedPass,
		idDependencyReview: model.StatusNotCheckable,
		idAlertsTriaged:    model.StatusVerifiedPass,
	})
}

func TestFailedRunOnTheReleaseCommitIsPartialNotFail(t *testing.T) {
	got := collectWith(t, failedRunProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured:   model.StatusVerifiedPass,
		idRanPerRelease:    model.StatusPartial,
		idManifestCoverage: model.StatusVerifiedPass,
		idDependencyReview: model.StatusNotCheckable,
		idAlertsTriaged:    model.StatusVerifiedPass,
	})
}

func TestNoManifestsIsNotCheckableNotAPass(t *testing.T) {
	got := collectWith(t, noManifestsProject(t))
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured:   model.StatusVerifiedPass,
		idRanPerRelease:    model.StatusVerifiedPass,
		idManifestCoverage: model.StatusNotCheckable,
		idDependencyReview: model.StatusNotCheckable,
		idAlertsTriaged:    model.StatusVerifiedPass,
	})
}

func TestUnreadableProjectIsNotCheckableEverywhere(t *testing.T) {
	got := collectWith(t, unreadableProject)
	assertStatuses(t, got, map[string]model.Status{
		idToolConfigured:   model.StatusNotCheckable,
		idRanPerRelease:    model.StatusNotCheckable,
		idManifestCoverage: model.StatusNotCheckable,
		idDependencyReview: model.StatusNotCheckable,
		idAlertsTriaged:    model.StatusNotCheckable,
	})
}

// -----------------------------------------------------------------------
// the recorded fixtures, read directly
// -----------------------------------------------------------------------

// TestGoModIsNotFlaggedAsUncovered is the live cross-check this package's
// manifest rule was built from: the recorded project's tree holds go.mod AND
// package-lock.json, and /dependencies reported package-lock.json only. go.mod
// must NOT be flagged, because GitLab's own analyzer rule gates on go.sum —
// a Go module with no committed go.sum is unscannable by Gemnasium, which is
// a GitLab limitation rather than a producer's finding.
func TestGoModIsNotFlaggedAsUncovered(t *testing.T) {
	tree := recordedTree(t)
	if !strings.Contains(tree, `"go.mod"`) || !strings.Contains(tree, `"package-lock.json"`) {
		t.Fatalf("the recorded tree no longer holds both files this test is about, so it proves nothing")
	}
	got := collectWith(t, entitledCleanProject(t))
	if got[idManifestCoverage].Status != model.StatusVerifiedPass {
		t.Fatalf("manifest coverage = %q, want verified-pass; reason=%q",
			got[idManifestCoverage].Status, got[idManifestCoverage].Reason)
	}
	manifests, _ := got[idManifestCoverage].Facts["repository_manifests"].([]string)
	for _, m := range manifests {
		if m == "go.mod" {
			t.Error("go.mod was treated as a dependency manifest; GitLab's own rule scans go.sum")
		}
	}
}

// TestDismissedAndResolvedFindingsDoNotCountAsOpen exercises the recorded
// all-states listing through the check: it carries a dismissed critical and a
// resolved high alongside the open ones, and counting a dismissed finding
// would turn a triage decision the producer already recorded into a finding
// against them.
func TestDismissedAndResolvedFindingsDoNotCountAsOpen(t *testing.T) {
	raw := recordedVulnerabilities(t)
	for _, state := range []string{`"dismissed"`, `"resolved"`, `"confirmed"`} {
		if !strings.Contains(raw, state) {
			t.Fatalf("the recorded listing no longer carries a %s finding, so this test proves nothing", state)
		}
	}
	got := collectWith(t, entitledCleanProject(t))
	// The listing's only DISMISSED critical is the minimist one; the only
	// other critical is a confirmed SECRET DETECTION finding, which is C04's
	// subject and not counted here either. So zero open critical dependency
	// findings, from a listing that contains two criticals.
	if count, _ := got[idAlertsTriaged].Facts["open_critical_count"].(int); count != 0 {
		t.Errorf("open_critical_count = %v, want 0 — the two criticals recorded are one dismissed dependency "+
			"finding and one confirmed SECRET DETECTION finding", got[idAlertsTriaged].Facts["open_critical_count"])
	}
}

// TestSASTFindingsAreNotCountedByC06 pins the report-type filter directly:
// the recorded listing carries an open medium SAST finding, and C06 judging
// it would make its verdict depend on C05's subject.
func TestSASTFindingsAreNotCountedByC06(t *testing.T) {
	f := entitledCleanProject(t)
	f.vulnerabilities = fmt.Sprintf(`[{"title":"Broken crypto","state":"detected","severity":"critical",
		"report_type":"sast","created_at":%q}]`, now.AddDate(0, 0, -400).Format(time.RFC3339))
	got := collectWith(t, f)
	if got[idAlertsTriaged].Status != model.StatusVerifiedPass {
		t.Errorf("alerts-triaged = %q, want verified-pass — a 400-day-old SAST finding is not C06's subject",
			got[idAlertsTriaged].Status)
	}
}

// TestSeverityIsMatchedCaseInsensitively: docs/gitlab-security-apis.md §4
// records three different casings for severity across three surfaces of the
// same product, so pinning to the one this endpoint happens to use today is
// how the check silently stops finding anything.
func TestSeverityIsMatchedCaseInsensitively(t *testing.T) {
	for _, severity := range []string{"critical", "Critical", "CRITICAL"} {
		f := entitledCleanProject(t)
		f.vulnerabilities = fmt.Sprintf(`[{"title":"x","state":"detected","severity":%q,
			"report_type":"dependency_scanning","created_at":%q}]`,
			severity, now.AddDate(0, 0, -60).Format(time.RFC3339))
		if got := collectWith(t, f)[idAlertsTriaged]; got.Status != model.StatusVerifiedFail {
			t.Errorf("severity %q produced %q, want verified-fail", severity, got.Status)
		}
	}
}

// TestAFindingExactlyAtTheWindowEdgeIsNotYetStale pins the boundary rather
// than leaving it to whichever comparison operator happened to be written.
func TestAFindingExactlyAtTheWindowEdgeIsNotYetStale(t *testing.T) {
	f := entitledCleanProject(t)
	f.vulnerabilities = fmt.Sprintf(`[{"title":"x","state":"detected","severity":"critical",
		"report_type":"dependency_scanning","created_at":%q}]`, now.Add(-criticalTriageWindow).Format(time.RFC3339))
	if got := collectWith(t, f)[idAlertsTriaged]; got.Status != model.StatusVerifiedPass {
		t.Errorf("a finding exactly %v old produced %q, want verified-pass — the window is inclusive",
			criticalTriageWindow, got.Status)
	}
}

// -----------------------------------------------------------------------
// per-phase error boundaries
// -----------------------------------------------------------------------

// TestEachUltimateEndpointFailsOnlyItsOwnCheck: the two gated checks read
// different endpoints and one refusing must not drag the other down.
func TestEachUltimateEndpointFailsOnlyItsOwnCheck(t *testing.T) {
	t.Run("dependencies refused", func(t *testing.T) {
		f := entitledCleanProject(t)
		f.dependenciesStatus = 403
		got := collectWith(t, f)
		if got[idManifestCoverage].Status != model.StatusNotCheckable {
			t.Errorf("manifest coverage = %q, want not-checkable", got[idManifestCoverage].Status)
		}
		if got[idAlertsTriaged].Status != model.StatusVerifiedPass {
			t.Errorf("alerts-triaged = %q, want verified-pass — it reads a different endpoint",
				got[idAlertsTriaged].Status)
		}
	})
	t.Run("vulnerabilities refused", func(t *testing.T) {
		f := entitledCleanProject(t)
		f.vulnerabilitiesStatus = 403
		got := collectWith(t, f)
		if got[idAlertsTriaged].Status != model.StatusNotCheckable {
			t.Errorf("alerts-triaged = %q, want not-checkable", got[idAlertsTriaged].Status)
		}
		if got[idManifestCoverage].Status != model.StatusVerifiedPass {
			t.Errorf("manifest coverage = %q, want verified-pass", got[idManifestCoverage].Status)
		}
	})
}

// TestUnreadableTreeIsNotCheckableNotAPass: without the tree, "every manifest
// is covered" is an assertion over an unknown denominator.
func TestUnreadableTreeIsNotCheckableNotAPass(t *testing.T) {
	f := entitledCleanProject(t)
	f.treeStatus = 500
	got := collectWith(t, f)
	if got[idManifestCoverage].Status != model.StatusNotCheckable {
		t.Errorf("manifest coverage = %q, want not-checkable", got[idManifestCoverage].Status)
	}
	if !strings.Contains(got[idManifestCoverage].Reason, "repository tree") {
		t.Errorf("reason does not name the missing evidence: %q", got[idManifestCoverage].Reason)
	}
}

// -----------------------------------------------------------------------
// provenance, plumbing, titles
// -----------------------------------------------------------------------

func TestProvenanceIsSegmentedPerCheck(t *testing.T) {
	got := collectWith(t, entitledCleanProject(t))
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
	if contains(got[idToolConfigured], "/vulnerabilities") {
		t.Errorf("tool-configured provenance cites the vulnerability listing: %+v", got[idToolConfigured].Provenance)
	}
	if !contains(got[idAlertsTriaged], "/vulnerabilities") {
		t.Errorf("alerts-triaged provenance omits its own call: %+v", got[idAlertsTriaged].Provenance)
	}
	if contains(got[idAlertsTriaged], "/ci/lint") || contains(got[idAlertsTriaged], "/dependencies") {
		t.Errorf("alerts-triaged provenance cites calls its status does not depend on: %+v",
			got[idAlertsTriaged].Provenance)
	}
	if !contains(got[idManifestCoverage], "/dependencies") || !contains(got[idManifestCoverage], "/repository/tree") {
		t.Errorf("manifest-coverage provenance is missing one of its two evidence calls: %+v",
			got[idManifestCoverage].Provenance)
	}
	if len(got[idDependencyReview].Provenance) != 0 {
		t.Errorf("dependency-review carries provenance for a check that makes no call: %+v",
			got[idDependencyReview].Provenance)
	}
}

func TestDependencyReviewNeverVariesWithTheProject(t *testing.T) {
	clean := collectWith(t, entitledCleanProject(t))[idDependencyReview]
	broken := collectWith(t, unreadableProject)[idDependencyReview]
	if clean.Reason != broken.Reason {
		t.Errorf("dependency-review reason varies with the project:\n clean:  %q\n broken: %q", clean.Reason, broken.Reason)
	}
	if !strings.Contains(clean.Reason, "merge request approval policy") {
		t.Errorf("reason does not name the mechanism that would answer it: %q", clean.Reason)
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
	for _, r := range collectAll(t, entitledCleanProject(t)) {
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

// TestNoTitleNamesAGitHubMechanism: three of these five titles were inherited
// from a twin that names Dependabot, dependency review and required status
// checks — none of which exist on GitLab.
func TestNoTitleNamesAGitHubMechanism(t *testing.T) {
	for id, title := range checkTitles {
		for _, banned := range []string{"Dependabot", "CodeQL", "GitHub", "pull request", "required check", "workflow"} {
			if strings.Contains(title, banned) {
				t.Errorf("%s title %q names %q, a GitHub mechanism", id, title, banned)
			}
		}
	}
}

// TestNoRubricNamesAGitHubMechanism extends the guard to the text
// `attestward checks docs` publishes. dependency-review is exempted: its
// whole reason is that GitLab has no equivalent of GitHub's mechanism, which
// it has to name to be understood.
func TestNoRubricNamesAGitHubMechanism(t *testing.T) {
	exempt := map[string]bool{idDependencyReview: true}
	for id, rubric := range checkRubrics {
		if exempt[id] {
			continue
		}
		for status, text := range rubric {
			for _, banned := range []string{"Dependabot", "CodeQL", "GitHub Actions", "GITHUB_TOKEN", "workflow"} {
				if strings.Contains(text, banned) {
					t.Errorf("%s/%s rubric names %q, a GitHub mechanism", id, status, banned)
				}
			}
		}
	}
}

func TestFactsAreJSONSerialisable(t *testing.T) {
	for _, r := range collectAll(t, entitledCleanProject(t)) {
		if _, err := json.Marshal(r); err != nil {
			t.Errorf("%s does not marshal: %v", r.CheckID, err)
		}
	}
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue
// #10). The matrix is the named states above, which together reach every
// status all five checks can emit.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	states := []struct {
		name string
		f    fixture
	}{
		{"entitled and clean", entitledCleanProject(t)},
		{"free tier", freeTierProject(t)},
		{"a stale critical finding", staleCriticalProject(t)},
		{"an unrecognised vulnerability state", unknownStateProject(t)},
		{"an uncovered manifest", uncoveredManifestProject(t)},
		{"no scanner configured at all", noScannerProject(t)},
		{"a job named like a scanner", nameOnlyScannerProject(t)},
		{"the scanner ran and failed", failedRunProject(t)},
		{"no dependency manifests at all", noManifestsProject(t)},
		{"every endpoint refusing", unreadableProject},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			all = append(all, collectAll(t, st.f)...)
		})
	}
	collecttest.AssertRubricsMatchObservedBehaviour(t, platform, collectorID, all)
}
