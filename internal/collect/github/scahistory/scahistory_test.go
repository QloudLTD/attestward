package scahistory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/model"
)

func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode fixture response: %v", err)
	}
}

func newCollectorForServer(t *testing.T, server *httptest.Server) *Collector {
	t.Helper()
	c := New("ghp_test-token")
	c.newClientForTest = func(token string) *ghcollect.Client {
		client := ghcollect.NewClient(token)
		baseURL, err := url.Parse(server.URL + "/")
		if err != nil {
			t.Errorf("parse test server URL: %v", err)
			return client
		}
		client.REST.BaseURL = baseURL
		return client
	}
	return c
}

func byID(results []model.CheckResult) map[string]model.CheckResult {
	m := map[string]model.CheckResult{}
	for _, r := range results {
		m[r.CheckID] = r
	}
	return m
}

const trivyWorkflowYAML = `name: Trivy Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/trivy-action@0.24.0
`

const dependencyReviewWorkflowYAML = `name: Dependency Review
on:
  pull_request:
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
`

const dependencyReviewNoTriggerYAML = `name: Dependency Review
on: [push]
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
`

// Every register* helper below owns exactly one mux pattern per call and
// is never called twice for the same pattern within one test — net/http's
// ServeMux panics on a duplicate pattern registration, so each test picks
// ONE of a default/override pair (e.g. registerNoWorkflows XOR
// registerWorkflows) per endpoint, never both.

func registerRepo(t *testing.T, mux *http.ServeMux, org, repo, defaultBranch string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"default_branch": defaultBranch})
	})
}

func registerNoWorkflows(t *testing.T, mux *http.ServeMux, org, repo string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"total_count": 0, "workflows": []any{}})
	})
}

type workflowFixture struct {
	ID      int64
	Path    string
	Name    string
	Content string
}

func registerWorkflows(t *testing.T, mux *http.ServeMux, org, repo string, workflows ...workflowFixture) {
	t.Helper()
	entries := make([]map[string]any, 0, len(workflows))
	for _, wf := range workflows {
		entries = append(entries, map[string]any{"id": wf.ID, "name": wf.Name, "path": wf.Path, "state": "active"})
	}
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"total_count": len(entries), "workflows": entries})
	})
	for _, wf := range workflows {
		content := wf.Content
		mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/"+wf.Path, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, map[string]any{"content": content, "sha": "content-sha"})
		})
	}
}

func registerWorkflowRuns(t *testing.T, mux *http.ServeMux, org, repo string, workflowID int64, runs []map[string]any) {
	t.Helper()
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/workflows/%d/runs", org, repo, workflowID), func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"total_count": len(runs), "workflow_runs": runs})
	})
}

func registerNoReleases(t *testing.T, mux *http.ServeMux, org, repo string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/releases", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []any{})
	})
}

func registerOneRelease(t *testing.T, mux *http.ServeMux, org, repo, tag, commitSHA string, publishedAt time.Time) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/releases", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{
			{"tag_name": tag, "target_commitish": "main", "published_at": publishedAt.Format(time.RFC3339)},
		})
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/git/ref/tags/"+tag, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"ref":    "refs/tags/" + tag,
			"object": map[string]any{"type": "commit", "sha": commitSHA},
		})
	})
}

// registerRootFiles is optional — a test that never calls it (nor
// registerDependabotConfig, which owns a more specific pattern under the
// same prefix) leaves the root-listing path unmocked, which 404s and
// degrades to "zero ecosystems detected" — a safe default for tests that
// don't care about ecosystem detection.
func registerRootFiles(t *testing.T, mux *http.ServeMux, org, repo string, filenames ...string) {
	t.Helper()
	entries := make([]map[string]any, 0, len(filenames))
	for _, f := range filenames {
		entries = append(entries, map[string]any{"type": "file", "name": f, "path": f})
	}
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/"+org+"/"+repo+"/contents/" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, http.StatusOK, entries)
	})
}

// registerDependabotConfig is optional — see registerRootFiles' doc
// comment for why leaving it unmocked (both extensions 404) is a safe
// "no config present" default.
func registerDependabotConfig(t *testing.T, mux *http.ServeMux, org, repo, content string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/dependabot.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"content": content, "sha": "dependabot-sha"})
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/dependabot.yaml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
}

func registerNoAlerts(t *testing.T, mux *http.ServeMux, org, repo string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/dependabot/alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []any{})
	})
}

func registerAlerts(t *testing.T, mux *http.ServeMux, org, repo string, alerts []map[string]any) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/dependabot/alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, alerts)
	})
}

func registerAlertsStatus(t *testing.T, mux *http.ServeMux, org, repo string, status int, message string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/dependabot/alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, status, map[string]any{"message": message})
	})
}

func registerNoBranchProtection(t *testing.T, mux *http.ServeMux, org, repo, defaultBranch string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/branches/"+defaultBranch+"/protection", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Branch not protected"})
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/rules/branches/"+defaultBranch, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []any{})
	})
}

func registerRequiredStatusCheck(t *testing.T, mux *http.ServeMux, org, repo, defaultBranch, contextName string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/branches/"+defaultBranch+"/protection", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"required_status_checks": map[string]any{"contexts": []string{contextName}},
		})
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/rules/branches/"+defaultBranch, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []any{})
	})
}

func TestCollect_WorkflowBasedSCATool_AllChecksResolveCleanly(t *testing.T) {
	org, repo, branch := "attestward-demo", "good-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerRootFiles(t, mux, org, repo, "go.mod")
	// This repo has workflows, so detectEcosystems also reports
	// github-actions — cover both to make this the fully-clean scenario.
	registerDependabotConfig(t, mux, org, repo, "version: 2\nupdates:\n  - package-ecosystem: gomod\n    directory: /\n  - package-ecosystem: github-actions\n    directory: /\n")
	registerWorkflows(t, mux, org, repo,
		workflowFixture{ID: 1, Path: ".github/workflows/trivy.yml", Name: "Trivy Scan", Content: trivyWorkflowYAML},
		workflowFixture{ID: 2, Path: ".github/workflows/dependency-review.yml", Name: "Dependency Review", Content: dependencyReviewWorkflowYAML},
	)
	registerOneRelease(t, mux, org, repo, "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerWorkflowRuns(t, mux, org, repo, 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": branch, "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	// dependency-review-action is itself SCA-category (mappings/scanner-signatures.yaml),
	// so it's a second matched workflow alongside trivy — its own run
	// history must be registered too (issue #287's review: this fixture
	// previously left workflow 2's runs endpoint unmocked, and the bug
	// this test now guards against silently swallowed the resulting fetch
	// error rather than surfacing it).
	registerWorkflowRuns(t, mux, org, repo, 2, []map[string]any{})
	registerNoAlerts(t, mux, org, repo)
	registerRequiredStatusCheck(t, mux, org, repo, branch, "Dependency Review")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.tool-configured"].Status; got != model.StatusVerifiedPass {
		t.Errorf("tool-configured = %q, want verified-pass; reason=%q", got, m["C06.sca.tool-configured"].Reason)
	}
	if got := m["C06.sca.ran-per-release"].Status; got != model.StatusVerifiedPass {
		t.Errorf("ran-per-release = %q, want verified-pass; reason=%q", got, m["C06.sca.ran-per-release"].Reason)
	}
	if got := m["C06.sca.dependabot-config"].Status; got != model.StatusVerifiedPass {
		t.Errorf("dependabot-config = %q, want verified-pass; reason=%q", got, m["C06.sca.dependabot-config"].Reason)
	}
	if got := m["C06.sca.dependency-review"].Status; got != model.StatusVerifiedPass {
		t.Errorf("dependency-review = %q, want verified-pass; reason=%q", got, m["C06.sca.dependency-review"].Reason)
	}
	if got := m["C06.sca.alerts-triaged"].Status; got != model.StatusVerifiedPass {
		t.Errorf("alerts-triaged = %q, want verified-pass; reason=%q", got, m["C06.sca.alerts-triaged"].Reason)
	}

	// The initial repo-metadata fetch (which every check downstream
	// implicitly depends on for defaultBranch) must itself be attributed
	// somewhere, not vanish from every check's provenance — tool-configured
	// is the first check in the pipeline, so its provenance is the natural
	// place to look for the repo-Get call specifically.
	repoEndpoint := "/repos/" + org + "/" + repo
	found := false
	for _, p := range m["C06.sca.tool-configured"].Provenance {
		if p.Endpoint == repoEndpoint {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("tool-configured provenance = %+v, want it to include the initial repo-Get call (%s)", m["C06.sca.tool-configured"].Provenance, repoEndpoint)
	}
}

func TestCollect_DependabotOnly_ToolConfiguredPassesRanPerReleaseNotCheckable(t *testing.T) {
	org, repo, branch := "attestward-demo", "dependabot-only-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerNoReleases(t, mux, org, repo)
	registerDependabotConfig(t, mux, org, repo, "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n")
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.tool-configured"].Status; got != model.StatusVerifiedPass {
		t.Errorf("tool-configured = %q, want verified-pass (Dependabot config alone counts); reason=%q", got, m["C06.sca.tool-configured"].Reason)
	}
	if got := m["C06.sca.ran-per-release"].Status; got != model.StatusNotCheckable {
		t.Errorf("ran-per-release = %q, want not-checkable (Dependabot has no per-release run history); reason=%q", got, m["C06.sca.ran-per-release"].Reason)
	}
}

// TestCollect_OnlyWorkflowUnreadable_ToolConfiguredNotCheckableNotFail is
// issue #178's regression case, mirrored from C05 sasthistory's identical
// test: a repo whose only workflow can't be fetched (content 404) and has
// no Dependabot config must NOT read verified-fail ("no SCA tool
// detected") — that asserts a confirmed absence when inspection of the
// one workflow that exists actually failed. It must read not-checkable
// instead, with the skip surfaced in Facts.
func TestCollect_OnlyWorkflowUnreadable_ToolConfiguredNotCheckableNotFail(t *testing.T) {
	org, repo, branch := "attestward-demo", "flaky-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"workflows": []map[string]any{
				{"id": 1, "name": "Mystery", "path": ".github/workflows/mystery.yml", "state": "active"},
			},
		})
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/workflows/mystery.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
	registerNoReleases(t, mux, org, repo)
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	tc := m["C06.sca.tool-configured"]
	if tc.Status != model.StatusNotCheckable {
		t.Errorf("tool-configured = %q, want not-checkable (the repo's only workflow couldn't be inspected — not a confirmed absence); reason=%q", tc.Status, tc.Reason)
	}
	skipped, ok := tc.Facts["skipped_workflows"].([]map[string]any)
	if !ok || len(skipped) != 1 || skipped[0]["path"] != ".github/workflows/mystery.yml" || skipped[0]["reason"] == "" {
		t.Errorf("skipped_workflows facts = %v, want one entry for mystery.yml with a non-empty reason", tc.Facts["skipped_workflows"])
	}
}

// TestCollect_OnlyWorkflowUnreadableWithRelease_RanPerReleaseNotCheckableNotFail
// is the review finding on #202, mirrored from C05 sasthistory's identical
// test: the test above uses no releases, so it never exercises
// ran-per-release's own coverage-computation path. With a real release in
// scope and the repo's only workflow unreadable, ran-per-release previously
// read verified-fail ("no matched SCA runs at all") in the same breath
// tool-configured read not-checkable for the identical evidence — two
// panels of one pack, opposite claims. Both must now agree: not-checkable.
func TestCollect_OnlyWorkflowUnreadableWithRelease_RanPerReleaseNotCheckableNotFail(t *testing.T) {
	org, repo, branch := "attestward-demo", "flaky-release-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"workflows": []map[string]any{
				{"id": 1, "name": "Mystery", "path": ".github/workflows/mystery.yml", "state": "active"},
			},
		})
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/workflows/mystery.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
	registerOneRelease(t, mux, org, repo, "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	toolConfigured := m["C06.sca.tool-configured"]
	if toolConfigured.Status != model.StatusNotCheckable {
		t.Fatalf("tool-configured = %q, want not-checkable; reason=%q (test fixture no longer matches this test's premise)", toolConfigured.Status, toolConfigured.Reason)
	}
	ranPerRelease := m["C06.sca.ran-per-release"]
	if ranPerRelease.Status != model.StatusNotCheckable {
		t.Errorf("ran-per-release = %q, want not-checkable (must agree with tool-configured's not-checkable over the identical unreadable-workflow evidence, not independently assert verified-fail); reason=%q", ranPerRelease.Status, ranPerRelease.Reason)
	}
}

// TestCollect_NoSCAToolAtAllWithRelease_RanPerReleaseStillVerifiedFail is the
// negative counterpart the review round on #202 found missing: the guard
// added to checkRanPerRelease must be skip-gated, not a blanket "zero
// matched = not-checkable." A repo with a real release in scope, zero
// workflows, and no Dependabot config — genuinely no SCA evidence, and no
// skip explaining the absence — must still read verified-fail. Without this
// test, widening the guard's condition (e.g. dropping the skip check
// entirely) would silently turn every real zero-SCA-evidence gap into a
// false "couldn't check" and nothing in this package would catch it.
func TestCollect_NoSCAToolAtAllWithRelease_RanPerReleaseStillVerifiedFail(t *testing.T) {
	org, repo, branch := "attestward-demo", "bare-release-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerOneRelease(t, mux, org, repo, "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	toolConfigured := m["C06.sca.tool-configured"]
	if toolConfigured.Status != model.StatusVerifiedFail {
		t.Fatalf("tool-configured = %q, want verified-fail (test fixture no longer matches this test's premise)", toolConfigured.Status)
	}
	ranPerRelease := m["C06.sca.ran-per-release"]
	if ranPerRelease.Status != model.StatusVerifiedFail {
		t.Errorf("ran-per-release = %q, want verified-fail (no skip, so this is a confirmed absence, not a gap in inspection); reason=%q", ranPerRelease.Status, ranPerRelease.Reason)
	}
}

func TestCollect_NoSCAToolAtAll_ToolConfiguredFails(t *testing.T) {
	org, repo, branch := "attestward-demo", "bare-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerNoReleases(t, mux, org, repo)
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.tool-configured"].Status; got != model.StatusVerifiedFail {
		t.Errorf("tool-configured = %q, want verified-fail", got)
	}
	if got := m["C06.sca.dependabot-config"].Status; got != model.StatusNotCheckable {
		t.Errorf("dependabot-config = %q, want not-checkable (no manifests, nothing to cover)", got)
	}
}

func TestCollect_DependabotConfigMissingWithManifests_VerifiedFail(t *testing.T) {
	org, repo, branch := "attestward-demo", "uncovered-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerNoReleases(t, mux, org, repo)
	registerRootFiles(t, mux, org, repo, "go.mod")
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.dependabot-config"].Status; got != model.StatusVerifiedFail {
		t.Errorf("dependabot-config = %q, want verified-fail; reason=%q", got, m["C06.sca.dependabot-config"].Reason)
	}
	uncovered, _ := m["C06.sca.dependabot-config"].Facts["uncovered_ecosystems"].([]string)
	if len(uncovered) != 1 || uncovered[0] != "gomod" {
		t.Errorf("uncovered_ecosystems = %v, want [gomod]", uncovered)
	}
}

func TestCollect_DependabotConfigPartialCoverage_Partial(t *testing.T) {
	org, repo, branch := "attestward-demo", "partial-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerNoReleases(t, mux, org, repo)
	registerRootFiles(t, mux, org, repo, "go.mod", "package.json")
	registerDependabotConfig(t, mux, org, repo, "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n")
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.dependabot-config"].Status; got != model.StatusPartial {
		t.Errorf("dependabot-config = %q, want partial; reason=%q", got, m["C06.sca.dependabot-config"].Reason)
	}
	uncovered, _ := m["C06.sca.dependabot-config"].Facts["uncovered_ecosystems"].([]string)
	if len(uncovered) != 1 || uncovered[0] != "gomod" {
		t.Errorf("uncovered_ecosystems = %v, want [gomod]", uncovered)
	}
}

// TestCollect_RootListingFailure_DependabotConfigNotCheckable pins the
// fix for a silently-swallowed root-listing error: a 403 fetching the
// root directory must not degrade to "zero ecosystems detected" (which
// would falsely read as either verified-pass, if a config exists, or
// "nothing to cover", if it doesn't) — it must surface as not-checkable,
// since ecosystem coverage genuinely couldn't be determined.
func TestCollect_RootListingFailure_DependabotConfigNotCheckable(t *testing.T) {
	org, repo, branch := "attestward-demo", "root-403-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerNoReleases(t, mux, org, repo)
	registerDependabotConfig(t, mux, org, repo, "version: 2\nupdates:\n  - package-ecosystem: gomod\n    directory: /\n")
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/"+org+"/"+repo+"/contents/" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.dependabot-config"].Status; got != model.StatusNotCheckable {
		t.Errorf("dependabot-config = %q, want not-checkable (root listing failed, coverage genuinely unknown); reason=%q", got, m["C06.sca.dependabot-config"].Reason)
	}
}

// TestCollect_ReleaseListingFailure_RanPerReleaseSurfacesRealReason pins
// the fix for a silently-swallowed release-fetch error: a 403 listing
// releases must not be reported as "no releases match the configured
// pattern" (a misleading claim — releases may well exist and match, the
// call just failed) once a real workflow-based SCA tool is in play.
func TestCollect_ReleaseListingFailure_RanPerReleaseSurfacesRealReason(t *testing.T) {
	org, repo, branch := "attestward-demo", "releases-403-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerWorkflows(t, mux, org, repo, workflowFixture{ID: 1, Path: ".github/workflows/trivy.yml", Name: "Trivy Scan", Content: trivyWorkflowYAML})
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)
	mux.HandleFunc("/repos/"+org+"/"+repo+"/releases", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.ran-per-release"].Status; got != model.StatusNotCheckable {
		t.Errorf("ran-per-release = %q, want not-checkable; reason=%q", got, m["C06.sca.ran-per-release"].Reason)
	}
	if reason := m["C06.sca.ran-per-release"].Reason; strings.Contains(reason, "no releases match") {
		t.Errorf("ran-per-release reason = %q, want it to reflect the real fetch failure, not a misleading pattern-match claim", reason)
	}
}

// TestCollect_WorkflowRunsFetch403_RanPerReleaseNotCheckable is issue #287's
// GitHub-side twin for C06: a real Trivy workflow is matched, one release is
// in scope, and everything succeeds except the run-history call (GET
// .../actions/workflows/{id}/runs), which returns a 403 — a realistic
// secondary-rate-limit response. Before this fix, collectRepo silently
// `continue`d past that error, leaving runs empty, so ran-per-release
// asserted "no matched SCA run at all" (verified-fail) from a query that
// never actually returned.
func TestCollect_WorkflowRunsFetch403_RanPerReleaseNotCheckable(t *testing.T) {
	org, repo, branch := "attestward-demo", "sca-rate-limited-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerWorkflows(t, mux, org, repo, workflowFixture{ID: 1, Path: ".github/workflows/trivy.yml", Name: "Trivy Scan", Content: trivyWorkflowYAML})
	registerOneRelease(t, mux, org, repo, "v1.2.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows/1/runs", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "API rate limit exceeded"})
	})
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.tool-configured"].Status; got != model.StatusVerifiedPass {
		t.Errorf("tool-configured = %q, want verified-pass (unaffected — it never reads run history); reason=%q", got, m["C06.sca.tool-configured"].Reason)
	}

	ranPerRelease := m["C06.sca.ran-per-release"]
	if ranPerRelease.Status != model.StatusNotCheckable {
		t.Errorf("ran-per-release = %q, want not-checkable, NOT verified-fail — a failed run-history query is not a confirmed per-release absence; reason=%q", ranPerRelease.Status, ranPerRelease.Reason)
	}
	if v, ok := ranPerRelease.Facts["per_release"]; ok {
		t.Errorf("ran-per-release Facts[per_release] = %v, want the key absent — coverage was computed from an incomplete runs pool", v)
	}
	if dropped, ok := ranPerRelease.Facts["dropped_tags"].(int); !ok || dropped != 0 {
		t.Errorf("ran-per-release Facts[dropped_tags] = %v, want 0 (still reported — unaffected by the run-history failure)", ranPerRelease.Facts["dropped_tags"])
	}
}

// TestCollect_SecondWorkflowRunsFetch403WithReleaseAlreadyRan_RanPerReleaseStaysVerifiedPass
// is issue #291's own reproduction, applied to C06 — the widest surface
// named in the issue: dependency-review-action is itself SCA-category
// (mappings/scanner-signatures.yaml), so any repo with dependency review
// PLUS another SCA scanner has two matched workflows, and
// dependency-review typically triggers only on pull_request — contributing
// nothing to release coverage either way. Trivy's run history resolves
// cleanly and already covers the one release with a successful run before
// dependency-review's own `/runs` fetch (which 403s) even factors in.
//
// Coverage status is monotone non-decreasing in the runs pool, so
// ran-per-release's already-"ran" table can't be invalidated by whatever
// dependency-review's unfetched runs would have added — it must stay
// verified-pass, not be discarded to not-checkable the way #289 tainted it
// unconditionally (see TestCollect_WorkflowRunsFetch403_RanPerReleaseNotCheckable
// above for the single-workflow case that must still taint).
func TestCollect_SecondWorkflowRunsFetch403WithReleaseAlreadyRan_RanPerReleaseStaysVerifiedPass(t *testing.T) {
	org, repo, branch := "attestward-demo", "acme-multi", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerWorkflows(t, mux, org, repo,
		workflowFixture{ID: 1, Path: ".github/workflows/trivy.yml", Name: "Trivy Scan", Content: trivyWorkflowYAML},
		workflowFixture{ID: 2, Path: ".github/workflows/dependency-review.yml", Name: "Dependency Review", Content: dependencyReviewWorkflowYAML},
	)
	registerOneRelease(t, mux, org, repo, "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerWorkflowRuns(t, mux, org, repo, 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": branch, "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows/2/runs", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "API rate limit exceeded"})
	})
	registerNoAlerts(t, mux, org, repo)
	registerRequiredStatusCheck(t, mux, org, repo, branch, "Dependency Review")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	ranPerRelease := m["C06.sca.ran-per-release"]
	if ranPerRelease.Status != model.StatusVerifiedPass {
		t.Errorf("ran-per-release = %q, want verified-pass — every release already reads \"ran\" from Trivy's own runs, so dependency-review's failed fetch can't invalidate it; reason=%q", ranPerRelease.Status, ranPerRelease.Reason)
	}
	perRelease, ok := ranPerRelease.Facts["per_release"].([]map[string]any)
	if !ok || len(perRelease) != 1 || perRelease[0]["status"] != "ran" {
		t.Errorf("ran-per-release Facts[per_release] = %v, want one entry with status=ran", ranPerRelease.Facts["per_release"])
	}
}

// TestCollect_DependabotConfigFetchFailure_ToolConfiguredAndConfigNotCheckable
// pins the fix for a second silently-swallowed error: collectRepo used to
// discard fetchDependabotConfig's own resp/err entirely (`cfg,
// configExists, _, _ := fetchDependabotConfig(...)`), so a genuine fetch
// failure (403, a malformed dependabot.yml, ...) was indistinguishable
// from a legitimate "no config at either path" 404 — both left
// configExists false. With a detected ecosystem in play (so there's
// something to falsely claim is "uncovered"), that made
// C06.sca.dependabot-config assert a confident verified-fail, and
// C06.sca.tool-configured assert a confident verified-fail too (no
// workflow evidence either), when the truth for both is "unknown, the
// query failed."
func TestCollect_DependabotConfigFetchFailure_ToolConfiguredAndConfigNotCheckable(t *testing.T) {
	org, repo, branch := "attestward-demo", "dependabot-403-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerNoReleases(t, mux, org, repo)
	registerRootFiles(t, mux, org, repo, "go.mod")
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/dependabot.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.dependabot-config"].Status; got != model.StatusNotCheckable {
		t.Errorf("dependabot-config = %q, want not-checkable (the config fetch itself failed, coverage genuinely unknown); reason=%q", got, m["C06.sca.dependabot-config"].Reason)
	}
	if got := m["C06.sca.tool-configured"].Status; got != model.StatusNotCheckable {
		t.Errorf("tool-configured = %q, want not-checkable (no workflow evidence, and the Dependabot config fetch itself failed — unknown, not a confirmed absence); reason=%q", got, m["C06.sca.tool-configured"].Reason)
	}
}

// TestCollect_DependabotConfigFetchFailureWithRelease_RanPerReleaseNotCheckable
// covers the same swallowed-error bug's effect on ran-per-release: with no
// workflow-based SCA evidence and a Dependabot config fetch failure, it's
// unknown whether Dependabot is this repo's sole (per-release-history-less)
// SCA tool or genuinely absent — either way, evaluating release coverage
// against zero workflow runs and confidently failing would be wrong.
func TestCollect_DependabotConfigFetchFailureWithRelease_RanPerReleaseNotCheckable(t *testing.T) {
	org, repo, branch := "attestward-demo", "dependabot-403-release-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerOneRelease(t, mux, org, repo, "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/dependabot.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.ran-per-release"].Status; got != model.StatusNotCheckable {
		t.Errorf("ran-per-release = %q, want not-checkable (unknown whether Dependabot is this repo's sole SCA tool); reason=%q", got, m["C06.sca.ran-per-release"].Reason)
	}
}

// TestCollect_LowConfidenceMatchPlusDependabotFetchFails_FactsOmitDependabotFields
// is the regression test for issue #258: a low-confidence-only workflow
// match plus a failed (non-normalized) Dependabot config fetch must not
// silently report Facts["dependabot_configured"]=false or
// Facts["low_confidence_match_only"]=true — both derive from
// dependabotConfigured, and fetchDependabotConfig returns exists=false
// alongside any real fetch error (permission denied, malformed YAML, ...),
// indistinguishable from a genuine "no config at either path" response.
// This combination is reachable in production: hasAny=true here bypasses
// checkToolConfigured's own not-checkable guard, which only fires when
// hasAny is false — every existing dependabot-fetch-failure test
// (TestCollect_DependabotConfigFetchFailure_ToolConfiguredAndConfigNotCheckable
// and its ran-per-release twin) uses registerNoWorkflows, so neither
// exercises this Facts path. Before this fix, both fields asserted a
// confirmed value from a fetch that merely failed. The workflow is named
// "Snyk Scan" — mappings/scanner-signatures.yaml gives snyk a non-empty
// workflow_name_patterns (unlike, e.g., trivy's empty list, so a
// trivy-named workflow with no real trivy step wouldn't match at all) —
// but its content has neither a snyk/actions/* step nor a `snyk test`/
// `snyk monitor` invocation, so only the name heuristic fires.
func TestCollect_LowConfidenceMatchPlusDependabotFetchFails_FactsOmitDependabotFields(t *testing.T) {
	org, repo, branch := "attestward-demo", "snyk-name-only-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerWorkflows(t, mux, org, repo, workflowFixture{
		ID: 1, Path: ".github/workflows/snyk.yml", Name: "Snyk Scan",
		Content: "name: Snyk Scan\non: [push]\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
	})
	registerWorkflowRuns(t, mux, org, repo, 1, []map[string]any{})
	registerNoReleases(t, mux, org, repo)
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/dependabot.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m["C06.sca.tool-configured"]
	if got.Status != model.StatusPartial {
		t.Errorf("tool-configured = %q, want partial (unaffected by this fix — only the Facts values change); reason=%q", got.Status, got.Reason)
	}
	if v, ok := got.Facts["dependabot_configured"]; ok {
		t.Errorf("Facts[dependabot_configured] = %v, want the key absent — the Dependabot config fetch failed, so its value can't be reported as a confirmed fact", v)
	}
	if v, ok := got.Facts["low_confidence_match_only"]; ok {
		t.Errorf("Facts[low_confidence_match_only] = %v, want the key absent — its value depends on the same unconfirmed Dependabot fetch", v)
	}

	// Issue #287's secondary finding: tool_names must not silently include
	// "Dependabot" (or silently omit it as a confirmed exclusion) from an
	// unconfirmed dependabotConfigured value either — same source, same
	// hazard as the two keys just checked above.
	names, ok := got.Facts["tool_names"].([]string)
	if !ok {
		t.Fatalf("Facts[tool_names] = %v (%T), want a []string", got.Facts["tool_names"], got.Facts["tool_names"])
	}
	for _, n := range names {
		if n == "Dependabot" {
			t.Errorf("Facts[tool_names] = %v, want it to exclude \"Dependabot\" — the Dependabot config fetch failed, so its presence can't be reported as a confirmed fact", names)
		}
	}
}

func TestCollect_DependencyReview_NoWorkflow_VerifiedFail(t *testing.T) {
	org, repo, branch := "attestward-demo", "no-dep-review-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerNoReleases(t, mux, org, repo)
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.dependency-review"].Status; got != model.StatusVerifiedFail {
		t.Errorf("dependency-review = %q, want verified-fail", got)
	}
}

// TestCollect_DependencyReview_OnlyWorkflowUnreadable_NotCheckableNotFail is
// issue #290's regression case, mirrored from #178/#202's identical fix for
// this package's other two checks: a repo whose only workflow can't be
// fetched (content 404) must NOT read verified-fail ("no dependency-review
// workflow detected") — that asserts a confirmed absence when inspection of
// the one workflow that exists actually failed. It must read not-checkable
// instead, with the skip surfaced in Facts, the same way
// C06.sca.tool-configured already does for identical evidence.
func TestCollect_DependencyReview_OnlyWorkflowUnreadable_NotCheckableNotFail(t *testing.T) {
	org, repo, branch := "attestward-demo", "flaky-dep-review-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"workflows": []map[string]any{
				{"id": 1, "name": "Mystery", "path": ".github/workflows/mystery.yml", "state": "active"},
			},
		})
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/workflows/mystery.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
	registerNoReleases(t, mux, org, repo)
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	dr := m["C06.sca.dependency-review"]
	if dr.Status != model.StatusNotCheckable {
		t.Errorf("dependency-review = %q, want not-checkable (the repo's only workflow couldn't be inspected — not a confirmed absence); reason=%q", dr.Status, dr.Reason)
	}
	skipped, ok := dr.Facts["skipped_workflows"].([]map[string]any)
	if !ok || len(skipped) != 1 || skipped[0]["path"] != ".github/workflows/mystery.yml" || skipped[0]["reason"] == "" {
		t.Errorf("skipped_workflows facts = %v, want one entry for mystery.yml with a non-empty reason", dr.Facts["skipped_workflows"])
	}
}

func TestCollect_DependencyReview_NotTriggeredOnPullRequest_Partial(t *testing.T) {
	org, repo, branch := "attestward-demo", "wrong-trigger-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerWorkflows(t, mux, org, repo, workflowFixture{ID: 1, Path: ".github/workflows/dependency-review.yml", Name: "Dependency Review", Content: dependencyReviewNoTriggerYAML})
	registerNoReleases(t, mux, org, repo)
	registerNoAlerts(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.dependency-review"].Status; got != model.StatusPartial {
		t.Errorf("dependency-review = %q, want partial; reason=%q", got, m["C06.sca.dependency-review"].Reason)
	}
}

func TestCollect_DependencyReview_NotRequiredStatusCheck_Partial(t *testing.T) {
	org, repo, branch := "attestward-demo", "not-required-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerWorkflows(t, mux, org, repo, workflowFixture{ID: 1, Path: ".github/workflows/dependency-review.yml", Name: "Dependency Review", Content: dependencyReviewWorkflowYAML})
	registerNoReleases(t, mux, org, repo)
	registerNoAlerts(t, mux, org, repo)
	// No required status checks configured at all.
	registerNoBranchProtection(t, mux, org, repo, branch)

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.dependency-review"].Status; got != model.StatusPartial {
		t.Errorf("dependency-review = %q, want partial (runs on PRs but not required); reason=%q", got, m["C06.sca.dependency-review"].Reason)
	}
}

// TestCollect_DependencyReview_LooseNameMatchOnUnrelatedJob_StaysPartial
// pins a real false-positive risk: a workflow named "PR Checks" (which
// happens to also run dependency-review-action) sitting alongside a
// required status check "PR Checks / lint" — the required check is a
// DIFFERENT job in the same workflow, not proof the dependency-review job
// itself is required. matchRequiredCheck's exact-vs-loose distinction must
// keep this at partial, not claim verified-pass on the loose substring
// match alone (mapping.WorkflowFile carries no per-job display names to
// disambiguate this precisely).
func TestCollect_DependencyReview_LooseNameMatchOnUnrelatedJob_StaysPartial(t *testing.T) {
	org, repo, branch := "attestward-demo", "loose-match-repo", "main"
	prChecksYAML := `name: PR Checks
on:
  pull_request:
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
`
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerWorkflows(t, mux, org, repo, workflowFixture{ID: 1, Path: ".github/workflows/pr-checks.yml", Name: "PR Checks", Content: prChecksYAML})
	registerNoReleases(t, mux, org, repo)
	registerNoAlerts(t, mux, org, repo)
	registerRequiredStatusCheck(t, mux, org, repo, branch, "PR Checks / lint")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.dependency-review"].Status; got != model.StatusPartial {
		t.Errorf("dependency-review = %q, want partial (loose name match on a DIFFERENT job's required check must not claim verified-pass); reason=%q", got, m["C06.sca.dependency-review"].Reason)
	}
}

func TestCollect_AlertsTriaged_CriticalBeyondThreshold_Partial(t *testing.T) {
	org, repo, branch := "attestward-demo", "stale-critical-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerNoReleases(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)
	registerAlerts(t, mux, org, repo, []map[string]any{
		{
			"number":            1,
			"state":             "open",
			"created_at":        time.Now().UTC().AddDate(0, 0, -40).Format(time.RFC3339),
			"security_advisory": map[string]any{"severity": "critical"},
		},
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.alerts-triaged"].Status; got != model.StatusPartial {
		t.Errorf("alerts-triaged = %q, want partial; reason=%q", got, m["C06.sca.alerts-triaged"].Reason)
	}
	if got, _ := m["C06.sca.alerts-triaged"].Facts["open_critical_count"].(int); got != 1 {
		t.Errorf("Facts[open_critical_count] = %v, want 1", m["C06.sca.alerts-triaged"].Facts["open_critical_count"])
	}
}

func TestCollect_AlertsTriaged_RecentCritical_VerifiedPass(t *testing.T) {
	org, repo, branch := "attestward-demo", "fresh-critical-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerNoReleases(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)
	registerAlerts(t, mux, org, repo, []map[string]any{
		{
			"number":            1,
			"state":             "open",
			"created_at":        time.Now().UTC().AddDate(0, 0, -5).Format(time.RFC3339),
			"security_advisory": map[string]any{"severity": "critical"},
		},
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.alerts-triaged"].Status; got != model.StatusVerifiedPass {
		t.Errorf("alerts-triaged = %q, want verified-pass (within the triage window); reason=%q", got, m["C06.sca.alerts-triaged"].Reason)
	}
}

// TestCollect_AlertsDisabled403_VerifiedFail pins GitHub's real, empirically
// confirmed behavior for a repo with Dependabot alerts turned off: a 403
// whose message says the feature is disabled — not a 404, and not a bare
// "you are not authorized" 403 (see TestCollect_AlertsForbidden403_NotCheckable
// for that distinct case).
func TestCollect_AlertsDisabled403_VerifiedFail(t *testing.T) {
	org, repo, branch := "attestward-demo", "alerts-disabled-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerNoReleases(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)
	registerAlertsStatus(t, mux, org, repo, http.StatusForbidden, "Dependabot alerts are disabled for this repository.")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.alerts-triaged"].Status; got != model.StatusVerifiedFail {
		t.Errorf("alerts-triaged = %q, want verified-fail (disabled is a real gap); reason=%q", got, m["C06.sca.alerts-triaged"].Reason)
	}
}

// TestCollect_AlertsNotFound404_NotCheckable proves a plain 404 (which,
// unlike the disabled-feature case above, doesn't carry a message
// confirming what it means) degrades honestly to not-checkable rather than
// being assumed to mean "disabled."
func TestCollect_AlertsNotFound404_NotCheckable(t *testing.T) {
	org, repo, branch := "attestward-demo", "alerts-404-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerNoReleases(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)
	registerAlertsStatus(t, mux, org, repo, http.StatusNotFound, "Not Found")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.alerts-triaged"].Status; got != model.StatusNotCheckable {
		t.Errorf("alerts-triaged = %q, want not-checkable; reason=%q", got, m["C06.sca.alerts-triaged"].Reason)
	}
}

func TestCollect_AlertsForbidden403_NotCheckable(t *testing.T) {
	org, repo, branch := "attestward-demo", "alerts-forbidden-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerNoReleases(t, mux, org, repo)
	registerNoBranchProtection(t, mux, org, repo, branch)
	registerAlertsStatus(t, mux, org, repo, http.StatusForbidden, "You are not authorized to perform this operation.")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C06.sca.alerts-triaged"].Status; got != model.StatusNotCheckable {
		t.Errorf("alerts-triaged = %q, want not-checkable; reason=%q", got, m["C06.sca.alerts-triaged"].Reason)
	}
}

func TestCollect_RepoFetchFailure403_AllChecksNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/secret-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"secret-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	for _, id := range checkIDs {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got)
		}
	}
}

func TestCollect_PreCanceledContextProducesNotCheckableNotPanic(t *testing.T) {
	mux := http.NewServeMux()
	c := newCollectorForServer(t, newTestServer(t, mux))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := c.Collect(ctx, collect.Scope{Org: "attestward-demo", Repos: []string{"repo-a"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	for _, id := range checkIDs {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got)
		}
	}
}

func TestChecksRegistered(t *testing.T) {
	if len(checkTitles) != 5 {
		t.Fatalf("len(checkTitles) = %d, want 5", len(checkTitles))
	}
	for id := range checkTitles {
		if _, ok := collect.Lookup(id); !ok {
			t.Errorf("check %q not found in the collect.CheckMeta registry", id)
		}
	}
}

// checkWantStatuses is a human-reviewed declaration of exactly which
// statuses each check can produce (see orgsecurity's own copy of this
// pattern for the full rationale). Unlike C05, every one of C06's five
// checks can reach all four statuses, including alerts-triaged (whose
// partial branch is a real, reachable aged-critical-alert case — see
// checkAlertsTriaged in checks.go).
var checkWantStatuses = map[string][]model.Status{
	"C06.sca.tool-configured":   {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	"C06.sca.ran-per-release":   {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	"C06.sca.dependabot-config": {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	"C06.sca.dependency-review": {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	"C06.sca.alerts-triaged":    {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
}

var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) /`)

// TestCollect_RegisteredMetadataCompleteForChecksReference is
// orgsecurity's TestCollect_RegisteredMetadataCompleteForChecksReference,
// replicated per the pattern that PR validated: see that test's own doc
// comment for the full rationale (exact Rubric key-set equality per check,
// GET/HEAD-only Endpoints enforcing ADR-0004, orphaned-key detection).
func TestCollect_RegisteredMetadataCompleteForChecksReference(t *testing.T) {
	if len(checkRubrics) != len(checkTitles) {
		t.Errorf("checkRubrics has %d entries, checkTitles has %d — a typo'd/orphaned key won't otherwise be caught", len(checkRubrics), len(checkTitles))
	}
	if len(checkEndpoints) != len(checkTitles) {
		t.Errorf("checkEndpoints has %d entries, checkTitles has %d — a typo'd/orphaned key won't otherwise be caught", len(checkEndpoints), len(checkTitles))
	}

	for id := range checkTitles {
		meta, ok := collect.Lookup(id)
		if !ok {
			t.Fatalf("check %q not found in the collect.CheckMeta registry", id)
		}

		want, ok := checkWantStatuses[id]
		if !ok {
			t.Fatalf("checkWantStatuses is missing an entry for %q — add the statuses this check can actually produce", id)
		}
		wantSet := make(map[model.Status]bool, len(want))
		for _, s := range want {
			wantSet[s] = true
		}
		for s := range wantSet {
			if meta.Rubric[s] == "" {
				t.Errorf("%s: Rubric[%s] is empty, want a concrete explanation", id, s)
			}
		}
		for s := range meta.Rubric {
			if !wantSet[s] {
				t.Errorf("%s: Rubric has an entry for status %q, but checkWantStatuses says this check can't produce it — either the rubric is wrong or checkWantStatuses is stale", id, s)
			}
		}

		if len(meta.Endpoints) == 0 {
			t.Errorf("%s: Endpoints is empty, want at least one", id)
		}
		for _, e := range meta.Endpoints {
			if !endpointVerbRE.MatchString(e) {
				t.Errorf("%s: Endpoints entry %q isn't GET/HEAD — this project is read-only forever (ADR-0004)", id, e)
			}
		}

		if meta.FixtureRef == "" {
			t.Errorf("%s: FixtureRef is empty", id)
		}
	}
}

// TestToolConfiguredRubricHandlesExistingButEmptyConfig locks in that the
// fail/partial rubric text doesn't claim a confirmed absence of any
// Dependabot config — dependabotConfigured requires
// len(cfg.ecosystems()) > 0 (scahistory.go), so a dependabot.yml that
// EXISTS but configures nothing (an empty `updates:` list, or entries
// missing `package-ecosystem`) reaches configExists=true,
// dependabotConfigured=false, dependabotErr=nil, and lands in the exact
// same fail/partial branches as a genuinely-absent config. Unqualified
// wording ("confirmed no config exists"/"no Dependabot config was
// found") is false for that reachable case.
func TestToolConfiguredRubricHandlesExistingButEmptyConfig(t *testing.T) {
	fail := checkRubrics["C06.sca.tool-configured"][model.StatusVerifiedFail]
	if strings.Contains(fail, "confirmed no config exists at either accepted path") {
		t.Errorf("C06.sca.tool-configured verified-fail rubric asserts a confirmed absence, but an existing-but-empty config reaches this same branch: %q", fail)
	}
	partial := checkRubrics["C06.sca.tool-configured"][model.StatusPartial]
	if strings.Contains(partial, "no Dependabot config was found") {
		t.Errorf("C06.sca.tool-configured partial rubric asserts a confirmed absence, but an existing-but-empty config (or a fetch failure alongside a low-confidence match) reaches this same branch: %q", partial)
	}
}

// TestAlertsTriagedRemediationCoversDisabledFailMode locks in that the
// remediation addresses checkAlertsTriaged's verified-fail path (the 403
// "disabled" response, meaning Dependabot alerts aren't enabled at all —
// its Security > Dependabot alerts view doesn't even exist in that state),
// not just the partial path (an aged critical alert). Advice that only
// covers triaging an existing alert is unfollowable when there's no
// feature enabled to view alerts in.
func TestAlertsTriagedRemediationCoversDisabledFailMode(t *testing.T) {
	remediation := strings.ToLower(checkRemediations["C06.sca.alerts-triaged"])
	if !strings.Contains(remediation, "enable") {
		t.Errorf("C06.sca.alerts-triaged remediation doesn't cover enabling Dependabot alerts (the check's verified-fail mode is the feature being disabled entirely): %q", checkRemediations["C06.sca.alerts-triaged"])
	}
}

const grypeWorkflowYAML = `name: Grype Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: anchore/scan-action@v4
`

// lowConfidenceSnykYAML is named "Snyk" — matching the snyk signature's
// low-confidence workflow_name_pattern — while invoking neither a snyk
// action nor the snyk CLI, so it produces a name-only match and nothing
// stronger.
const lowConfidenceSnykYAML = `name: Snyk
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
`

func scaSuccessfulRun(sha string, daysAgo int) map[string]any {
	return map[string]any{
		"head_sha": sha, "head_branch": "main", "conclusion": "success",
		"created_at": time.Now().UTC().AddDate(0, 0, -daysAgo).Format(time.RFC3339),
	}
}

// registerDependabotConfigStatus registers a Dependabot config fetch that
// FAILS (rather than legitimately 404ing at both paths), which
// fetchDependabotConfig reports as a real error rather than a confirmed
// absence.
func registerDependabotConfigStatus(t *testing.T, mux *http.ServeMux, org, repo string, status int) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/dependabot.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, status, map[string]any{"message": "Forbidden"})
	})
}

func dependabotConfigFor(ecosystems ...string) string {
	out := "version: 2\nupdates:\n"
	for _, e := range ecosystems {
		out += "  - package-ecosystem: \"" + e + "\"\n    directory: \"/\"\n    schedule:\n      interval: weekly\n"
	}
	return out
}

// scaRubricState is one fixture world for TestRubricsMatchObservedBehaviour.
// C06's five checks draw on six different upstream reads in varying
// combinations, and which of them a given state needs to bend varies too
// much for a flat struct of optional fields — so each state registers its
// own handlers.
type scaRubricState struct {
	name  string
	setup func(t *testing.T, mux *http.ServeMux, org, repo string)
	want  map[string]model.Status
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue #10).
//
// # Conflation risks
//
// Four of C06's five checks read overlapping evidence, and in each pair the
// naive fixture moves both together:
//
//  1. tool-configured and dependabot-config BOTH read the same
//     .github/dependabot.yml fetch (configExists, cfg, dependabotErr).
//     tool-configured passes on the config merely existing with one usable
//     `updates:` entry; dependabot-config passes only if it COVERS every
//     detected ecosystem. State 4 makes them disagree — a config that
//     covers gomod while npm is also detected — and state 12 splits their
//     shared failure handling.
//  2. tool-configured and dependency-review BOTH read workflowMatches, but
//     through different lenses: matchConfidence over ALL SCA matches versus
//     findMatchedSignature for the dependency-review signature specifically.
//     Any state whose SCA workflow is Trivy or Grype rather than
//     dependency-review-action separates them (2, 3, 5, 7, 10, 13, 14, 15).
//  3. tool-configured and ran-per-release BOTH read workflowMatches plus the
//     Dependabot config. States 3 and 4 are the split: Dependabot alone is
//     a configured tool with no per-release run history to evaluate, so one
//     passes while the other reports not-checkable.
//  4. ran-per-release and dependency-review BOTH consume matched workflows,
//     and dependency-review-action is ITSELF SCA-category, so in a
//     dependency-review-only repo the same workflow feeds both. State 8
//     holds exactly that repo and still splits them.
//
// C06.sca.alerts-triaged is the one check with NO conflation risk: it reads
// only GET /repos/{owner}/{repo}/dependabot/alerts, shares no intermediate
// with any other check, and nothing else in the collector reads that
// response. Its four statuses are still driven independently across the
// matrix (fail in state 2, partial in 3 and 4 by the two different routes
// the rubric documents, not-checkable in 10 and 11) rather than left to
// ride along at pass.
//
// # Confirmed by mutation, not assumed
//
// Each was injected into the production code and traced to the exact states
// that caught it:
//
//   - checkDependabotConfig's uncovered-ecosystem comparison short-circuited
//     to always-covered (`var uncovered []string` with the loop removed):
//     caught by state 4 alone, the only state whose config covers some but
//     not all detected ecosystems.
//   - checkDependencyReview keyed off `len(matched) > 0` instead of the
//     dependency-review signature specifically — i.e. reading
//     tool-configured's evidence: caught by states 2, 5, 7, 10, 13, 14 and
//     15, every state with a non-dep-review SCA workflow. NOT by 3 or 4,
//     which have no workflows at all, so the mutated expression is false
//     there too.
//   - checkRanPerRelease's dependabotOnly guard dropped, so a
//     Dependabot-only repo has its releases evaluated against zero runs:
//     caught by state 3 alone. State 4 is Dependabot-only as well but has
//     no releases, so it reports not-checkable by the other route either
//     way — a reminder that "reaches the guard" and "binds the guard" are
//     different properties.
//   - checkRanPerRelease's runsErr guard widened to taint unconditionally
//     (reverting #291's narrowing): caught by state 13 alone.
//   - checkRanPerRelease's `case allRan && droppedTags == 0` weakened to
//     `case allRan`: caught by state 15 alone.
//   - checkDependencyReview's triggersOnPullRequest guard dropped: caught by
//     state 8 alone — and only after that state was given an exactly-named
//     required status check. Its first form registered no branch
//     protection, so it reported partial with the guard AND partial without
//     it (falling through to "no required check matches"), and the mutation
//     survived. That near-miss is why the state now configures the required
//     check: it forces the two paths to different statuses.
//   - checkAlertsTriaged's `case summary.OpenUnclassifiedCount > 0` arm
//     deleted: caught by state 4 alone, the only state with an alert whose
//     severity this build cannot interpret.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	const org = "attestward-demo"
	yesterday := time.Now().UTC().AddDate(0, 0, -1)
	staleCritical := []map[string]any{{
		"number": 1, "state": "open",
		"security_advisory": map[string]any{"severity": "critical"},
		"created_at":        time.Now().UTC().AddDate(0, 0, -60).Format(time.RFC3339),
	}}
	unclassified := []map[string]any{{
		"number": 1, "state": "open",
		"created_at": time.Now().UTC().AddDate(0, 0, -3).Format(time.RFC3339),
	}}

	states := []scaRubricState{
		{
			// Everything healthy, and the only state that reaches
			// dependency-review's verified-pass: the workflow triggers on
			// pull_request AND its name exactly matches a required status
			// check.
			name: "workflow SCA, covered release, full Dependabot config, required dependency review",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerWorkflows(t, mux, org, repo,
					workflowFixture{ID: 1, Path: ".github/workflows/trivy.yml", Name: "Trivy Scan", Content: trivyWorkflowYAML},
					workflowFixture{ID: 2, Path: ".github/workflows/dep-review.yml", Name: "Dependency Review", Content: dependencyReviewWorkflowYAML},
				)
				registerOneRelease(t, mux, org, repo, "v1.0.0", "sha1", yesterday)
				registerWorkflowRuns(t, mux, org, repo, 1, []map[string]any{scaSuccessfulRun("sha1", 1)})
				registerWorkflowRuns(t, mux, org, repo, 2, []map[string]any{scaSuccessfulRun("sha1", 1)})
				registerRootFiles(t, mux, org, repo)
				registerDependabotConfig(t, mux, org, repo, dependabotConfigFor("github-actions"))
				registerRequiredStatusCheck(t, mux, org, repo, "main", "Dependency Review")
				registerNoAlerts(t, mux, org, repo)
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusVerifiedPass,
				"C06.sca.ran-per-release":   model.StatusVerifiedPass,
				"C06.sca.dependabot-config": model.StatusVerifiedPass,
				"C06.sca.dependency-review": model.StatusVerifiedPass,
				"C06.sca.alerts-triaged":    model.StatusVerifiedPass,
			},
		},
		{
			// A real SCA workflow that is NOT dependency-review, no
			// Dependabot config at all, no releases, and alerts switched
			// off: four different answers off one repo.
			name: "Trivy workflow only, no Dependabot config, no releases, alerts disabled",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerWorkflows(t, mux, org, repo,
					workflowFixture{ID: 1, Path: ".github/workflows/trivy.yml", Name: "Trivy Scan", Content: trivyWorkflowYAML},
				)
				registerNoReleases(t, mux, org, repo)
				registerWorkflowRuns(t, mux, org, repo, 1, []map[string]any{})
				registerRootFiles(t, mux, org, repo, "go.mod")
				registerNoBranchProtection(t, mux, org, repo, "main")
				registerAlertsStatus(t, mux, org, repo, http.StatusForbidden, "Dependabot alerts are disabled for this repository.")
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusVerifiedPass,
				"C06.sca.ran-per-release":   model.StatusNotCheckable,
				"C06.sca.dependabot-config": model.StatusVerifiedFail,
				"C06.sca.dependency-review": model.StatusVerifiedFail,
				"C06.sca.alerts-triaged":    model.StatusVerifiedFail,
			},
		},
		{
			// Dependabot is the sole SCA tool. tool-configured passes on
			// it; ran-per-release has no per-release run history such a
			// tool could ever produce.
			name: "Dependabot-only repo with a stale critical alert",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerNoWorkflows(t, mux, org, repo)
				registerOneRelease(t, mux, org, repo, "v1.0.0", "sha1", yesterday)
				registerRootFiles(t, mux, org, repo, "go.mod")
				registerDependabotConfig(t, mux, org, repo, dependabotConfigFor("gomod"))
				registerNoBranchProtection(t, mux, org, repo, "main")
				registerAlerts(t, mux, org, repo, staleCritical)
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusVerifiedPass,
				"C06.sca.ran-per-release":   model.StatusNotCheckable,
				"C06.sca.dependabot-config": model.StatusVerifiedPass,
				"C06.sca.dependency-review": model.StatusVerifiedFail,
				"C06.sca.alerts-triaged":    model.StatusPartial,
			},
		},
		{
			// The tool-configured / dependabot-config split: the same
			// config that satisfies "a tool is configured" leaves npm
			// uncovered. Also the only state whose alerts carry a severity
			// this build cannot interpret.
			name: "Dependabot config covers one of two detected ecosystems",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerNoWorkflows(t, mux, org, repo)
				registerNoReleases(t, mux, org, repo)
				registerRootFiles(t, mux, org, repo, "go.mod", "package.json")
				registerDependabotConfig(t, mux, org, repo, dependabotConfigFor("gomod"))
				registerNoBranchProtection(t, mux, org, repo, "main")
				registerAlerts(t, mux, org, repo, unclassified)
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusVerifiedPass,
				"C06.sca.ran-per-release":   model.StatusNotCheckable,
				"C06.sca.dependabot-config": model.StatusPartial,
				"C06.sca.dependency-review": model.StatusVerifiedFail,
				"C06.sca.alerts-triaged":    model.StatusPartial,
			},
		},
		{
			// The only route to tool-configured's partial: a workflow named
			// "Snyk" that invokes nothing recognizable.
			name: "low-confidence-only Snyk match",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerWorkflows(t, mux, org, repo,
					workflowFixture{ID: 1, Path: ".github/workflows/snyk.yml", Name: "Snyk", Content: lowConfidenceSnykYAML},
				)
				registerNoReleases(t, mux, org, repo)
				registerWorkflowRuns(t, mux, org, repo, 1, []map[string]any{})
				registerRootFiles(t, mux, org, repo)
				registerNoBranchProtection(t, mux, org, repo, "main")
				registerNoAlerts(t, mux, org, repo)
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusPartial,
				"C06.sca.ran-per-release":   model.StatusNotCheckable,
				"C06.sca.dependabot-config": model.StatusVerifiedFail,
				"C06.sca.dependency-review": model.StatusVerifiedFail,
				"C06.sca.alerts-triaged":    model.StatusVerifiedPass,
			},
		},
		{
			// No SCA evidence from either source, an empty root so nothing
			// is detected for Dependabot to cover, and a release that
			// nothing ran for.
			name: "no SCA evidence at all with a release in scope",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerNoWorkflows(t, mux, org, repo)
				registerOneRelease(t, mux, org, repo, "v1.0.0", "sha1", yesterday)
				registerRootFiles(t, mux, org, repo)
				registerNoBranchProtection(t, mux, org, repo, "main")
				registerNoAlerts(t, mux, org, repo)
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusVerifiedFail,
				"C06.sca.ran-per-release":   model.StatusVerifiedFail,
				"C06.sca.dependabot-config": model.StatusNotCheckable,
				"C06.sca.dependency-review": model.StatusVerifiedFail,
				"C06.sca.alerts-triaged":    model.StatusVerifiedPass,
			},
		},
		{
			name: "SCA tool ran for the release but failed",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerWorkflows(t, mux, org, repo,
					workflowFixture{ID: 1, Path: ".github/workflows/trivy.yml", Name: "Trivy Scan", Content: trivyWorkflowYAML},
				)
				registerOneRelease(t, mux, org, repo, "v1.0.0", "sha1", yesterday)
				registerWorkflowRuns(t, mux, org, repo, 1, []map[string]any{
					{"head_sha": "sha1", "head_branch": "main", "conclusion": "failure", "created_at": yesterday.Format(time.RFC3339)},
				})
				registerRootFiles(t, mux, org, repo)
				registerDependabotConfig(t, mux, org, repo, dependabotConfigFor("github-actions"))
				registerNoBranchProtection(t, mux, org, repo, "main")
				registerNoAlerts(t, mux, org, repo)
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusVerifiedPass,
				"C06.sca.ran-per-release":   model.StatusPartial,
				"C06.sca.dependabot-config": model.StatusVerifiedPass,
				"C06.sca.dependency-review": model.StatusVerifiedFail,
				"C06.sca.alerts-triaged":    model.StatusVerifiedPass,
			},
		},
		{
			// A dependency-review-ONLY repo: one workflow feeds both
			// ran-per-release (as an SCA-category match) and
			// dependency-review (as the signature), and they still
			// disagree, because the workflow never triggers on a pull
			// request and so gates nothing.
			//
			// The required status check is deliberately configured and
			// deliberately an EXACT name match. Without it this state
			// reports partial either way — the trigger guard and the
			// no-required-check fallthrough produce the same status — so
			// deleting triggersOnPullRequest entirely would go unnoticed.
			// With it, the two paths diverge: partial while the guard
			// stands, verified-pass the moment it is removed.
			name: "dependency-review workflow is a required check but never triggers on pull requests",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerWorkflows(t, mux, org, repo,
					workflowFixture{ID: 2, Path: ".github/workflows/dep-review.yml", Name: "Dependency Review", Content: dependencyReviewNoTriggerYAML},
				)
				registerOneRelease(t, mux, org, repo, "v1.0.0", "sha1", yesterday)
				registerWorkflowRuns(t, mux, org, repo, 2, []map[string]any{scaSuccessfulRun("sha1", 1)})
				registerRootFiles(t, mux, org, repo)
				registerDependabotConfig(t, mux, org, repo, dependabotConfigFor("github-actions"))
				registerRequiredStatusCheck(t, mux, org, repo, "main", "Dependency Review")
				registerNoAlerts(t, mux, org, repo)
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusVerifiedPass,
				"C06.sca.ran-per-release":   model.StatusVerifiedPass,
				"C06.sca.dependabot-config": model.StatusVerifiedPass,
				"C06.sca.dependency-review": model.StatusPartial,
				"C06.sca.alerts-triaged":    model.StatusVerifiedPass,
			},
		},
		{
			// The repo's only workflow can't be inspected, so three checks
			// refuse to assert an absence — while dependabot-config, which
			// reads the root listing and the config rather than workflow
			// content, still answers.
			name: "the only workflow is unreadable",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusOK, map[string]any{
						"total_count": 1,
						"workflows":   []map[string]any{{"id": 1, "name": "Mystery", "path": ".github/workflows/mystery.yml", "state": "active"}},
					})
				})
				mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/workflows/mystery.yml", func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
				})
				registerNoReleases(t, mux, org, repo)
				registerRootFiles(t, mux, org, repo)
				registerNoBranchProtection(t, mux, org, repo, "main")
				registerNoAlerts(t, mux, org, repo)
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusNotCheckable,
				"C06.sca.ran-per-release":   model.StatusNotCheckable,
				"C06.sca.dependabot-config": model.StatusVerifiedFail,
				"C06.sca.dependency-review": model.StatusNotCheckable,
				"C06.sca.alerts-triaged":    model.StatusVerifiedPass,
			},
		},
		{
			// The alerts endpoint fails with something other than a
			// confirmed "disabled", which this collector can't read as an
			// off state. Nothing else depends on that response.
			name: "alerts fetch 404 while everything else resolves",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerWorkflows(t, mux, org, repo,
					workflowFixture{ID: 1, Path: ".github/workflows/trivy.yml", Name: "Trivy Scan", Content: trivyWorkflowYAML},
				)
				registerOneRelease(t, mux, org, repo, "v1.0.0", "sha1", yesterday)
				registerWorkflowRuns(t, mux, org, repo, 1, []map[string]any{scaSuccessfulRun("sha1", 1)})
				registerRootFiles(t, mux, org, repo)
				registerDependabotConfig(t, mux, org, repo, dependabotConfigFor("github-actions"))
				registerNoBranchProtection(t, mux, org, repo, "main")
				registerAlertsStatus(t, mux, org, repo, http.StatusNotFound, "Not Found")
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusVerifiedPass,
				"C06.sca.ran-per-release":   model.StatusVerifiedPass,
				"C06.sca.dependabot-config": model.StatusVerifiedPass,
				"C06.sca.dependency-review": model.StatusVerifiedFail,
				"C06.sca.alerts-triaged":    model.StatusNotCheckable,
			},
		},
		{
			// The repo read fails, so collectRepo returns before any
			// check-specific evidence exists: the only route to all five
			// reporting not-checkable together.
			name: "repo read forbidden",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				mux.HandleFunc("/repos/"+org+"/"+repo, func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
				})
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusNotCheckable,
				"C06.sca.ran-per-release":   model.StatusNotCheckable,
				"C06.sca.dependabot-config": model.StatusNotCheckable,
				"C06.sca.dependency-review": model.StatusNotCheckable,
				"C06.sca.alerts-triaged":    model.StatusNotCheckable,
			},
		},
		{
			// The Dependabot config fetch itself fails with no workflow
			// evidence to fall back on. Three checks that read it go
			// not-checkable; dependency-review, which never reads it,
			// still asserts its own confirmed absence.
			name: "Dependabot config fetch forbidden with no workflow evidence",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerNoWorkflows(t, mux, org, repo)
				registerOneRelease(t, mux, org, repo, "v1.0.0", "sha1", yesterday)
				registerRootFiles(t, mux, org, repo, "go.mod")
				registerDependabotConfigStatus(t, mux, org, repo, http.StatusForbidden)
				registerNoBranchProtection(t, mux, org, repo, "main")
				registerNoAlerts(t, mux, org, repo)
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusNotCheckable,
				"C06.sca.ran-per-release":   model.StatusNotCheckable,
				"C06.sca.dependabot-config": model.StatusNotCheckable,
				"C06.sca.dependency-review": model.StatusVerifiedFail,
				"C06.sca.alerts-triaged":    model.StatusVerifiedPass,
			},
		},
		{
			// Issue #291: one of two matched SCA workflows fails its run
			// fetch, but the release already reads "ran" from the other.
			// Coverage is monotone in the runs pool, so it cannot be
			// invalidated by runs it never needed.
			name: "second workflow's run fetch fails while every release already ran",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerWorkflows(t, mux, org, repo,
					workflowFixture{ID: 1, Path: ".github/workflows/trivy.yml", Name: "Trivy Scan", Content: trivyWorkflowYAML},
					workflowFixture{ID: 2, Path: ".github/workflows/grype.yml", Name: "Grype Scan", Content: grypeWorkflowYAML},
				)
				registerOneRelease(t, mux, org, repo, "v1.0.0", "sha1", yesterday)
				registerWorkflowRuns(t, mux, org, repo, 1, []map[string]any{scaSuccessfulRun("sha1", 1)})
				mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows/2/runs", func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "API rate limit exceeded"})
				})
				registerRootFiles(t, mux, org, repo)
				registerDependabotConfig(t, mux, org, repo, dependabotConfigFor("github-actions"))
				registerNoBranchProtection(t, mux, org, repo, "main")
				registerNoAlerts(t, mux, org, repo)
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusVerifiedPass,
				"C06.sca.ran-per-release":   model.StatusVerifiedPass,
				"C06.sca.dependabot-config": model.StatusVerifiedPass,
				"C06.sca.dependency-review": model.StatusVerifiedFail,
				"C06.sca.alerts-triaged":    model.StatusVerifiedPass,
			},
		},
		{
			// Issue #287, and state 13's necessary counterpart: the only
			// matched workflow's run fetch fails and the coverage table
			// therefore DOES assert an absence, so ran-per-release refuses
			// it. Without this state, #291's narrowing could be widened
			// back to an unconditional taint and only state 13 would
			// notice; without state 13, it could be deleted entirely and
			// only this one would.
			name: "the only workflow's run fetch fails with an uncovered release",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerWorkflows(t, mux, org, repo,
					workflowFixture{ID: 1, Path: ".github/workflows/trivy.yml", Name: "Trivy Scan", Content: trivyWorkflowYAML},
				)
				registerOneRelease(t, mux, org, repo, "v1.0.0", "sha1", yesterday)
				mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows/1/runs", func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "API rate limit exceeded"})
				})
				registerRootFiles(t, mux, org, repo)
				registerDependabotConfig(t, mux, org, repo, dependabotConfigFor("github-actions"))
				registerNoBranchProtection(t, mux, org, repo, "main")
				registerNoAlerts(t, mux, org, repo)
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusVerifiedPass,
				"C06.sca.ran-per-release":   model.StatusNotCheckable,
				"C06.sca.dependabot-config": model.StatusVerifiedPass,
				"C06.sca.dependency-review": model.StatusVerifiedFail,
				"C06.sca.alerts-triaged":    model.StatusVerifiedPass,
			},
		},
		{
			// Coverage is clean for every release that resolved, but an
			// in-window tag could not be resolved at all — the
			// droppedTags == 0 arm of ran-per-release's switch.
			name: "one in-window release tag is unresolvable",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerWorkflows(t, mux, org, repo,
					workflowFixture{ID: 1, Path: ".github/workflows/trivy.yml", Name: "Trivy Scan", Content: trivyWorkflowYAML},
				)
				mux.HandleFunc("/repos/"+org+"/"+repo+"/releases", func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusOK, []map[string]any{
						{"tag_name": "v1.0.0", "target_commitish": "main", "published_at": yesterday.Format(time.RFC3339)},
						{"tag_name": "v0.9.0", "target_commitish": "main", "published_at": time.Now().UTC().AddDate(0, 0, -30).Format(time.RFC3339)},
					})
				})
				mux.HandleFunc("/repos/"+org+"/"+repo+"/git/ref/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusOK, map[string]any{"ref": "refs/tags/v1.0.0", "object": map[string]any{"type": "commit", "sha": "sha1"}})
				})
				mux.HandleFunc("/repos/"+org+"/"+repo+"/git/ref/tags/v0.9.0", func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
				})
				registerWorkflowRuns(t, mux, org, repo, 1, []map[string]any{scaSuccessfulRun("sha1", 1)})
				registerRootFiles(t, mux, org, repo)
				registerDependabotConfig(t, mux, org, repo, dependabotConfigFor("github-actions"))
				registerNoBranchProtection(t, mux, org, repo, "main")
				registerNoAlerts(t, mux, org, repo)
			},
			want: map[string]model.Status{
				"C06.sca.tool-configured":   model.StatusVerifiedPass,
				"C06.sca.ran-per-release":   model.StatusPartial,
				"C06.sca.dependabot-config": model.StatusVerifiedPass,
				"C06.sca.dependency-review": model.StatusVerifiedFail,
				"C06.sca.alerts-triaged":    model.StatusVerifiedPass,
			},
		},
	}

	var all []model.CheckResult
	for i, st := range states {
		t.Run(st.name, func(t *testing.T) {
			// A distinct repo name per state keeps each state's handler
			// registrations on their own mux paths, so a helper that
			// registers a fixed path can't collide across states.
			repo := fmt.Sprintf("rubric-repo-%02d", i+1)
			mux := http.NewServeMux()
			st.setup(t, mux, org, repo)

			c := newCollectorForServer(t, newTestServer(t, mux))
			scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
			results, err := c.Collect(context.Background(), scope)
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}

			got := map[string]model.Status{}
			for _, r := range results {
				if _, dup := got[r.CheckID]; dup {
					t.Errorf("%s emitted twice", r.CheckID)
				}
				got[r.CheckID] = r.Status
			}
			// Compared whole, in both directions: a missing key is as much
			// a defect as a wrong one, and a row count would show neither.
			for id, want := range st.want {
				if got[id] != want {
					t.Errorf("%s = %q, want %q", id, got[id], want)
				}
			}
			for id, status := range got {
				if _, expected := st.want[id]; !expected {
					t.Errorf("%s = %q, but this state expects no result for it", id, status)
				}
			}
			all = append(all, results...)
		})
	}

	collecttest.AssertRubricsMatchObservedBehaviour(t, "github", collectorID, all)
}
