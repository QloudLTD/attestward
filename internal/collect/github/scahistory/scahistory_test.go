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

	"github.com/sioakim/attestward/internal/collect"
	ghcollect "github.com/sioakim/attestward/internal/collect/github"
	"github.com/sioakim/attestward/internal/model"
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
	org, repo, branch := "attestor-demo", "good-repo", "main"
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
	org, repo, branch := "attestor-demo", "dependabot-only-repo", "main"
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

func TestCollect_NoSCAToolAtAll_ToolConfiguredFails(t *testing.T) {
	org, repo, branch := "attestor-demo", "bare-repo", "main"
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
	org, repo, branch := "attestor-demo", "uncovered-repo", "main"
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
	org, repo, branch := "attestor-demo", "partial-repo", "main"
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
	org, repo, branch := "attestor-demo", "root-403-repo", "main"
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
	org, repo, branch := "attestor-demo", "releases-403-repo", "main"
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
	org, repo, branch := "attestor-demo", "dependabot-403-repo", "main"
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
	org, repo, branch := "attestor-demo", "dependabot-403-release-repo", "main"
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

func TestCollect_DependencyReview_NoWorkflow_VerifiedFail(t *testing.T) {
	org, repo, branch := "attestor-demo", "no-dep-review-repo", "main"
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

func TestCollect_DependencyReview_NotTriggeredOnPullRequest_Partial(t *testing.T) {
	org, repo, branch := "attestor-demo", "wrong-trigger-repo", "main"
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
	org, repo, branch := "attestor-demo", "not-required-repo", "main"
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
	org, repo, branch := "attestor-demo", "loose-match-repo", "main"
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
	org, repo, branch := "attestor-demo", "stale-critical-repo", "main"
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
	org, repo, branch := "attestor-demo", "fresh-critical-repo", "main"
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
	org, repo, branch := "attestor-demo", "alerts-disabled-repo", "main"
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
	org, repo, branch := "attestor-demo", "alerts-404-repo", "main"
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
	org, repo, branch := "attestor-demo", "alerts-forbidden-repo", "main"
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
	mux.HandleFunc("/repos/attestor-demo/secret-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"secret-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
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

	results, err := c.Collect(ctx, collect.Scope{Org: "attestor-demo", Repos: []string{"repo-a"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12})
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
