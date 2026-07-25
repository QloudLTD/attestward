package sasthistory

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

const codeqlWorkflowYAML = `name: CodeQL
on: [push]
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/analyze@v4
`

// baseRepoHandlers registers the handlers every scenario needs: the repo
// itself (default_branch), an empty workflow-run history endpoint isn't
// needed generically (registered per matched workflow ID by callers), and
// a not-configured default-setup response (callers override if they want
// "configured").
func registerRepo(t *testing.T, mux *http.ServeMux, org, repo, defaultBranch string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"default_branch": defaultBranch})
	})
}

func registerDefaultSetup(t *testing.T, mux *http.ServeMux, org, repo, state string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/code-scanning/default-setup", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"state": state})
	})
}

func registerNoWorkflows(t *testing.T, mux *http.ServeMux, org, repo string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"total_count": 0, "workflows": []any{}})
	})
}

func registerNoReleases(t *testing.T, mux *http.ServeMux, org, repo string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/releases", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []any{})
	})
}

// registerCodeQLWorkflow registers a single CodeQL workflow file (id=1,
// path .github/workflows/codeql.yml) whose content matches the codeql
// signature at high confidence.
func registerCodeQLWorkflow(t *testing.T, mux *http.ServeMux, org, repo string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"workflows": []map[string]any{
				{"id": 1, "name": "CodeQL", "path": ".github/workflows/codeql.yml", "state": "active"},
			},
		})
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/workflows/codeql.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"content": codeqlWorkflowYAML, "sha": "content-sha"})
	})
}

func registerOneRelease(t *testing.T, mux *http.ServeMux, org, repo, tag, commitSHA string, publishedAt time.Time) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/releases", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{
			{"tag_name": tag, "target_commitish": "main", "published_at": publishedAt.Format(time.RFC3339)},
		})
	})
	// Lightweight tag: the ref object's type is "commit" and its SHA is
	// already the target commit — no second GetTag call needed.
	mux.HandleFunc("/repos/"+org+"/"+repo+"/git/ref/tags/"+tag, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"ref":    "refs/tags/" + tag,
			"object": map[string]any{"type": "commit", "sha": commitSHA},
		})
	})
}

func registerWorkflowRuns(t *testing.T, mux *http.ServeMux, org, repo string, workflowID int64, runs []map[string]any) {
	t.Helper()
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/workflows/%d/runs", org, repo, workflowID), func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"total_count": len(runs), "workflow_runs": runs})
	})
}

// registerCodeQLDefaultSetupWorkflow registers the synthetic workflow
// entry GitHub's ListWorkflows API includes when CodeQL default setup is
// enabled — a virtual, non-file workflow at a fixed dynamic path. Its
// content is deliberately NOT registered (fetching it would 404 against a
// real GitHub API); collectRepo must special-case this path rather than
// attempt a content fetch.
func registerCodeQLDefaultSetupWorkflow(t *testing.T, mux *http.ServeMux, org, repo string, workflowID int64) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"workflows": []map[string]any{
				{"id": workflowID, "name": "CodeQL", "path": "dynamic/github-code-scanning/codeql", "state": "active"},
			},
		})
	})
}

func TestCollect_CodeQLWorkflowWithSuccessfulReleaseRun_AllChecksResolve(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "good-repo", "main")
	registerCodeQLWorkflow(t, mux, "attestward-demo", "good-repo")
	registerOneRelease(t, mux, "attestward-demo", "good-repo", "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerWorkflowRuns(t, mux, "attestward-demo", "good-repo", 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	registerDefaultSetup(t, mux, "attestward-demo", "good-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"good-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C05.sast.tool-configured"].Status; got != model.StatusVerifiedPass {
		t.Errorf("tool-configured = %q, want verified-pass; reason=%q", got, m["C05.sast.tool-configured"].Reason)
	}
	if got := m["C05.sast.ran-per-release"].Status; got != model.StatusVerifiedPass {
		t.Errorf("ran-per-release = %q, want verified-pass; reason=%q", got, m["C05.sast.ran-per-release"].Reason)
	}
	if got := m["C05.sast.cadence"].Status; got != model.StatusVerifiedPass {
		t.Errorf("cadence = %q, want verified-pass; reason=%q", got, m["C05.sast.cadence"].Reason)
	}
	if got := m["C05.sast.default-setup"].Status; got != model.StatusVerifiedFail {
		t.Errorf("default-setup = %q, want verified-fail (not-configured is a real fail); reason=%q", got, m["C05.sast.default-setup"].Reason)
	}

	perRelease, ok := m["C05.sast.ran-per-release"].Facts["per_release"].([]map[string]any)
	if !ok || len(perRelease) != 1 {
		t.Fatalf("per_release facts = %v, want 1 entry", m["C05.sast.ran-per-release"].Facts["per_release"])
	}
	if perRelease[0]["tag"] != "v1.0.0" || perRelease[0]["status"] != "ran" {
		t.Errorf("per_release[0] = %v, want tag=v1.0.0 status=ran", perRelease[0])
	}
}

func TestCollect_NoSASTToolAtAll_ToolConfiguredFailsCadenceNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "bad-repo", "main")
	registerNoWorkflows(t, mux, "attestward-demo", "bad-repo")
	registerOneRelease(t, mux, "attestward-demo", "bad-repo", "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerDefaultSetup(t, mux, "attestward-demo", "bad-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"bad-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C05.sast.tool-configured"].Status; got != model.StatusVerifiedFail {
		t.Errorf("tool-configured = %q, want verified-fail", got)
	}
	if got := m["C05.sast.cadence"].Status; got != model.StatusNotCheckable {
		t.Errorf("cadence = %q, want not-checkable (no tool to compute cadence for)", got)
	}
	if got := m["C05.sast.ran-per-release"].Status; got != model.StatusVerifiedFail {
		t.Errorf("ran-per-release = %q, want verified-fail (release exists, nothing ran)", got)
	}
}

// TestCollect_OnlyWorkflowUnreadable_ToolConfiguredNotCheckableNotFail is
// issue #178's regression case: a repo whose only workflow can't be
// fetched (content 404) and has no CodeQL default setup must NOT read
// verified-fail ("no SAST tool detected") — that asserts a confirmed
// absence when inspection of the one workflow that exists actually
// failed. It must read not-checkable instead, with the skip surfaced in
// Facts.
func TestCollect_OnlyWorkflowUnreadable_ToolConfiguredNotCheckableNotFail(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "flaky-repo", "main")
	mux.HandleFunc("/repos/attestward-demo/flaky-repo/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"workflows": []map[string]any{
				{"id": 1, "name": "Mystery", "path": ".github/workflows/mystery.yml", "state": "active"},
			},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/flaky-repo/contents/.github/workflows/mystery.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
	registerNoReleases(t, mux, "attestward-demo", "flaky-repo")
	registerDefaultSetup(t, mux, "attestward-demo", "flaky-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"flaky-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	tc := m["C05.sast.tool-configured"]
	if tc.Status != model.StatusNotCheckable {
		t.Errorf("tool-configured = %q, want not-checkable (the repo's only workflow couldn't be inspected — not a confirmed absence); reason=%q", tc.Status, tc.Reason)
	}
	skipped, ok := tc.Facts["skipped_workflows"].([]map[string]any)
	if !ok || len(skipped) != 1 || skipped[0]["path"] != ".github/workflows/mystery.yml" || skipped[0]["reason"] == "" {
		t.Errorf("skipped_workflows facts = %v, want one entry for mystery.yml with a non-empty reason", tc.Facts["skipped_workflows"])
	}
}

// TestCollect_OnlyWorkflowUnreadableWithRelease_RanPerReleaseNotCheckableNotFail
// is the review finding on #202: TestCollect_OnlyWorkflowUnreadable... above
// uses no releases, so it never actually exercises ran-per-release's own
// coverage-computation path. With a real release in scope and the repo's
// only workflow unreadable, ran-per-release previously read verified-fail
// ("no matched SAST run at all") in the same breath tool-configured read
// not-checkable for the identical evidence — two panels of one pack, opposite
// claims. Both must now agree: not-checkable.
func TestCollect_OnlyWorkflowUnreadableWithRelease_RanPerReleaseNotCheckableNotFail(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "flaky-release-repo", "main")
	mux.HandleFunc("/repos/attestward-demo/flaky-release-repo/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"workflows": []map[string]any{
				{"id": 1, "name": "Mystery", "path": ".github/workflows/mystery.yml", "state": "active"},
			},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/flaky-release-repo/contents/.github/workflows/mystery.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
	registerOneRelease(t, mux, "attestward-demo", "flaky-release-repo", "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerDefaultSetup(t, mux, "attestward-demo", "flaky-release-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"flaky-release-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	toolConfigured := m["C05.sast.tool-configured"]
	if toolConfigured.Status != model.StatusNotCheckable {
		t.Fatalf("tool-configured = %q, want not-checkable; reason=%q (test fixture no longer matches this test's premise)", toolConfigured.Status, toolConfigured.Reason)
	}
	ranPerRelease := m["C05.sast.ran-per-release"]
	if ranPerRelease.Status != model.StatusNotCheckable {
		t.Errorf("ran-per-release = %q, want not-checkable (must agree with tool-configured's not-checkable over the identical unreadable-workflow evidence, not independently assert verified-fail); reason=%q", ranPerRelease.Status, ranPerRelease.Reason)
	}
}

func TestCollect_LowConfidenceOnlyMatch_CapsAtPartial(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "iffy-repo", "main")
	mux.HandleFunc("/repos/attestward-demo/iffy-repo/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"workflows": []map[string]any{
				{"id": 1, "name": "CodeQL", "path": ".github/workflows/codeql.yml", "state": "active"},
			},
		})
	})
	// The workflow is literally named "CodeQL" (matches the low-confidence
	// workflow_name_pattern) but its content has neither the action nor
	// any run-pattern-matching step — only a name-based heuristic fires.
	mux.HandleFunc("/repos/attestward-demo/iffy-repo/contents/.github/workflows/codeql.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"content": "name: CodeQL\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"})
	})
	registerNoReleases(t, mux, "attestward-demo", "iffy-repo")
	registerWorkflowRuns(t, mux, "attestward-demo", "iffy-repo", 1, []map[string]any{})
	registerDefaultSetup(t, mux, "attestward-demo", "iffy-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"iffy-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C05.sast.tool-configured"].Status; got != model.StatusPartial {
		t.Errorf("tool-configured = %q, want partial (low-confidence match must never alone justify pass); reason=%q", got, m["C05.sast.tool-configured"].Reason)
	}
	if low, ok := m["C05.sast.tool-configured"].Facts["low_confidence_match_only"].(bool); !ok || !low {
		t.Errorf("Facts[low_confidence_match_only] = %v, want true", m["C05.sast.tool-configured"].Facts["low_confidence_match_only"])
	}
}

// TestCollect_LowConfidenceOnlyMatchWithRuns_CadenceCapsAtPartial proves
// checkCadence applies the same confidence cap as checkToolConfigured: a
// workflow-name-only match that happens to have real run history must not
// report cadence as verified-pass, since it's unconfirmed the workflow is
// actually a SAST tool at all.
func TestCollect_LowConfidenceOnlyMatchWithRuns_CadenceCapsAtPartial(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "iffy-runs-repo", "main")
	mux.HandleFunc("/repos/attestward-demo/iffy-runs-repo/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"workflows": []map[string]any{
				{"id": 1, "name": "CodeQL", "path": ".github/workflows/codeql.yml", "state": "active"},
			},
		})
	})
	// Same low-confidence-only content as TestCollect_LowConfidenceOnlyMatch_CapsAtPartial.
	mux.HandleFunc("/repos/attestward-demo/iffy-runs-repo/contents/.github/workflows/codeql.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"content": "name: CodeQL\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"})
	})
	registerNoReleases(t, mux, "attestward-demo", "iffy-runs-repo")
	registerWorkflowRuns(t, mux, "attestward-demo", "iffy-runs-repo", 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	registerDefaultSetup(t, mux, "attestward-demo", "iffy-runs-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"iffy-runs-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C05.sast.cadence"].Status; got != model.StatusPartial {
		t.Errorf("cadence = %q, want partial (low-confidence match must never alone justify pass); reason=%q", got, m["C05.sast.cadence"].Reason)
	}
	if low, ok := m["C05.sast.cadence"].Facts["low_confidence_match_only"].(bool); !ok || !low {
		t.Errorf("Facts[low_confidence_match_only] = %v, want true", m["C05.sast.cadence"].Facts["low_confidence_match_only"])
	}
}

func TestCollect_ConfiguredButRunFails_RanPerReleaseIsPartial(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "failing-repo", "main")
	registerCodeQLWorkflow(t, mux, "attestward-demo", "failing-repo")
	registerOneRelease(t, mux, "attestward-demo", "failing-repo", "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerWorkflowRuns(t, mux, "attestward-demo", "failing-repo", 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "failure", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	registerDefaultSetup(t, mux, "attestward-demo", "failing-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"failing-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C05.sast.ran-per-release"].Status; got != model.StatusPartial {
		t.Errorf("ran-per-release = %q, want partial (tool configured and attempted, but never succeeded); reason=%q", got, m["C05.sast.ran-per-release"].Reason)
	}
	// The tool DID run (just failed) — cadence still counts the attempt.
	if got := m["C05.sast.cadence"].Status; got != model.StatusVerifiedPass {
		t.Errorf("cadence = %q, want verified-pass (a run happened, regardless of its conclusion)", got)
	}
}

// TestCollect_CodeQLDefaultSetupDynamicWorkflow_RunHistoryObserved covers
// the common real-world case: CodeQL default setup is enabled, and GitHub
// surfaces it via ListWorkflows as a virtual entry at
// "dynamic/github-code-scanning/codeql" (not a real file — fetching its
// content would 404). collectRepo must recognize that path and treat it as
// a direct, high-confidence CodeQL match, then still fetch its run history
// by workflow ID like any other matched workflow — so a repo using
// GitHub's own recommended SAST setup gets accurate ran-per-release/cadence
// results instead of a false-fail from a silently-skipped "workflow."
func TestCollect_CodeQLDefaultSetupDynamicWorkflow_RunHistoryObserved(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "default-setup-repo", "main")
	registerCodeQLDefaultSetupWorkflow(t, mux, "attestward-demo", "default-setup-repo", 42)
	registerOneRelease(t, mux, "attestward-demo", "default-setup-repo", "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerWorkflowRuns(t, mux, "attestward-demo", "default-setup-repo", 42, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	registerDefaultSetup(t, mux, "attestward-demo", "default-setup-repo", "configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"default-setup-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C05.sast.tool-configured"].Status; got != model.StatusVerifiedPass {
		t.Errorf("tool-configured = %q, want verified-pass; reason=%q", got, m["C05.sast.tool-configured"].Reason)
	}
	if got := m["C05.sast.default-setup"].Status; got != model.StatusVerifiedPass {
		t.Errorf("default-setup = %q, want verified-pass", got)
	}
	if got := m["C05.sast.ran-per-release"].Status; got != model.StatusVerifiedPass {
		t.Errorf("ran-per-release = %q, want verified-pass (the dynamic workflow's run history covers the release); reason=%q", got, m["C05.sast.ran-per-release"].Reason)
	}
	if got := m["C05.sast.cadence"].Status; got != model.StatusVerifiedPass {
		t.Errorf("cadence = %q, want verified-pass (the dynamic workflow's run history is observable); reason=%q", got, m["C05.sast.cadence"].Reason)
	}
}

// TestCollect_DefaultSetupConfiguredButDynamicWorkflowNotSurfaced_CadenceHasNothingToReport
// covers the narrow fallback: default-setup reports "configured" via its
// own endpoint, but for whatever reason ListWorkflows doesn't include the
// dynamic entry for it (a scenario this collector must still degrade
// honestly for, not assume it can never happen). tool-configured still
// passes on the default-setup signal alone; without a matched workflow ID
// there is no run history to inspect, so cadence has nothing to report.
func TestCollect_DefaultSetupConfiguredButDynamicWorkflowNotSurfaced_CadenceHasNothingToReport(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "default-setup-repo", "main")
	registerNoWorkflows(t, mux, "attestward-demo", "default-setup-repo")
	registerNoReleases(t, mux, "attestward-demo", "default-setup-repo")
	registerDefaultSetup(t, mux, "attestward-demo", "default-setup-repo", "configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"default-setup-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C05.sast.tool-configured"].Status; got != model.StatusVerifiedPass {
		t.Errorf("tool-configured = %q, want verified-pass (default setup counts as configured)", got)
	}
	if got := m["C05.sast.default-setup"].Status; got != model.StatusVerifiedPass {
		t.Errorf("default-setup = %q, want verified-pass", got)
	}
	if got := m["C05.sast.cadence"].Status; got != model.StatusVerifiedFail {
		t.Errorf("cadence = %q, want verified-fail (no run history observable without a matched workflow)", got)
	}
}

// TestCollect_UnresolvableReleaseTag_CapsRanPerReleaseAtPartial covers a
// repo with two releases matching the tag pattern: one resolves and has a
// clean SAST run, the other's tag ref 404s (e.g. a deleted/rewritten tag).
// Without accounting for the drop, ran-per-release would see only the one
// resolved, fully-covered release and report verified-pass — overstating
// confidence about a release that was never actually evaluated. It must
// cap at partial and surface the drop count in Facts instead.
func TestCollect_UnresolvableReleaseTag_CapsRanPerReleaseAtPartial(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "broken-tag-repo", "main")
	registerCodeQLWorkflow(t, mux, "attestward-demo", "broken-tag-repo")
	mux.HandleFunc("/repos/attestward-demo/broken-tag-repo/releases", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{
			{"tag_name": "v1.0.0", "target_commitish": "main", "published_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
			{"tag_name": "v0.9.0", "target_commitish": "main", "published_at": time.Now().UTC().AddDate(0, 0, -30).Format(time.RFC3339)},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/broken-tag-repo/git/ref/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"ref":    "refs/tags/v1.0.0",
			"object": map[string]any{"type": "commit", "sha": "sha1"},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/broken-tag-repo/git/ref/tags/v0.9.0", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
	registerWorkflowRuns(t, mux, "attestward-demo", "broken-tag-repo", 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	registerDefaultSetup(t, mux, "attestward-demo", "broken-tag-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"broken-tag-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C05.sast.ran-per-release"].Status; got != model.StatusPartial {
		t.Errorf("ran-per-release = %q, want partial (one release tag was unresolvable); reason=%q", got, m["C05.sast.ran-per-release"].Reason)
	}
	if dropped, ok := m["C05.sast.ran-per-release"].Facts["dropped_tags"].(int); !ok || dropped != 1 {
		t.Errorf("Facts[dropped_tags] = %v, want 1", m["C05.sast.ran-per-release"].Facts["dropped_tags"])
	}
}

// TestCollect_ProvenanceSplitsSharedFromDefaultSetup pins the deliberate
// call-ordering design documented on collectRepo: the default-setup call
// runs last specifically so provenance splits into a shared prefix (used
// by tool-configured/ran-per-release/cadence) and a one-call suffix (used
// only by default-setup) via plain slicing. That design was previously
// unverified by any test — this proves the split actually lands where the
// doc comment claims.
func TestCollect_ProvenanceSplitsSharedFromDefaultSetup(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "prov-repo", "main")
	registerCodeQLWorkflow(t, mux, "attestward-demo", "prov-repo")
	registerOneRelease(t, mux, "attestward-demo", "prov-repo", "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerWorkflowRuns(t, mux, "attestward-demo", "prov-repo", 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	registerDefaultSetup(t, mux, "attestward-demo", "prov-repo", "configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"prov-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	const defaultSetupEndpointSuffix = "/code-scanning/default-setup"

	shared := m["C05.sast.tool-configured"].Provenance
	if len(shared) == 0 {
		t.Fatal("tool-configured provenance is empty, want at least the repo/workflow/release calls")
	}
	for _, p := range shared {
		if strings.HasSuffix(p.Endpoint, defaultSetupEndpointSuffix) {
			t.Errorf("shared provenance unexpectedly includes the default-setup call: %+v", p)
		}
	}

	dsProv := m["C05.sast.default-setup"].Provenance
	if len(dsProv) != 1 {
		t.Fatalf("default-setup provenance = %d entries, want exactly 1 (just its own call); got %+v", len(dsProv), dsProv)
	}
	if !strings.HasSuffix(dsProv[0].Endpoint, defaultSetupEndpointSuffix) {
		t.Errorf("default-setup provenance[0].Endpoint = %q, want suffix %q", dsProv[0].Endpoint, defaultSetupEndpointSuffix)
	}

	if got := len(m["C05.sast.ran-per-release"].Provenance); got != len(shared) {
		t.Errorf("ran-per-release provenance length = %d, want %d (same shared slice as tool-configured)", got, len(shared))
	}
	if got := len(m["C05.sast.cadence"].Provenance); got != len(shared) {
		t.Errorf("cadence provenance length = %d, want %d (same shared slice as tool-configured)", got, len(shared))
	}
}

// TestCollect_WorkflowsListing403_ReasonMentionsPermission pins the fix to
// fetchAndMatchWorkflows discarding its *github.Response on error: a 403
// from the workflows-listing call must classify the same way a 403 from
// the initial repo fetch already does ("token lacks permission..."), not
// fall back to a generic "could not query" wrapping the raw go-github
// error string.
func TestCollect_WorkflowsListing403_ReasonMentionsPermission(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "workflows-403-repo", "main")
	mux.HandleFunc("/repos/attestward-demo/workflows-403-repo/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"workflows-403-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	const wantSubstring = "token lacks permission"
	for _, id := range checkIDs {
		r := m[id]
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, r.Status)
		}
		if !strings.Contains(r.Reason, wantSubstring) {
			t.Errorf("%s reason = %q, want it to contain %q", id, r.Reason, wantSubstring)
		}
	}
}

// TestCollect_UnresolvableTagOutsideLookbackWindow_DoesNotCountAsDrop
// covers the case the second review round flagged: an old release (well
// outside the 12-month lookback window) whose tag was later deleted must
// NOT count toward droppedTags — it could never have been evaluated even
// if the tag HAD resolved, so counting it would cap ran-per-release at
// partial permanently, with no way to fix it short of deleting the old
// GitHub release. Only a resolution failure on a release that's still
// actually in scope should count.
func TestCollect_UnresolvableTagOutsideLookbackWindow_DoesNotCountAsDrop(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "old-broken-tag-repo", "main")
	registerCodeQLWorkflow(t, mux, "attestward-demo", "old-broken-tag-repo")
	mux.HandleFunc("/repos/attestward-demo/old-broken-tag-repo/releases", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{
			{"tag_name": "v1.0.0", "target_commitish": "main", "published_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
			// Well outside the 12-month lookback window configured below.
			{"tag_name": "v0.1.0", "target_commitish": "main", "published_at": time.Now().UTC().AddDate(-3, 0, 0).Format(time.RFC3339)},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/old-broken-tag-repo/git/ref/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"ref":    "refs/tags/v1.0.0",
			"object": map[string]any{"type": "commit", "sha": "sha1"},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/old-broken-tag-repo/git/ref/tags/v0.1.0", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
	registerWorkflowRuns(t, mux, "attestward-demo", "old-broken-tag-repo", 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	registerDefaultSetup(t, mux, "attestward-demo", "old-broken-tag-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"old-broken-tag-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C05.sast.ran-per-release"].Status; got != model.StatusVerifiedPass {
		t.Errorf("ran-per-release = %q, want verified-pass (the unresolvable tag is outside the lookback window, not a real drop); reason=%q", got, m["C05.sast.ran-per-release"].Reason)
	}
	if dropped, ok := m["C05.sast.ran-per-release"].Facts["dropped_tags"].(int); !ok || dropped != 0 {
		t.Errorf("Facts[dropped_tags] = %v, want 0", m["C05.sast.ran-per-release"].Facts["dropped_tags"])
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

func TestCollect_DefaultSetupCallFailsOnlyThatCheckNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "flaky-repo", "main")
	registerCodeQLWorkflow(t, mux, "attestward-demo", "flaky-repo")
	registerOneRelease(t, mux, "attestward-demo", "flaky-repo", "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerWorkflowRuns(t, mux, "attestward-demo", "flaky-repo", 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	mux.HandleFunc("/repos/attestward-demo/flaky-repo/code-scanning/default-setup", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"flaky-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C05.sast.default-setup"].Status; got != model.StatusNotCheckable {
		t.Errorf("default-setup = %q, want not-checkable", got)
	}
	for _, id := range []string{"C05.sast.tool-configured", "C05.sast.ran-per-release", "C05.sast.cadence"} {
		if got := m[id].Status; got == model.StatusNotCheckable {
			t.Errorf("%s = %q, want NOT not-checkable (doesn't depend on the failed default-setup call)", id, got)
		}
	}
}

// TestCollect_DefaultSetupCallFailsWithNoOtherEvidence_ToolConfiguredNotCheckable
// covers the edge case TestCollect_DefaultSetupCallFailsOnlyThatCheckNotCheckable
// doesn't reach: that test's "flaky-repo" always has a real CodeQL workflow
// match, so tool-configured's status is already decided by that evidence
// independent of whatever the default-setup call does. Here there is zero
// workflow-based evidence at all, so tool-configured's outcome depends
// entirely on defaultSetupConfigured(ds) — and GetDefaultSetupConfiguration
// returns a nil ds on ANY error, indistinguishable from a genuine
// successful "not configured" response, unless the check itself accounts
// for the failure. Before the fix, this silently asserted verified-fail
// ("CodeQL default setup is not configured") when the truth is "unknown,
// the query failed."
func TestCollect_DefaultSetupCallFailsWithNoOtherEvidence_ToolConfiguredNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "no-evidence-repo", "main")
	registerNoWorkflows(t, mux, "attestward-demo", "no-evidence-repo")
	registerNoReleases(t, mux, "attestward-demo", "no-evidence-repo")
	mux.HandleFunc("/repos/attestward-demo/no-evidence-repo/code-scanning/default-setup", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"no-evidence-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C05.sast.tool-configured"].Status; got != model.StatusNotCheckable {
		t.Errorf("tool-configured = %q, want not-checkable — zero workflow evidence plus a failed default-setup query is unknown, not a confirmed \"not configured\"", got)
	}
}

// TestCollect_DefaultSetupPlanGatedWithNoOtherEvidence_ToolConfiguredStaysFail
// is the fix's negative-control companion: a plan-gated default-setup
// response (404/402 — GHAS/default-setup genuinely unavailable on this
// repo, e.g. no license) is a real, legitimate "not configured" fact, not
// an unknown — the not-checkable branch added for the test above must not
// fire here too.
func TestCollect_DefaultSetupPlanGatedWithNoOtherEvidence_ToolConfiguredStaysFail(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestward-demo", "plan-gated-repo", "main")
	registerNoWorkflows(t, mux, "attestward-demo", "plan-gated-repo")
	registerNoReleases(t, mux, "attestward-demo", "plan-gated-repo")
	mux.HandleFunc("/repos/attestward-demo/plan-gated-repo/code-scanning/default-setup", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"plan-gated-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C05.sast.tool-configured"].Status; got != model.StatusVerifiedFail {
		t.Errorf("tool-configured = %q, want verified-fail — a plan-gated default-setup response is a legitimate \"not configured\" fact, not an unknown", got)
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
	if len(checkTitles) != 4 {
		t.Fatalf("len(checkTitles) = %d, want 4", len(checkTitles))
	}
	for id := range checkTitles {
		if _, ok := collect.Lookup(id); !ok {
			t.Errorf("check %q not found in the collect.CheckMeta registry", id)
		}
	}
}

// checkWantStatuses is a human-reviewed declaration of exactly which
// statuses each check can produce (see orgsecurity's own copy of this
// pattern for the full rationale). All four C05 checks can reach partial
// except default-setup, which is a plain pass/fail/not-checkable check —
// see checks.go's checkDefaultSetup for why it has no partial branch.
var checkWantStatuses = map[string][]model.Status{
	"C05.sast.tool-configured": {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	"C05.sast.ran-per-release": {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	"C05.sast.cadence":         {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	"C05.sast.default-setup":   {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
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

// TestRanPerReleaseRubricScopesResolvedTagsToLookbackWindow locks in that
// the verified-pass/partial rubric text doesn't claim EVERY matching
// release tag resolved to a commit — droppedTags (collectRepo) only
// counts an unresolvable tag as a drop when it's published within the
// lookback window; a pattern-matching tag well outside the window that
// fails to resolve is silently out of scope, not a drop, and the check
// still reaches verified-pass — see
// TestCollect_UnresolvableTagOutsideLookbackWindow_DoesNotCountAsDrop.
// Unscoped wording ("every matching release tag resolved") reads as
// false for that real, tested scenario.
func TestRanPerReleaseRubricScopesResolvedTagsToLookbackWindow(t *testing.T) {
	pass := checkRubrics["C05.sast.ran-per-release"][model.StatusVerifiedPass]
	if !strings.Contains(pass, "in the lookback window resolved") {
		t.Errorf("C05.sast.ran-per-release verified-pass rubric doesn't scope \"resolved to a commit\" to the lookback window: %q", pass)
	}
	partial := checkRubrics["C05.sast.ran-per-release"][model.StatusPartial]
	if !strings.Contains(partial, "in the lookback window couldn't be resolved") {
		t.Errorf("C05.sast.ran-per-release partial rubric doesn't scope \"couldn't be resolved\" to the lookback window: %q", partial)
	}
}

// TestCadenceRemediationCoversLowConfidencePartial locks in that the
// remediation doesn't just address checkCadence's verified-fail path
// (RunCount == 0) — it must also cover the partial path (lowConfidenceOnly,
// where RunCount > 0 but the match is workflow-name-only), whose actual
// fix is raising match confidence (same fix as tool-configured), not
// adjusting triggers/schedule. Advice that only says "the trigger didn't
// fire" is factually wrong for the partial case and can't reach a pass
// there.
func TestCadenceRemediationCoversLowConfidencePartial(t *testing.T) {
	remediation := strings.ToLower(checkRemediations["C05.sast.cadence"])
	if !strings.Contains(remediation, "low-confidence") && !strings.Contains(remediation, "low confidence") {
		t.Errorf("C05.sast.cadence remediation doesn't address the low-confidence partial path (runs observed, but match confidence too weak): %q", checkRemediations["C05.sast.cadence"])
	}
}

// TestCodeScanningRemediationsUseCurrentSettingsPath locks in the current
// GitHub Settings navigation ("Security" sidebar section -> "Advanced
// Security", not the pre-GHAS-unbundling "Code security" label) for both
// checks that send a reader to the CodeQL default-setup page. Verified
// against docs.github.com/en/code-security/code-scanning/enabling-code-scanning/configuring-default-setup-for-code-scanning.
func TestCodeScanningRemediationsUseCurrentSettingsPath(t *testing.T) {
	for _, id := range []string{"C05.sast.tool-configured", "C05.sast.default-setup"} {
		remediation := checkRemediations[id]
		if strings.Contains(remediation, "Code security -> Code scanning") {
			t.Errorf("%s remediation uses the stale pre-GHAS-unbundling \"Code security\" settings path: %q", id, remediation)
		}
		if !strings.Contains(remediation, "Advanced Security") {
			t.Errorf("%s remediation should name the current \"Advanced Security\" settings section: %q", id, remediation)
		}
	}
}
