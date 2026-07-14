package sasthistory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/model"
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
	registerRepo(t, mux, "attestor-demo", "good-repo", "main")
	registerCodeQLWorkflow(t, mux, "attestor-demo", "good-repo")
	registerOneRelease(t, mux, "attestor-demo", "good-repo", "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerWorkflowRuns(t, mux, "attestor-demo", "good-repo", 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	registerDefaultSetup(t, mux, "attestor-demo", "good-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"good-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
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
	registerRepo(t, mux, "attestor-demo", "bad-repo", "main")
	registerNoWorkflows(t, mux, "attestor-demo", "bad-repo")
	registerOneRelease(t, mux, "attestor-demo", "bad-repo", "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerDefaultSetup(t, mux, "attestor-demo", "bad-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"bad-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
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

func TestCollect_LowConfidenceOnlyMatch_CapsAtPartial(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestor-demo", "iffy-repo", "main")
	mux.HandleFunc("/repos/attestor-demo/iffy-repo/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
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
	mux.HandleFunc("/repos/attestor-demo/iffy-repo/contents/.github/workflows/codeql.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"content": "name: CodeQL\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"})
	})
	registerNoReleases(t, mux, "attestor-demo", "iffy-repo")
	registerWorkflowRuns(t, mux, "attestor-demo", "iffy-repo", 1, []map[string]any{})
	registerDefaultSetup(t, mux, "attestor-demo", "iffy-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"iffy-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
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
	registerRepo(t, mux, "attestor-demo", "iffy-runs-repo", "main")
	mux.HandleFunc("/repos/attestor-demo/iffy-runs-repo/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"workflows": []map[string]any{
				{"id": 1, "name": "CodeQL", "path": ".github/workflows/codeql.yml", "state": "active"},
			},
		})
	})
	// Same low-confidence-only content as TestCollect_LowConfidenceOnlyMatch_CapsAtPartial.
	mux.HandleFunc("/repos/attestor-demo/iffy-runs-repo/contents/.github/workflows/codeql.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"content": "name: CodeQL\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"})
	})
	registerNoReleases(t, mux, "attestor-demo", "iffy-runs-repo")
	registerWorkflowRuns(t, mux, "attestor-demo", "iffy-runs-repo", 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	registerDefaultSetup(t, mux, "attestor-demo", "iffy-runs-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"iffy-runs-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
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
	registerRepo(t, mux, "attestor-demo", "failing-repo", "main")
	registerCodeQLWorkflow(t, mux, "attestor-demo", "failing-repo")
	registerOneRelease(t, mux, "attestor-demo", "failing-repo", "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerWorkflowRuns(t, mux, "attestor-demo", "failing-repo", 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "failure", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	registerDefaultSetup(t, mux, "attestor-demo", "failing-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"failing-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
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
	registerRepo(t, mux, "attestor-demo", "default-setup-repo", "main")
	registerCodeQLDefaultSetupWorkflow(t, mux, "attestor-demo", "default-setup-repo", 42)
	registerOneRelease(t, mux, "attestor-demo", "default-setup-repo", "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerWorkflowRuns(t, mux, "attestor-demo", "default-setup-repo", 42, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	registerDefaultSetup(t, mux, "attestor-demo", "default-setup-repo", "configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"default-setup-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
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
	registerRepo(t, mux, "attestor-demo", "default-setup-repo", "main")
	registerNoWorkflows(t, mux, "attestor-demo", "default-setup-repo")
	registerNoReleases(t, mux, "attestor-demo", "default-setup-repo")
	registerDefaultSetup(t, mux, "attestor-demo", "default-setup-repo", "configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"default-setup-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
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
	registerRepo(t, mux, "attestor-demo", "broken-tag-repo", "main")
	registerCodeQLWorkflow(t, mux, "attestor-demo", "broken-tag-repo")
	mux.HandleFunc("/repos/attestor-demo/broken-tag-repo/releases", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{
			{"tag_name": "v1.0.0", "target_commitish": "main", "published_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
			{"tag_name": "v0.9.0", "target_commitish": "main", "published_at": time.Now().UTC().AddDate(0, 0, -30).Format(time.RFC3339)},
		})
	})
	mux.HandleFunc("/repos/attestor-demo/broken-tag-repo/git/ref/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"ref":    "refs/tags/v1.0.0",
			"object": map[string]any{"type": "commit", "sha": "sha1"},
		})
	})
	mux.HandleFunc("/repos/attestor-demo/broken-tag-repo/git/ref/tags/v0.9.0", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
	registerWorkflowRuns(t, mux, "attestor-demo", "broken-tag-repo", 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	registerDefaultSetup(t, mux, "attestor-demo", "broken-tag-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"broken-tag-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
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
	registerRepo(t, mux, "attestor-demo", "prov-repo", "main")
	registerCodeQLWorkflow(t, mux, "attestor-demo", "prov-repo")
	registerOneRelease(t, mux, "attestor-demo", "prov-repo", "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerWorkflowRuns(t, mux, "attestor-demo", "prov-repo", 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	registerDefaultSetup(t, mux, "attestor-demo", "prov-repo", "configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"prov-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
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
	registerRepo(t, mux, "attestor-demo", "workflows-403-repo", "main")
	mux.HandleFunc("/repos/attestor-demo/workflows-403-repo/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"workflows-403-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
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
	registerRepo(t, mux, "attestor-demo", "old-broken-tag-repo", "main")
	registerCodeQLWorkflow(t, mux, "attestor-demo", "old-broken-tag-repo")
	mux.HandleFunc("/repos/attestor-demo/old-broken-tag-repo/releases", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{
			{"tag_name": "v1.0.0", "target_commitish": "main", "published_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
			// Well outside the 12-month lookback window configured below.
			{"tag_name": "v0.1.0", "target_commitish": "main", "published_at": time.Now().UTC().AddDate(-3, 0, 0).Format(time.RFC3339)},
		})
	})
	mux.HandleFunc("/repos/attestor-demo/old-broken-tag-repo/git/ref/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"ref":    "refs/tags/v1.0.0",
			"object": map[string]any{"type": "commit", "sha": "sha1"},
		})
	})
	mux.HandleFunc("/repos/attestor-demo/old-broken-tag-repo/git/ref/tags/v0.1.0", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
	registerWorkflowRuns(t, mux, "attestor-demo", "old-broken-tag-repo", 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	registerDefaultSetup(t, mux, "attestor-demo", "old-broken-tag-repo", "not-configured")

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"old-broken-tag-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
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

func TestCollect_DefaultSetupCallFailsOnlyThatCheckNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	registerRepo(t, mux, "attestor-demo", "flaky-repo", "main")
	registerCodeQLWorkflow(t, mux, "attestor-demo", "flaky-repo")
	registerOneRelease(t, mux, "attestor-demo", "flaky-repo", "v1.0.0", "sha1", time.Now().UTC().AddDate(0, 0, -1))
	registerWorkflowRuns(t, mux, "attestor-demo", "flaky-repo", 1, []map[string]any{
		{"head_sha": "sha1", "head_branch": "main", "conclusion": "success", "created_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)},
	})
	mux.HandleFunc("/repos/attestor-demo/flaky-repo/code-scanning/default-setup", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"flaky-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
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
	if len(checkTitles) != 4 {
		t.Fatalf("len(checkTitles) = %d, want 4", len(checkTitles))
	}
	for id := range checkTitles {
		if _, ok := collect.Lookup(id); !ok {
			t.Errorf("check %q not found in the collect.CheckMeta registry", id)
		}
	}
}
