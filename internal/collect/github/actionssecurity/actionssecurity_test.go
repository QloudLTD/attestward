package actionssecurity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/model"
)

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

func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func newCollectorForServer(t *testing.T, server *httptest.Server) *Collector {
	t.Helper()
	c := New("ghp_test-token")
	c.newClientForTest = func(token string) *ghcollect.Client {
		client := ghcollect.NewClient(token)
		baseURL, err := url.Parse(server.URL + "/")
		if err != nil {
			t.Fatalf("parse test server URL: %v", err)
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

func registerRepo(t *testing.T, mux *http.ServeMux, org, repo, defaultBranch string, private bool) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/"+org+"/"+repo {
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]any{"default_branch": defaultBranch, "private": private})
	})
}

func registerDefaultWorkflowPermissions(t *testing.T, mux *http.ServeMux, org, repo, perm string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/permissions/workflow", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"default_workflow_permissions": perm})
	})
}

func registerWorkflows(t *testing.T, mux *http.ServeMux, org, repo string, paths []string) {
	t.Helper()
	entries := make([]map[string]any, 0, len(paths))
	for i, p := range paths {
		entries = append(entries, map[string]any{"id": i + 1, "path": p, "state": "active"})
	}
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"total_count": len(entries), "workflows": entries})
	})
}

func registerContent(t *testing.T, mux *http.ServeMux, org, repo, path, fixtureFile string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "workflows", fixtureFile))
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixtureFile, err)
	}
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/"+path, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"content": string(raw), "sha": "content-sha"})
	})
}

func TestCollect_UnpinnedThirdPartyAction_PinnedFails(t *testing.T) {
	org, repoName, branch := "acme", "widgets", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repoName, branch, false)
	registerDefaultWorkflowPermissions(t, mux, org, repoName, "read")
	registerWorkflows(t, mux, org, repoName, []string{".github/workflows/build.yml"})
	registerContent(t, mux, org, repoName, ".github/workflows/build.yml", "pinned_thirdparty_unpinned.yaml")

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repoName}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if len(m) != len(checkIDs) {
		t.Fatalf("got %d results, want %d (%v)", len(m), len(checkIDs), checkIDs)
	}
	if got := m[checkPinnedID].Status; got != model.StatusVerifiedFail {
		t.Errorf("pinned = %q, want verified-fail; reason=%q", got, m[checkPinnedID].Reason)
	}
	if got := m[checkTokenPermissionsID].Status; got != model.StatusVerifiedPass {
		t.Errorf("token-permissions = %q, want verified-pass; reason=%q", got, m[checkTokenPermissionsID].Reason)
	}
	if got := m[checkTokenPermissionsID].Facts["repo_default_workflow_permissions"]; got != "read" {
		t.Errorf("repo_default_workflow_permissions = %v, want %q", got, "read")
	}
}

func TestCollect_NoWorkflows_AllChecksNotCheckable(t *testing.T) {
	org, repoName, branch := "acme", "empty-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repoName, branch, true)
	registerDefaultWorkflowPermissions(t, mux, org, repoName, "read")
	registerWorkflows(t, mux, org, repoName, nil)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repoName}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	for _, id := range checkIDs {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable (no workflow files at all); reason=%q", id, got, m[id].Reason)
		}
	}
}

func TestCollect_RepoFetchFailure403_AllChecksNotCheckable(t *testing.T) {
	org, repoName := "acme", "forbidden-repo"
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+org+"/"+repoName, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repoName}})
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

func TestCollect_ReusableWorkflow_SameOrgResolvedExternalOrgUnresolved(t *testing.T) {
	org, repoName, branch := "my-org", "widgets", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repoName, branch, false)
	registerDefaultWorkflowPermissions(t, mux, org, repoName, "read")
	registerWorkflows(t, mux, org, repoName, []string{".github/workflows/build.yml"})
	registerContent(t, mux, org, repoName, ".github/workflows/build.yml", "reusable_caller.yaml")
	// The caller references "my-org/shared-workflows/.github/workflows/build.yml@main" —
	// same org, so it must be resolved via a direct content fetch (not the
	// per-repo workflow-listing endpoint, which reusable-workflow
	// resolution deliberately skips).
	registerContent(t, mux, org, "shared-workflows", ".github/workflows/build.yml", "reusable_callee.yaml")

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repoName}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	// reusable_caller.yaml's own two job-level `uses:` entries are
	// themselves unpinned reusable-workflow references, so pinned would
	// already be verified-fail even if same-org resolution silently did
	// nothing — asserting Status alone doesn't prove resolution actually
	// ran. The proof is that reusable_callee.yaml's own unpinned
	// docker/build-push-action@v6 shows up, labeled with the *resolved*
	// repo ("my-org/shared-workflows:...", not the calling repo) — that
	// finding can only exist if the same-org content fetch happened.
	thirdParty, ok := m[checkPinnedID].Facts["third_party_unpinned"].([]map[string]any)
	if !ok {
		t.Fatalf("third_party_unpinned = %#v, want a slice", m[checkPinnedID].Facts["third_party_unpinned"])
	}
	const resolvedCalleeLabel = "my-org/shared-workflows:.github/workflows/build.yml"
	foundResolvedCalleeFinding := false
	for _, f := range thirdParty {
		if f["file"] == resolvedCalleeLabel && f["slug"] == "docker/build-push-action" {
			foundResolvedCalleeFinding = true
		}
	}
	if !foundResolvedCalleeFinding {
		t.Errorf("third_party_unpinned = %#v, want an entry from %s (proves the same-org reusable workflow's content was actually fetched and analyzed, not just its uses: ref noted)", thirdParty, resolvedCalleeLabel)
	}

	if got := m[checkPinnedID].Status; got != model.StatusVerifiedFail {
		t.Errorf("pinned = %q, want verified-fail; reason=%q", got, m[checkPinnedID].Reason)
	}
	unresolved, ok := m[checkPinnedID].Facts["unresolved_external_workflows"].([]map[string]any)
	if !ok || len(unresolved) != 1 {
		t.Fatalf("unresolved_external_workflows = %#v, want exactly one entry (the some-other-org reference)", m[checkPinnedID].Facts["unresolved_external_workflows"])
	}
	if got := unresolved[0]["ref"]; got != "some-other-org/other-repo/.github/workflows/build.yml@v1" {
		t.Errorf("unresolved ref = %v, want the external reusable-workflow reference", got)
	}
}

func TestCollect_PreCanceledContextProducesNotCheckableNotPanic(t *testing.T) {
	org, repoName := "acme", "canceled-repo"
	mux := http.NewServeMux()
	c := newCollectorForServer(t, newTestServer(t, mux))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, err := c.Collect(ctx, collect.Scope{Org: org, Repos: []string{repoName}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("want not-checkable results for a pre-canceled context, got none")
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", r.CheckID, r.Status)
		}
	}
}

func TestChecksRegistered(t *testing.T) {
	for _, id := range checkIDs {
		meta, ok := collect.Lookup(id)
		if !ok {
			t.Errorf("check %s not registered", id)
			continue
		}
		if meta.Collector != collectorID {
			t.Errorf("%s Collector = %q, want %q", id, meta.Collector, collectorID)
		}
		if meta.TokenScope == "" {
			t.Errorf("%s TokenScope is empty", id)
		}
	}
}
