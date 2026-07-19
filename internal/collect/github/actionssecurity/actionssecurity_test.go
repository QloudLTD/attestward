package actionssecurity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sioakim/attestward/internal/collect"
	ghcollect "github.com/sioakim/attestward/internal/collect/github"
	"github.com/sioakim/attestward/internal/model"
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

// TestCollect_AllWorkflowsUnreadable_NotCheckableFactsIncludeSkipped
// covers the len(units)==0-with-skipped case for the four checks that
// share noWorkflowsReason: GitHub listed a workflow file, but it
// couldn't be fetched (403) — the not-checkable reason correctly names
// this ("every one failed to fetch or parse (see skipped_workflows)"),
// and Facts must actually carry that skipped_workflows entry for the
// claim to be honest — a rubric/reason pointing readers at a Facts key
// that doesn't exist would be its own inaccuracy.
func TestCollect_AllWorkflowsUnreadable_NotCheckableFactsIncludeSkipped(t *testing.T) {
	org, repoName, branch := "acme", "all-unreadable-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repoName, branch, false)
	registerDefaultWorkflowPermissions(t, mux, org, repoName, "read")
	registerWorkflows(t, mux, org, repoName, []string{".github/workflows/build.yml"})
	mux.HandleFunc("/repos/"+org+"/"+repoName+"/contents/.github/workflows/build.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repoName}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	for _, id := range []string{checkPinnedID, checkTokenPermissionsID, checkPRTargetID, checkSelfHostedID} {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable; reason=%q", id, got, m[id].Reason)
		}
		if !strings.Contains(m[id].Reason, "skipped_workflows") {
			t.Errorf("%s reason doesn't mention skipped_workflows: %q", id, m[id].Reason)
		}
		skipped, ok := m[id].Facts["skipped_workflows"].([]map[string]any)
		if !ok || len(skipped) != 1 || skipped[0]["path"] != ".github/workflows/build.yml" {
			t.Errorf("%s Facts[skipped_workflows] = %v, want exactly one entry for build.yml — the reason text points readers here, so it must actually be populated", id, m[id].Facts["skipped_workflows"])
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

// TestCollect_OneWorkflowUnreadable_DoesNotFalselyPassOnIncompleteEvidence
// pins the fix for issue #96: fetchOneWorkflow (workflows.go) used to
// fold ANY GetContents failure — a genuine 403/500, not just a benign
// 404-at-ref — into the same silent skip as a workflow that legitimately
// doesn't exist at this ref. Three of five checks (pinned, pull-request-
// target, self-hosted) default to verified-pass when no violation is
// found among the workflows that WERE fetched — so the one workflow
// that couldn't be read (here, the one containing the dangerous
// pull_request_target+checkout-of-PR-head pattern) was silently
// invisible, and the check confidently asserted "no workflow triggers
// on pull_request_target at all" when the truth is "one workflow's
// content couldn't be confirmed either way."
func TestCollect_OneWorkflowUnreadable_DoesNotFalselyPassOnIncompleteEvidence(t *testing.T) {
	org, repoName, branch := "acme", "partial-read-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repoName, branch, false)
	registerDefaultWorkflowPermissions(t, mux, org, repoName, "read")
	registerWorkflows(t, mux, org, repoName, []string{
		".github/workflows/build.yml",
		".github/workflows/label.yml",
	})
	registerContent(t, mux, org, repoName, ".github/workflows/build.yml", "pinned_thirdparty_sha.yaml")
	mux.HandleFunc("/repos/"+org+"/"+repoName+"/contents/.github/workflows/label.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repoName}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	// pinned, token-permissions, pull-request-target, and self-hosted all
	// default to verified-pass when no violation is found among the
	// workflows successfully read — build.yml (the one readable
	// workflow) has an explicit permissions: block, so token-permissions
	// has no real missing-permissions finding here either, and is
	// affected by the same incomplete-evidence downgrade as the other
	// three. oidc-vs-secrets is the only one genuinely unaffected: it
	// has no cloud-login evidence anywhere among what was read, so it's
	// not-checkable regardless of the skipped workflow.
	for _, id := range []string{checkPinnedID, checkTokenPermissionsID, checkPRTargetID, checkSelfHostedID} {
		if got := m[id].Status; got != model.StatusPartial {
			t.Errorf("%s = %q, want partial (incomplete evidence — one workflow's content couldn't be fetched); reason=%q", id, got, m[id].Reason)
		}
		skipped, ok := m[id].Facts["skipped_workflows"].([]map[string]any)
		if !ok || len(skipped) != 1 || skipped[0]["path"] != ".github/workflows/label.yml" {
			t.Errorf("%s Facts[skipped_workflows] = %v, want exactly one entry for the unreadable label.yml", id, m[id].Facts["skipped_workflows"])
		}
	}
}

// TestCollect_SelfHostedOnPrivateRepo_NotDowngradedByUnrelatedSkip pins
// that checkSelfHosted's "found on a private repo, still passes" branch
// (checks.go) is NOT capped at partial just because some other,
// unrelated workflow was unreadable — that verdict already rests on a
// real, confirmed finding, and private-ness caps it at pass regardless
// of how many self-hosted usages exist, found or not. Only the
// zero-findings pass needs the incomplete-evidence caveat.
func TestCollect_SelfHostedOnPrivateRepo_NotDowngradedByUnrelatedSkip(t *testing.T) {
	org, repoName, branch := "acme", "private-selfhosted-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repoName, branch, true)
	registerDefaultWorkflowPermissions(t, mux, org, repoName, "read")
	registerWorkflows(t, mux, org, repoName, []string{
		".github/workflows/deploy.yml",
		".github/workflows/unreadable.yml",
	})
	registerContent(t, mux, org, repoName, ".github/workflows/deploy.yml", "selfhosted_bare_string.yaml")
	mux.HandleFunc("/repos/"+org+"/"+repoName+"/contents/.github/workflows/unreadable.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repoName}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[checkSelfHostedID].Status; got != model.StatusVerifiedPass {
		t.Errorf("%s = %q, want verified-pass — a confirmed self-hosted finding on a private repo isn't weakened by an unrelated unreadable workflow; reason=%q", checkSelfHostedID, got, m[checkSelfHostedID].Reason)
	}
}

// TestCollect_SameOrgReusableWorkflowFetchFails_DoesNotFalselyPass pins
// the same incomplete-evidence fix for resolveReusableWorkflows'
// (workflows.go) own fetch path — distinct code from fetchWorkflows'
// direct-listing path, and needs its own coverage: a same-org reusable
// workflow reference that fails to fetch (403) must also prevent a
// confident verified-pass, not just vanish.
func TestCollect_SameOrgReusableWorkflowFetchFails_DoesNotFalselyPass(t *testing.T) {
	org, repoName, branch := "my-org", "caller-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repoName, branch, false)
	registerDefaultWorkflowPermissions(t, mux, org, repoName, "read")
	registerWorkflows(t, mux, org, repoName, []string{".github/workflows/caller.yml"})
	// caller.yml's own job-level uses: is pinned to a full SHA, so it
	// contributes zero unpinned findings on its own — pinned would
	// otherwise reach verified-pass purely from what it CAN see; the
	// unreadable same-org callee must be what prevents that.
	const callerYAML = "name: build\non: [push]\npermissions:\n  contents: read\njobs:\n  call-internal:\n    uses: my-org/shared-workflows/.github/workflows/build.yml@1111111111111111111111111111111111111111\n"
	mux.HandleFunc("/repos/"+org+"/"+repoName+"/contents/.github/workflows/caller.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"content": callerYAML, "sha": "content-sha"})
	})
	mux.HandleFunc("/repos/"+org+"/shared-workflows/contents/.github/workflows/build.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repoName}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[checkPinnedID].Status; got != model.StatusPartial {
		t.Errorf("%s = %q, want partial (the same-org reusable workflow reference couldn't be fetched); reason=%q", checkPinnedID, got, m[checkPinnedID].Reason)
	}
}

// TestCollect_SameOrgReusableWorkflowReturns404_DoesNotFalselyPass covers
// the 404 variant of the previous test — a materially different, and
// arguably more realistic, cause: GitHub returns 404 (not 403) for a
// private repo the token can't see, specifically to avoid leaking
// whether it exists. Unlike fetchWorkflows' direct-listing path (where
// ListWorkflows already proved read access to the SAME repo, so a
// content-fetch 404 there really is a benign "not at this ref"),
// resolveReusableWorkflows has no such prior proof for the callee repo
// a reusable-workflow reference points at — so a 404 here must NOT be
// silently trusted as a genuine absence.
func TestCollect_SameOrgReusableWorkflowReturns404_DoesNotFalselyPass(t *testing.T) {
	org, repoName, branch := "my-org", "caller-404-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repoName, branch, false)
	registerDefaultWorkflowPermissions(t, mux, org, repoName, "read")
	registerWorkflows(t, mux, org, repoName, []string{".github/workflows/caller.yml"})
	const callerYAML = "name: build\non: [push]\npermissions:\n  contents: read\njobs:\n  call-internal:\n    uses: my-org/shared-workflows/.github/workflows/build.yml@2222222222222222222222222222222222222222\n"
	mux.HandleFunc("/repos/"+org+"/"+repoName+"/contents/.github/workflows/caller.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"content": callerYAML, "sha": "content-sha"})
	})
	mux.HandleFunc("/repos/"+org+"/shared-workflows/contents/.github/workflows/build.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repoName}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[checkPinnedID].Status; got != model.StatusPartial {
		t.Errorf("%s = %q, want partial (a 404 on the callee repo can't be trusted as a benign absence — it's GitHub's identical response for \"no access\"); reason=%q", checkPinnedID, got, m[checkPinnedID].Reason)
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

// checkWantStatuses is a human-reviewed declaration of exactly which
// statuses each check can produce (see orgsecurity's own copy of this
// pattern for the full rationale). checkSelfHostedID is the odd one
// out: unlike every other check in this package, it has no verified-fail
// outcome at all — self-hosted-runner usage on a public repo is only
// ever capped at partial, by design (see checkSelfHosted's own doc
// comment in checks.go).
var checkWantStatuses = map[string][]model.Status{
	checkPinnedID:           {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	checkTokenPermissionsID: {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	checkPRTargetID:         {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	checkOIDCID:             {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	checkSelfHostedID:       {model.StatusVerifiedPass, model.StatusPartial, model.StatusNotCheckable},
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

// TestSelfHostedRemediationDoesNotOverclaimNonRunsOnFixes locks in that
// the remediation doesn't present "restrict fork-PR approval" or "don't
// trigger on pull_request/pull_request_target from forks" as equivalent
// alternatives to moving off self-hosted — checkSelfHosted's status comes
// purely from runsOnSelfHosted(job.RunsOn) and the repo's private flag
// (checks.go's checkSelfHosted); neither of those other two settings
// changes what RunsOn contains, so they leave the check at partial
// forever on a public repo. Only actually removing self-hosted usage (or
// making the repo private) reaches a pass.
func TestSelfHostedRemediationDoesNotOverclaimNonRunsOnFixes(t *testing.T) {
	remediation := checkRemediations[checkSelfHostedID]
	if !strings.Contains(strings.ToLower(remediation), "only") {
		t.Errorf("C08.actions.self-hosted remediation doesn't make clear that only moving off self-hosted actually clears this check (the other mitigations are real but don't change RunsOn): %q", remediation)
	}
}

// TestPullRequestTargetRemediationClarifiesRefRemovalOnlyReachesPartial
// locks in that the remediation doesn't present "remove the checkout
// step's PR-head ref" as an equal alternative to switching triggers —
// checkPullRequestTarget only reaches verified-pass when NO workflow
// triggers on pull_request_target at all; removing just the head-ref
// checkout demotes "dangerous" to "bare" (still partial, "risky by
// design"), not to pass.
func TestPullRequestTargetRemediationClarifiesRefRemovalOnlyReachesPartial(t *testing.T) {
	remediation := checkRemediations[checkPRTargetID]
	if !strings.Contains(remediation, "partial") {
		t.Errorf("C08.actions.pull-request-target remediation doesn't clarify that removing only the PR-head checkout still caps the result at partial, not a full pass: %q", remediation)
	}
}

// TestOIDCRemediationCoversAmbiguousPartialMode locks in that the
// remediation doesn't only address the static-credential verified-fail
// mode — classifyCloudLoginStep's "ambiguous" partial mode fires when
// NEITHER an OIDC nor a static-credential parameter was set at all, so
// text that opens "replace the long-lived static credential" and closes
// "delete the corresponding long-lived secret" misdescribes that case
// (there's no existing secret to delete).
func TestOIDCRemediationCoversAmbiguousPartialMode(t *testing.T) {
	remediation := strings.ToLower(checkRemediations[checkOIDCID])
	if !strings.Contains(remediation, "ambiguous") && !strings.Contains(remediation, "neither") {
		t.Errorf("C08.actions.oidc-vs-secrets remediation doesn't address the \"ambiguous\" partial mode (no credential parameter recognized at all, so there's nothing to \"replace\" or \"delete\"): %q", checkRemediations[checkOIDCID])
	}
}

// TestNotCheckableRubricsDoNotOverclaimAbsence locks in that the four
// shared "zero readable workflows" not-checkable rubrics don't assert a
// confirmed "files exist"/"found" claim — fetchWorkflows (workflows.go)
// silently skips a listed workflow whose content fetch or parse fails,
// so zero resulting units doesn't distinguish "genuinely zero workflow
// files" from "GitHub listed one or more, but every one failed to
// read." Claiming files don't "exist" would be stronger than this
// collector can actually confirm. See issue #96 for the deeper fix
// (tracking and surfacing which/why a listed file was skipped, and
// capping affected checks at partial rather than a confident pass).
func TestNotCheckableRubricsDoNotOverclaimAbsence(t *testing.T) {
	for _, id := range []string{checkPinnedID, checkTokenPermissionsID, checkPRTargetID, checkSelfHostedID} {
		rubric := checkRubrics[id][model.StatusNotCheckable]
		if strings.Contains(rubric, "files exist") || strings.Contains(rubric, "files found") {
			t.Errorf("%s not-checkable rubric overclaims confirmed absence (\"exist\"/\"found\") when a listed-but-unreadable workflow reaches this same status: %q", id, rubric)
		}
	}
	oidcRubric := checkRubrics[checkOIDCID][model.StatusNotCheckable]
	if strings.Contains(oidcRubric, "no workflow contains") {
		t.Errorf("%s not-checkable rubric overclaims confirmed absence across \"any workflow\" when a listed-but-unreadable workflow reaches this same status: %q", checkOIDCID, oidcRubric)
	}
}

// TestOIDCPartialRubricDoesNotClaimNeitherParameterSet locks in a
// distinct accuracy gap from the ambiguous ("partial") rubric text:
// azure/login's OIDC classification requires BOTH client-id AND
// tenant-id (classifyCloudLoginStep in checks.go) — a step setting only
// one of the two still classifies "ambiguous"/partial, even though it
// DID set a recognized OIDC parameter. Wording that says the step sets
// "neither" an OIDC nor a static-credential parameter is literally false
// for that reachable case.
func TestOIDCPartialRubricDoesNotClaimNeitherParameterSet(t *testing.T) {
	rubric := checkRubrics[checkOIDCID][model.StatusPartial]
	if strings.Contains(rubric, "neither a recognized") {
		t.Errorf("%s partial rubric claims neither parameter is set, but azure/login's ambiguous case can have one (client-id or tenant-id alone) genuinely set: %q", checkOIDCID, rubric)
	}
}

// TestPinnedRemediationDoesNotClaimDependabotDoesInitialPinning locks in
// that the remediation doesn't claim Dependabot can perform the initial
// tag-to-SHA pinning conversion — Dependabot's action-pinning support only
// keeps an ALREADY-SHA-pinned reference's trailing version comment up to
// date; converting a mutable tag to a SHA in the first place is a
// long-standing unimplemented Dependabot feature request
// (dependabot/dependabot-core#7913), so pointing a reader at Dependabot
// for the initial fix is unfollowable advice.
func TestPinnedRemediationDoesNotClaimDependabotDoesInitialPinning(t *testing.T) {
	remediation := checkRemediations[checkPinnedID]
	if strings.Contains(remediation, "Dependabot") && strings.Contains(remediation, "can automate this") {
		t.Errorf("C08.actions.pinned remediation implies Dependabot can perform the initial tag-to-SHA pinning conversion, which it doesn't support: %q", remediation)
	}
}
