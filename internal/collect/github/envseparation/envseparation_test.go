package envseparation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

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
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode fixture response: %v", err)
	}
}

func newCollectorForServer(t *testing.T, server *httptest.Server) *Collector {
	t.Helper()
	c := New("ghp_test-token", ghcollect.ClientConfig{})
	c.newClientForTest = func(token string) *ghcollect.Client {
		client := ghcollect.NewClient(token, ghcollect.ClientConfig{})
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

// newGHESCollectorForServer mirrors newCollectorForServer, but resolves
// each per-repo client through ghcollect.ResolveHostConfig the way a real
// --github-url scan would (issue #13's GHES epic) — so the mux must route
// requests under the "/api/v3" prefix go-github's request builder adds for
// a GHES base URL.
func newGHESCollectorForServer(t *testing.T, server *httptest.Server) *Collector {
	t.Helper()
	cfg, err := ghcollect.ResolveHostConfig(server.URL, "")
	if err != nil {
		t.Fatalf("ResolveHostConfig: %v", err)
	}
	c := New("ghp_test-token", cfg)
	c.newClientForTest = func(token string) *ghcollect.Client {
		return ghcollect.NewClient(token, cfg)
	}
	return c
}

// TestCollect_GHESHost_ProdEnvFullyProtectedAllPass mirrors
// TestCollect_ProdEnvFullyProtectedAllPass against a GHES-shaped base URL
// (issue #13's GHES epic) — this collector's own endpoint
// (GET /repos/{owner}/{repo}/environments) was audited as
// ghcollect.GHESNoteSupported (see envseparation.go's init()): a
// long-standing GHES feature, not GitHub Advanced Security gated. Alongside
// (not replacing) the github.com scenario, so both drift together.
func TestCollect_GHESHost_ProdEnvFullyProtectedAllPass(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/attestward-demo/good-repo/environments", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"environments": []map[string]any{
				{
					"name": "production",
					"protection_rules": []map[string]any{
						{"type": "required_reviewers", "reviewers": []map[string]any{{"type": "Team", "id": 1}}},
						{"type": "wait_timer", "wait_timer": 30},
					},
					"deployment_branch_policy": map[string]any{"protected_branches": true, "custom_branch_policies": false},
				},
			},
		})
	})

	c := newGHESCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"good-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want 4", len(results))
	}
	for _, r := range results {
		if r.Status != model.StatusVerifiedPass {
			t.Errorf("%s status = %q, want verified-pass; reason=%q", r.CheckID, r.Status, r.Reason)
		}
		for _, p := range r.Provenance {
			if !strings.HasPrefix(p.Endpoint, "/api/v3") {
				t.Errorf("%s provenance Endpoint = %q, want a /api/v3 prefix (GHES routing)", r.CheckID, p.Endpoint)
			}
		}
	}
}

func TestCollect_NoEnvironmentsAllNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/lib-repo/environments", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"total_count": 0, "environments": []any{}})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"lib-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want 4", len(results))
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable (no deployments)", r.CheckID, r.Status)
		}
		if !strings.Contains(r.Reason, "no environments configured") {
			t.Errorf("%s Reason = %q, want it to mention no environments configured", r.CheckID, r.Reason)
		}
	}
}

func TestCollect_EnvsExistNoneProdLikeAllPartial(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/staging-only/environments", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 2,
			"environments": []map[string]any{
				{"name": "staging"},
				{"name": "dev"},
			},
		})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"staging-only"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want 4", len(results))
	}
	for _, r := range results {
		if r.Status != model.StatusPartial {
			t.Errorf("%s status = %q, want partial (envs exist, none production-like)", r.CheckID, r.Status)
		}
		names, ok := r.Facts["all_environment_names"].([]string)
		if !ok || len(names) != 2 {
			t.Errorf("%s Facts[all_environment_names] = %v, want [staging dev]", r.CheckID, r.Facts["all_environment_names"])
		}
	}
}

func TestCollect_ProdEnvFullyProtectedAllPass(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/good-repo/environments", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"environments": []map[string]any{
				{
					"name": "production",
					"protection_rules": []map[string]any{
						{"type": "required_reviewers", "reviewers": []map[string]any{{"type": "Team", "id": 1}}},
						{"type": "wait_timer", "wait_timer": 30},
					},
					"deployment_branch_policy": map[string]any{"protected_branches": true, "custom_branch_policies": false},
				},
			},
		})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"good-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want 4", len(results))
	}
	for _, r := range results {
		if r.Status != model.StatusVerifiedPass {
			t.Errorf("%s status = %q, want verified-pass; reason=%q", r.CheckID, r.Status, r.Reason)
		}
		if len(r.Provenance) == 0 {
			t.Errorf("%s has no provenance", r.CheckID)
		}
	}
}

func TestCollect_ProdEnvNoProtectionRelevantChecksFail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/bad-repo/environments", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"environments": []map[string]any{
				{"name": "Production"},
			},
		})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"bad-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := map[string]model.CheckResult{}
	for _, r := range results {
		byID[r.CheckID] = r
	}
	if got := byID["C03.env.exists"].Status; got != model.StatusVerifiedPass {
		t.Errorf("exists status = %q, want verified-pass (a production-like env exists, case-insensitive match)", got)
	}
	for _, id := range []string{"C03.env.protection-rules", "C03.env.required-reviewers", "C03.env.branch-policy"} {
		if got := byID[id].Status; got != model.StatusVerifiedFail {
			t.Errorf("%s status = %q, want verified-fail (env has no protection at all)", id, got)
		}
	}
}

// TestCollect_MultipleProdEnvsEveryOneMustPass proves the check requires
// EVERY production-like environment to satisfy a criterion, not just one —
// a second, unprotected prod-like env can't be hidden behind a
// well-protected first one.
func TestCollect_MultipleProdEnvsEveryOneMustPass(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/multi-prod/environments", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 2,
			"environments": []map[string]any{
				{
					"name": "production",
					"protection_rules": []map[string]any{
						{"type": "required_reviewers", "reviewers": []map[string]any{{"type": "Team", "id": 1}}},
					},
					"deployment_branch_policy": map[string]any{"protected_branches": true},
				},
				{"name": "production-eu"},
			},
		})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"multi-prod"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := map[string]model.CheckResult{}
	for _, r := range results {
		byID[r.CheckID] = r
	}
	pr := byID["C03.env.protection-rules"]
	if pr.Status != model.StatusVerifiedFail {
		t.Errorf("protection-rules status = %q, want verified-fail (production-eu has no rules)", pr.Status)
	}
	without, ok := pr.Facts["environments_without_protection"].([]string)
	if !ok || len(without) != 1 || without[0] != "production-eu" {
		t.Errorf("environments_without_protection = %v, want [production-eu]", pr.Facts["environments_without_protection"])
	}

	// production-eu also lacks reviewers and a branch policy — the loop
	// that checks every production-like environment (not just the first)
	// must catch these too, not only protection-rules.
	rr := byID["C03.env.required-reviewers"]
	if rr.Status != model.StatusVerifiedFail {
		t.Errorf("required-reviewers status = %q, want verified-fail (production-eu has no required reviewers)", rr.Status)
	}
	if got, ok := rr.Facts["environments_without_required_reviewers"].([]string); !ok || len(got) != 1 || got[0] != "production-eu" {
		t.Errorf("environments_without_required_reviewers = %v, want [production-eu]", rr.Facts["environments_without_required_reviewers"])
	}

	bp := byID["C03.env.branch-policy"]
	if bp.Status != model.StatusVerifiedFail {
		t.Errorf("branch-policy status = %q, want verified-fail (production-eu has no deployment branch policy)", bp.Status)
	}
	if got, ok := bp.Facts["environments_allowing_any_branch"].([]string); !ok || len(got) != 1 || got[0] != "production-eu" {
		t.Errorf("environments_allowing_any_branch = %v, want [production-eu]", bp.Facts["environments_allowing_any_branch"])
	}
}

// TestCollect_PaginatesAcrossMultiplePages is a regression test for a real
// pre-merge bug: ListEnvironments was called with nil options, so only the
// first page (GitHub default: 30 per page) was ever fetched. A repo with an
// unprotected production-like environment past page 1 would silently pass
// every check — exactly the false verified-pass the all-must-pass design
// exists to prevent, just via a different mechanism (missing data instead
// of a short-circuiting loop). Page 1 holds a fully protected "production";
// page 2 holds an unprotected "production-eu" — every check must still see
// both.
func TestCollect_PaginatesAcrossMultiplePages(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/paginated-repo/environments", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			writeJSON(t, w, http.StatusOK, map[string]any{
				"total_count": 2,
				"environments": []map[string]any{
					{"name": "production-eu"},
				},
			})
			return
		}
		w.Header().Set("Link", `<https://api.github.com/repos/attestward-demo/paginated-repo/environments?page=2>; rel="next"`)
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 2,
			"environments": []map[string]any{
				{
					"name": "production",
					"protection_rules": []map[string]any{
						{"type": "required_reviewers", "reviewers": []map[string]any{{"type": "Team", "id": 1}}},
					},
					"deployment_branch_policy": map[string]any{"protected_branches": true},
				},
			},
		})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"paginated-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := map[string]model.CheckResult{}
	for _, r := range results {
		byID[r.CheckID] = r
	}
	if got := byID["C03.env.protection-rules"].Status; got != model.StatusVerifiedFail {
		t.Errorf("protection-rules status = %q, want verified-fail — production-eu (page 2) has no protection rules and must not be silently dropped", got)
	}
	names, ok := byID["C03.env.exists"].Facts["production_like_environments"].([]string)
	if !ok || len(names) != 2 {
		t.Errorf("production_like_environments = %v, want both production and production-eu across both pages", names)
	}
}

func TestCollect_PermissionGated403AllNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/secret-repo/environments", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"secret-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", r.CheckID, r.Status)
		}
		if len(r.Provenance) == 0 {
			t.Errorf("%s has no provenance", r.CheckID)
		}
		if !strings.Contains(r.Reason, "permission") {
			t.Errorf("%s Reason = %q, want it to mention permission (distinguishing this from the plan-gated path)", r.CheckID, r.Reason)
		}
	}
}

func TestCollect_PlanGated404AllNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/free-plan-repo/environments", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"free-plan-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable (never verified-fail for a plan-gated response)", r.CheckID, r.Status)
		}
		if !strings.Contains(r.Reason, "plan-gated") {
			t.Errorf("%s Reason = %q, want it to mention plan-gated (distinguishing this from the permission-denied path)", r.CheckID, r.Reason)
		}
	}
}

func TestCollect_MultiRepoScanProducesFourResultsEach(t *testing.T) {
	mux := http.NewServeMux()
	for _, repo := range []string{"repo-a", "repo-b"} {
		mux.HandleFunc("/repos/attestward-demo/"+repo+"/environments", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, map[string]any{"total_count": 0, "environments": []any{}})
		})
	}

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"repo-a", "repo-b"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 8 {
		t.Fatalf("len(results) = %d, want 8 (4 checks x 2 repos)", len(results))
	}
	byRepo := map[string]int{}
	for _, r := range results {
		byRepo[r.Scope.Repo]++
	}
	if byRepo["repo-a"] != 4 || byRepo["repo-b"] != 4 {
		t.Errorf("byRepo = %v, want 4 each", byRepo)
	}
}

func TestCollect_PreCanceledContextProducesNotCheckableNotPanic(t *testing.T) {
	mux := http.NewServeMux()
	c := newCollectorForServer(t, newTestServer(t, mux))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := c.Collect(ctx, collect.Scope{Org: "attestward-demo", Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want 4", len(results))
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", r.CheckID, r.Status)
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
// pattern for the full rationale). C03.env.exists is the odd one out here:
// checkExists (checks.go) is only ever called once collectRepo has already
// confirmed len(prodEnvs) > 0, so it structurally can never produce
// verified-fail — its only three possible outcomes are verified-pass (a
// prod-like env exists, which is guaranteed by the time it runs) and the
// two shared non-pass statuses (partial when no prod-like env was found,
// not-checkable when the API read failed or the repo has zero
// environments at all). The other three checks each have a real
// pass/fail split per environment.
var checkWantStatuses = map[string][]model.Status{
	"C03.env.exists":             {model.StatusVerifiedPass, model.StatusPartial, model.StatusNotCheckable},
	"C03.env.protection-rules":   {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	"C03.env.required-reviewers": {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	"C03.env.branch-policy":      {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
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

// TestBranchPolicyRemediationUsesCurrentUILabel locks in that the
// remediation names GitHub's actual current deployment-branch-policy UI
// option ("No restriction") rather than the stale pre-tags-support label
// ("All branches"), which no longer appears in the environment settings
// UI.
func TestBranchPolicyRemediationUsesCurrentUILabel(t *testing.T) {
	remediation := checkRemediations["C03.env.branch-policy"]
	if strings.Contains(remediation, "All branches") {
		t.Errorf("C03.env.branch-policy remediation uses the stale \"All branches\" label — GitHub's current UI calls this option \"No restriction\": %q", remediation)
	}
	if !strings.Contains(remediation, "No restriction") {
		t.Errorf("C03.env.branch-policy remediation should name the current \"No restriction\" label as the state being changed from: %q", remediation)
	}
}

// rubricState is one fixture world for TestRubricsMatchObservedBehaviour.
// Every check in this collector bottoms out at the SAME environments list,
// so envsStatus/envs is the whole input surface.
type rubricState struct {
	name       string
	envsStatus int
	envs       []map[string]any
	want       map[string]model.Status
}

func (st rubricState) mux(t *testing.T, org, repo string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/environments", func(w http.ResponseWriter, _ *http.Request) {
		if st.envsStatus != http.StatusOK {
			writeJSON(t, w, st.envsStatus, map[string]any{"message": "nope"})
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]any{"total_count": len(st.envs), "environments": st.envs})
	})
	return mux
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue #10).
//
// Five states reach all sixteen (four checks × four statuses) combinations,
// minus C03.env.exists' verified-fail, which this collector deliberately
// cannot produce — collectRepo returns before calling checkExists unless a
// production-like environment already exists, so its only open question is
// which non-fail status applies.
//
// Three of the four checks are conflated by construction, not by accident:
// protection-rules, required-reviewers and branch-policy all read the SAME
// prodEnvs slice from the SAME ListEnvironments response, and the two states
// that produce a collector-wide answer (not-checkable, partial) move all four
// in lockstep. So a matrix built only from "fully protected" and "fully
// unprotected" prod environments would reach every status while never once
// making two of these three checks disagree — coverage that proves nothing
// about which field each check reads.
//
// States 1-3 are constructed against exactly that. Each holds ONE
// production-like environment configured so the three checks split:
//
//	state 1: rules present, none of them reviewers, branch policy set
//	         -> protection PASS, reviewers FAIL, branch PASS
//	state 2: a real reviewers rule, no deployment_branch_policy at all
//	         -> protection PASS, reviewers PASS, branch FAIL
//	state 3: zero protection rules, branch policy set
//	         -> protection FAIL, reviewers FAIL, branch PASS
//
// Every pair among the three disagrees in at least one state (protection vs
// reviewers in 1 and 2, protection vs branch in 2, reviewers vs branch in 1
// and 3). Confirmed by injection rather than assumed — three mutations that a
// lockstep matrix would miss, all caught:
//
//   - making checkRequiredReviewers fail on len(e.ProtectionRules) == 0
//     instead of hasRequiredReviewers — i.e. conflating it with
//     protection-rules — is caught by state 1 alone, the only state whose
//     environment has rules but no usable reviewers rule.
//   - making checkBranchPolicy read hasRequiredReviewers instead of
//     hasBranchPolicy is caught by states 1, 2 and 3, in both directions.
//   - dropping hasRequiredReviewers' len(rule.Reviewers) > 0 condition is
//     caught by state 1, whose environment carries a required_reviewers rule
//     with an EMPTY reviewers list alongside the wait timer. That is the
//     rubric's second fail route for the check ("has one configured with zero
//     reviewers") and is not reachable any other way: a rule of the right type
//     still has to be rejected.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	const org, repo = "attestward-demo", "svc"

	branchPolicySet := map[string]any{"protected_branches": true, "custom_branch_policies": false}

	states := []rubricState{
		{
			name:       "prod env has rules and a branch policy, but no usable reviewers rule",
			envsStatus: http.StatusOK,
			envs: []map[string]any{{
				"name": "production",
				"protection_rules": []map[string]any{
					{"type": "wait_timer", "wait_timer": 30},
					{"type": "required_reviewers", "reviewers": []map[string]any{}},
				},
				"deployment_branch_policy": branchPolicySet,
			}},
			want: map[string]model.Status{
				"C03.env.exists":             model.StatusVerifiedPass,
				"C03.env.protection-rules":   model.StatusVerifiedPass,
				"C03.env.required-reviewers": model.StatusVerifiedFail,
				"C03.env.branch-policy":      model.StatusVerifiedPass,
			},
		},
		{
			name:       "prod env has real reviewers but deploys from any branch",
			envsStatus: http.StatusOK,
			envs: []map[string]any{{
				"name": "prod-us-east",
				"protection_rules": []map[string]any{
					{"type": "required_reviewers", "reviewers": []map[string]any{{"type": "Team", "id": 1}}},
				},
			}},
			want: map[string]model.Status{
				"C03.env.exists":             model.StatusVerifiedPass,
				"C03.env.protection-rules":   model.StatusVerifiedPass,
				"C03.env.required-reviewers": model.StatusVerifiedPass,
				"C03.env.branch-policy":      model.StatusVerifiedFail,
			},
		},
		{
			name:       "prod env has no protection rules at all but restricts branches",
			envsStatus: http.StatusOK,
			envs: []map[string]any{{
				"name":                     "Production",
				"protection_rules":         []map[string]any{},
				"deployment_branch_policy": branchPolicySet,
			}},
			want: map[string]model.Status{
				"C03.env.exists":             model.StatusVerifiedPass,
				"C03.env.protection-rules":   model.StatusVerifiedFail,
				"C03.env.required-reviewers": model.StatusVerifiedFail,
				"C03.env.branch-policy":      model.StatusVerifiedPass,
			},
		},
		{
			// Environments exist but none is production-like: an affirmative
			// "ambiguous, a human should judge", so all four report partial
			// together. The only route to partial.
			name:       "environments exist but none production-like",
			envsStatus: http.StatusOK,
			envs: []map[string]any{
				{"name": "staging"},
				{"name": "dev"},
			},
			want: map[string]model.Status{
				"C03.env.exists":             model.StatusPartial,
				"C03.env.protection-rules":   model.StatusPartial,
				"C03.env.required-reviewers": model.StatusPartial,
				"C03.env.branch-policy":      model.StatusPartial,
			},
		},
		{
			// The list itself is refused, so nothing downstream ran.
			name:       "environments list forbidden",
			envsStatus: http.StatusForbidden,
			want: map[string]model.Status{
				"C03.env.exists":             model.StatusNotCheckable,
				"C03.env.protection-rules":   model.StatusNotCheckable,
				"C03.env.required-reviewers": model.StatusNotCheckable,
				"C03.env.branch-policy":      model.StatusNotCheckable,
			},
		},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			c := newCollectorForServer(t, newTestServer(t, st.mux(t, org, repo)))
			results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
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
			// Compared whole, in both directions: a missing key is as much a
			// defect as a wrong one, and a row count would show neither.
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
