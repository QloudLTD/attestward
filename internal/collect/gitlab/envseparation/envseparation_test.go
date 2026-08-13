package envseparation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/model"
)

func newTestCollector(t *testing.T, handler http.Handler) *Collector {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return NewForTest(server.URL, "token", func() (*gitlabcollect.Client, error) {
		return gitlabcollect.NewClientForTest(server.URL, "token", http.DefaultTransport)
	})
}

func byID(results []model.CheckResult) map[string]model.CheckResult {
	out := map[string]model.CheckResult{}
	for _, r := range results {
		out[r.CheckID] = r
	}
	return out
}

func collectWith(t *testing.T, handler http.Handler, org string, repos ...string) []model.CheckResult {
	t.Helper()
	c := newTestCollector(t, handler)
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: repos})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return results
}

// envMux mirrors the two calls collectRepo actually makes: GET
// /projects/:id/environments, then (only if at least one prod-like name
// exists) GET /projects/:id/protected_environments. envStatus/peStatus let a
// state supply a non-200 response for either endpoint independently.
func envMux(envNames []string, envStatus int, protected []protectedEnvironment, peStatus int) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/g%2Fp/environments", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if envStatus != http.StatusOK {
			w.WriteHeader(envStatus)
			_, _ = fmt.Fprint(w, `{"message":"nope"}`)
			return
		}
		envs := make([]environment, 0, len(envNames))
		for _, n := range envNames {
			envs = append(envs, environment{Name: n})
		}
		body, _ := json.Marshal(envs)
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/api/v4/projects/g%2Fp/protected_environments", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if peStatus != http.StatusOK {
			w.WriteHeader(peStatus)
			_, _ = fmt.Fprint(w, `{"message":"nope"}`)
			return
		}
		body, _ := json.Marshal(protected)
		_, _ = w.Write(body)
	})
	return mux
}

func TestBranchPolicyIsAlwaysNotCheckable(t *testing.T) {
	states := []http.Handler{
		envMux(nil, 200, nil, 200),                 // zero environments
		envMux([]string{"staging"}, 200, nil, 200), // no prod-like name
		envMux([]string{"production"}, 200, []protectedEnvironment{{Name: "production", ApprovalRules: []approvalRule{{RequiredApprovals: 1}}}}, 200), // real evaluation
		envMux(nil, 403, nil, 200), // env read failure
	}
	for i, h := range states {
		t.Run(fmt.Sprintf("state-%d", i), func(t *testing.T) {
			got := byID(collectWith(t, h, "g", "p"))[idBranchPolicy]
			if got.Status != model.StatusNotCheckable {
				t.Errorf("branch-policy = %q, want not-checkable in every state — it has no data source "+
					"regardless of environment state", got.Status)
			}
		})
	}
}

func TestZeroEnvironmentsIsNotCheckable(t *testing.T) {
	got := byID(collectWith(t, envMux(nil, 200, nil, 200), "g", "p"))
	for _, id := range []string{idExists, idProtectionRules, idRequiredReviewers} {
		if got[id].Status != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got[id].Status)
		}
	}
}

func TestNoProdLikeNameIsPartial(t *testing.T) {
	got := byID(collectWith(t, envMux([]string{"staging", "dev"}, 200, nil, 200), "g", "p"))
	for _, id := range []string{idExists, idProtectionRules, idRequiredReviewers} {
		if got[id].Status != model.StatusPartial {
			t.Errorf("%s = %q, want partial", id, got[id].Status)
		}
	}
}

func TestProtectedWithApprovalIsAllPass(t *testing.T) {
	protected := []protectedEnvironment{{Name: "production", ApprovalRules: []approvalRule{{RequiredApprovals: 1}}}}
	got := byID(collectWith(t, envMux([]string{"production"}, 200, protected, 200), "g", "p"))
	if got[idExists].Status != model.StatusVerifiedPass {
		t.Errorf("exists = %q, want verified-pass", got[idExists].Status)
	}
	if got[idProtectionRules].Status != model.StatusVerifiedPass {
		t.Errorf("protection-rules = %q, want verified-pass", got[idProtectionRules].Status)
	}
	if got[idRequiredReviewers].Status != model.StatusVerifiedPass {
		t.Errorf("required-reviewers = %q, want verified-pass; reason=%q", got[idRequiredReviewers].Status, got[idRequiredReviewers].Reason)
	}
}

// TestRequiredReviewersPassReasonDoesNotAssertLiveEnforcement pins the
// wording issue #12 exists to fix. A stored approval_rules entry is
// confirmed readable on Free (this package's own doc comment) but verified
// NOT enforced there — a real pipeline deployment against exactly this
// configuration ran unblocked with pending_approval_count 0. Without this
// test, the verified-pass Reason can silently round-trip back to its old
// wording ("...requires at least one approval", asserting a live gate) and
// nothing else in the repo catches it: the Reason field is not rendered
// into docs/checks-reference.md, so make checks-docs-check passes either
// way — confirmed by reverting the wording and re-running that check before
// writing this test.
func TestRequiredReviewersPassReasonDoesNotAssertLiveEnforcement(t *testing.T) {
	protected := []protectedEnvironment{{Name: "production", ApprovalRules: []approvalRule{{RequiredApprovals: 1}}}}
	got := byID(collectWith(t, envMux([]string{"production"}, 200, protected, 200), "g", "p"))
	r := got[idRequiredReviewers]
	if r.Status != model.StatusVerifiedPass {
		t.Fatalf("required-reviewers = %q, want verified-pass (fixture setup sanity check)", r.Status)
	}
	if !strings.Contains(r.Reason, "not evidence the gate fires") {
		t.Errorf("Reason must state the stored rule is not evidence of live enforcement, got: %s", r.Reason)
	}
	if !strings.Contains(r.Reason, "verified live") {
		t.Errorf("Reason must name that non-enforcement on Free was verified live, not assumed, got: %s", r.Reason)
	}
	if strings.Contains(r.Reason, "requires at least one approval:") {
		t.Errorf("Reason must not assert an active gate (\"requires at least one approval\"), got: %s", r.Reason)
	}
}

func TestUnprotectedProdEnvFailsBothProtectionChecks(t *testing.T) {
	got := byID(collectWith(t, envMux([]string{"production"}, 200, nil, 200), "g", "p"))
	if got[idExists].Status != model.StatusVerifiedPass {
		t.Errorf("exists = %q, want verified-pass — the environment exists regardless of protection", got[idExists].Status)
	}
	if got[idProtectionRules].Status != model.StatusVerifiedFail {
		t.Errorf("protection-rules = %q, want verified-fail", got[idProtectionRules].Status)
	}
	if got[idRequiredReviewers].Status != model.StatusVerifiedFail {
		t.Errorf("required-reviewers = %q, want verified-fail", got[idRequiredReviewers].Status)
	}
}

// TestProtectedWithoutApprovalPassesProtectionButFailsReviewers guards the
// two protection checks' independence: deploy_access_levels-only protection
// (no approval_rules) satisfies "has SOME protection" but not "requires an
// approval" — they are different questions and must not share an answer.
func TestProtectedWithoutApprovalPassesProtectionButFailsReviewers(t *testing.T) {
	protected := []protectedEnvironment{{Name: "production", ApprovalRules: nil}}
	got := byID(collectWith(t, envMux([]string{"production"}, 200, protected, 200), "g", "p"))
	if got[idProtectionRules].Status != model.StatusVerifiedPass {
		t.Errorf("protection-rules = %q, want verified-pass — a matching protected_environments entry "+
			"exists, regardless of whether it requires approval", got[idProtectionRules].Status)
	}
	if got[idRequiredReviewers].Status != model.StatusVerifiedFail {
		t.Errorf("required-reviewers = %q, want verified-fail — no approval_rules entry requires an approval",
			got[idRequiredReviewers].Status)
	}
}

// TestZeroRequiredApprovalsDoesNotCount guards against an approval_rules
// entry that exists but requires zero approvals — GitLab's schema allows
// required_approvals: 0, which is not a reviewer requirement at all.
func TestZeroRequiredApprovalsDoesNotCount(t *testing.T) {
	protected := []protectedEnvironment{{Name: "production", ApprovalRules: []approvalRule{{RequiredApprovals: 0}}}}
	got := byID(collectWith(t, envMux([]string{"production"}, 200, protected, 200), "g", "p"))
	if got[idRequiredReviewers].Status != model.StatusVerifiedFail {
		t.Errorf("required-reviewers = %q, want verified-fail — required_approvals: 0 requires nothing",
			got[idRequiredReviewers].Status)
	}
}

func TestEnvironmentsReadFailureIsNotCheckable(t *testing.T) {
	got := byID(collectWith(t, envMux(nil, 403, nil, 200), "g", "p"))
	for _, id := range []string{idExists, idProtectionRules, idRequiredReviewers} {
		if got[id].Status != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got[id].Status)
		}
	}
}

func TestProtectedEnvironmentsReadFailureIsNotCheckable(t *testing.T) {
	got := byID(collectWith(t, envMux([]string{"production"}, 200, nil, 403), "g", "p"))
	for _, id := range []string{idExists, idProtectionRules, idRequiredReviewers} {
		if got[id].Status != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable — the protected-environments read failed, so this "+
				"cannot honestly assert pass or fail", id, got[id].Status)
		}
	}
}

func TestClientBuildFailureIsNotCheckableForEveryCheck(t *testing.T) {
	c := NewForTest("https://example.invalid", "token", func() (*gitlabcollect.Client, error) {
		return nil, fmt.Errorf("boom")
	})
	results, err := c.Collect(context.Background(), collect.Scope{Org: "g", Repos: []string{"p"}})
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

func TestID(t *testing.T) {
	if got := New("https://gitlab.example", "t").ID(); got != collectorID {
		t.Errorf("ID() = %q, want %q", got, collectorID)
	}
}

// twoRepoEnvMux serves the same healthy environment state for two distinct
// projects, so every recorded provenance endpoint names exactly one of them
// and a cross-repo attribution is visible in the endpoint string itself.
func twoRepoEnvMux(repos ...string) http.Handler {
	mux := http.NewServeMux()
	for _, repo := range repos {
		id := "g%2F" + repo
		mux.HandleFunc("/api/v4/projects/"+id+"/environments", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `[{"name":"production"}]`)
		})
		mux.HandleFunc("/api/v4/projects/"+id+"/protected_environments", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `[{"name":"production","approval_rules":[{"required_approvals":1}]}]`)
		})
	}
	return mux
}

// TestProvenanceNeverCitesAnotherReposAPICalls pins issue #14. Client
// .Provenance() is cumulative over every call ever made through a client
// instance, so when Collect built one client outside the scope.Repos loop, a
// later repo's CheckResult.Provenance carried entries for API calls actually
// made against an earlier repo — evidence citing a project the result is not
// about, which for an attestation tool is an evidence-integrity defect, not
// a cosmetic one. Building the client per repo is what keeps each result's
// evidence its own; this test fails if that construction moves back out of
// collectRepo.
func TestProvenanceNeverCitesAnotherReposAPICalls(t *testing.T) {
	results := collectWith(t, twoRepoEnvMux("p1", "p2"), "g", "p1", "p2")

	sawP2Evidence := false
	for _, r := range results {
		if r.Scope.Repo != "p2" {
			continue
		}
		for _, p := range r.Provenance {
			if strings.Contains(p.Endpoint, "p1") {
				t.Errorf("%s (repo p2) provenance cites %s %s — an API call made while processing repo p1, "+
					"not p2", r.CheckID, p.Method, p.Endpoint)
			}
			if strings.Contains(p.Endpoint, "p2") {
				sawP2Evidence = true
			}
		}
	}
	if !sawP2Evidence {
		t.Fatal("no p2 result carried a single provenance entry naming p2 — the cross-repo assertion above " +
			"would have passed vacuously")
	}
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue
// #10) from the start, with per-state expected statuses compared as a whole
// map — the lesson from review of this package's siblings earlier the same
// day: a state that merely executes a code path without asserting its
// outcome is worse than no state at all.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	pass, fail, partial, nc := model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable
	protectedWithApproval := []protectedEnvironment{{Name: "production", ApprovalRules: []approvalRule{{RequiredApprovals: 1}}}}

	states := []struct {
		name string
		h    http.Handler
		want map[string]model.Status
	}{
		{"protected with approval", envMux([]string{"production"}, 200, protectedWithApproval, 200),
			map[string]model.Status{idExists: pass, idProtectionRules: pass, idRequiredReviewers: pass, idBranchPolicy: nc}},
		{"unprotected", envMux([]string{"production"}, 200, nil, 200),
			map[string]model.Status{idExists: pass, idProtectionRules: fail, idRequiredReviewers: fail, idBranchPolicy: nc}},
		{"no prod-like name", envMux([]string{"staging"}, 200, nil, 200),
			map[string]model.Status{idExists: partial, idProtectionRules: partial, idRequiredReviewers: partial, idBranchPolicy: nc}},
		{"zero environments", envMux(nil, 200, nil, 200),
			map[string]model.Status{idExists: nc, idProtectionRules: nc, idRequiredReviewers: nc, idBranchPolicy: nc}},
		{"environments unreadable", envMux(nil, 403, nil, 200),
			map[string]model.Status{idExists: nc, idProtectionRules: nc, idRequiredReviewers: nc, idBranchPolicy: nc}},
		{"protected environments unreadable", envMux([]string{"production"}, 200, nil, 403),
			map[string]model.Status{idExists: nc, idProtectionRules: nc, idRequiredReviewers: nc, idBranchPolicy: nc}},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			res := collectWith(t, st.h, "g", "p")
			got := map[string]model.Status{}
			for _, r := range res {
				got[r.CheckID] = r.Status
			}
			if len(got) != len(st.want) {
				t.Fatalf("got %d results, want %d", len(got), len(st.want))
			}
			for id, want := range st.want {
				if got[id] != want {
					t.Errorf("%s = %q, want %q", id, got[id], want)
				}
			}
			all = append(all, res...)
		})
	}

	collecttest.AssertRubricsMatchObservedBehaviour(t, platform, collectorID, all)
}
