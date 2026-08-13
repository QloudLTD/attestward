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
	"gitlab.com/sioakeim/attestward/internal/collect/gitlab/gitlabfixture"
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

// envMux mirrors the calls collectRepo actually makes: GET
// /projects/:id/environments, then (only if at least one prod-like name
// exists) GET /projects/:id/protected_environments, then (only if either
// protection check would still fail) GET /groups/:path/protected_environments
// for the namespace and each ancestor. envStatus/peStatus let a state supply
// a non-200 response for either project endpoint independently.
//
// Every group path not named in a state answers 404, matching the live
// default: GitLab 404s /groups/:path for a personal namespace, which is where
// most projects using this collector live.
func envMux(envNames []string, envStatus int, protected []protectedEnvironment, peStatus int) http.Handler {
	return envMuxTiered(taggedEnvs(envNames), envStatus, protected, peStatus, nil)
}

// taggedEnvs gives each name the deployment tier GitLab derives from it, so
// the shared states keep behaving as they did before tiers existed:
// "production" comes back tier "production", as it does live.
func taggedEnvs(names []string) []environment {
	out := make([]environment, 0, len(names))
	for _, n := range names {
		tier := "other"
		if prodLikeName(n) {
			tier = "production"
		}
		out = append(out, environment{Name: n, Tier: tier})
	}
	return out
}

// groupState is one group path's answer: entries when status is 200, an error
// body otherwise. Keyed by the unescaped group path in envMuxTiered.
type groupState struct {
	status  int
	entries []protectedEnvironment
}

func envMuxTiered(envs []environment, envStatus int, protected []protectedEnvironment, peStatus int,
	groups map[string]groupState) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/environments"):
			if envStatus != http.StatusOK {
				w.WriteHeader(envStatus)
				_, _ = fmt.Fprint(w, `{"message":"nope"}`)
				return
			}
			body, _ := json.Marshal(envs)
			_, _ = w.Write(body)
		case strings.HasSuffix(r.URL.Path, "/protected_environments"):
			if peStatus != http.StatusOK {
				w.WriteHeader(peStatus)
				_, _ = fmt.Fprint(w, `{"message":"nope"}`)
				return
			}
			body, _ := json.Marshal(protected)
			_, _ = w.Write(body)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"404"}`)
		}
	})
	mux.HandleFunc("/api/v4/groups/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// r.URL.Path is already percent-decoded, so a nested namespace's
		// %2F arrives here as the "/" the state map is keyed by.
		path := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v4/groups/"), "/protected_environments")
		st, ok := groups[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"404 Group Not Found"}`)
			return
		}
		if st.status != http.StatusOK {
			w.WriteHeader(st.status)
			_, _ = fmt.Fprint(w, `{"message":"403 Forbidden"}`)
			return
		}
		body, _ := json.Marshal(st.entries)
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

// groupProduction is the group-level shape observed live: name is the
// deployment TIER, and the approval rule requires one approval.
func groupProduction(requiredApprovals int) []protectedEnvironment {
	pe := protectedEnvironment{Name: "production"}
	if requiredApprovals > 0 {
		pe.ApprovalRules = []approvalRule{{RequiredApprovals: requiredApprovals}}
	}
	return []protectedEnvironment{pe}
}

// TestGroupLevelProtectionPasses is issue #13's exact false-fail: a project
// with a production environment, an EMPTY project-level protected list, and
// group-level protection of the production tier. That combination was
// verified-fail before this; it is the state observed live on
// qloud-ltd-group/attestward-fixtures (2026-08-13).
func TestGroupLevelProtectionPasses(t *testing.T) {
	h := envMuxTiered(taggedEnvs([]string{"production"}), 200, nil, 200,
		map[string]groupState{"g": {status: 200, entries: groupProduction(1)}})
	got := byID(collectWith(t, h, "g", "p"))

	if got[idProtectionRules].Status != model.StatusVerifiedPass {
		t.Errorf("protection-rules = %q, want verified-pass — the environment is protected at the group "+
			"level, which the project-level list cannot show; reason=%q",
			got[idProtectionRules].Status, got[idProtectionRules].Reason)
	}
	if got[idRequiredReviewers].Status != model.StatusVerifiedPass {
		t.Errorf("required-reviewers = %q, want verified-pass — the group-level entry requires an approval; "+
			"reason=%q", got[idRequiredReviewers].Status, got[idRequiredReviewers].Reason)
	}
	if !strings.Contains(got[idProtectionRules].Reason, "group-level") {
		t.Errorf("reason %q does not say the pass came from group-level config; a reader looking at an empty "+
			"project-level list would have no way to tell where the pass came from", got[idProtectionRules].Reason)
	}
}

// TestGroupLevelMatchesOnTierNotName is the reason group-level protection
// exists at all, in GitLab's own words: a group holds projects whose
// production environments have unrelated names. Matching the group entry's
// name against the environment's name would pass "production" and fail
// "prodweb", even though both carry tier "production" and both are covered.
func TestGroupLevelMatchesOnTierNotName(t *testing.T) {
	envs := []environment{{Name: "prodweb", Tier: "production"}}
	h := envMuxTiered(envs, 200, nil, 200,
		map[string]groupState{"g": {status: 200, entries: groupProduction(1)}})
	got := byID(collectWith(t, h, "g", "p"))

	if got[idProtectionRules].Status != model.StatusVerifiedPass {
		t.Errorf("protection-rules = %q, want verified-pass — \"prodweb\" carries tier \"production\", and "+
			"tier is what group-level entries are keyed by; reason=%q",
			got[idProtectionRules].Status, got[idProtectionRules].Reason)
	}
}

// TestGroupLevelTierMismatchStillFails is the same test's other half: tier
// matching must be real matching, not a proxy for "some group entry exists".
func TestGroupLevelTierMismatchStillFails(t *testing.T) {
	envs := []environment{{Name: "production", Tier: "staging"}}
	h := envMuxTiered(envs, 200, nil, 200,
		map[string]groupState{"g": {status: 200, entries: groupProduction(1)}})
	got := byID(collectWith(t, h, "g", "p"))

	if got[idProtectionRules].Status != model.StatusVerifiedFail {
		t.Errorf("protection-rules = %q, want verified-fail — the only group entry protects tier "+
			"\"production\" and this environment's tier is \"staging\"", got[idProtectionRules].Status)
	}
}

// TestEnvironmentWithNoTierCannotMatchGroupLevel pins the empty-tier
// decision: group-level protection is keyed by tier and nothing else, so an
// environment reporting no tier — an older self-managed instance, say — must
// read as unmatched rather than as matching whatever entry happens to exist.
func TestEnvironmentWithNoTierCannotMatchGroupLevel(t *testing.T) {
	envs := []environment{{Name: "production", Tier: ""}}
	h := envMuxTiered(envs, 200, nil, 200,
		map[string]groupState{"g": {status: 200, entries: groupProduction(1)}})
	got := byID(collectWith(t, h, "g", "p"))

	if got[idProtectionRules].Status != model.StatusVerifiedFail {
		t.Errorf("protection-rules = %q, want verified-fail — an absent tier is a non-answer, not a wildcard",
			got[idProtectionRules].Status)
	}
}

// TestUntieredGroupEntryCannotProtectAnUntieredEnvironment is the collision
// the tier map is built to avoid, and the only one whose failure direction is
// a false PASS. A group entry naming no tier and an environment reporting no
// tier would meet at the empty-string key and read as protected — a project
// with no protection anywhere reported as protected. Nothing in either
// response is evidence of protection, so both are dropped rather than matched.
func TestUntieredGroupEntryCannotProtectAnUntieredEnvironment(t *testing.T) {
	envs := []environment{{Name: "production", Tier: ""}}
	untiered := []protectedEnvironment{{Name: "", ApprovalRules: []approvalRule{{RequiredApprovals: 1}}}}
	h := envMuxTiered(envs, 200, nil, 200, map[string]groupState{"g": {status: 200, entries: untiered}})
	got := byID(collectWith(t, h, "g", "p"))

	for _, id := range []string{idProtectionRules, idRequiredReviewers} {
		if got[id].Status != model.StatusVerifiedFail {
			t.Errorf("%s = %q, want verified-fail — an entry naming no tier protects no tier, and matching "+
				"it against an environment reporting no tier would pass an unprotected project; reason=%q",
				id, got[id].Status, got[id].Reason)
		}
	}
}

// TestGroupLevelProtectionWithoutApprovalSplitsTheChecks mirrors the
// project-level independence test one level up: group protection with no
// approval rule satisfies "has some protection" and not "requires approval".
func TestGroupLevelProtectionWithoutApprovalSplitsTheChecks(t *testing.T) {
	h := envMuxTiered(taggedEnvs([]string{"production"}), 200, nil, 200,
		map[string]groupState{"g": {status: 200, entries: groupProduction(0)}})
	got := byID(collectWith(t, h, "g", "p"))

	if got[idProtectionRules].Status != model.StatusVerifiedPass {
		t.Errorf("protection-rules = %q, want verified-pass", got[idProtectionRules].Status)
	}
	if got[idRequiredReviewers].Status != model.StatusVerifiedFail {
		t.Errorf("required-reviewers = %q, want verified-fail — the group entry protects the tier but "+
			"requires no approvals", got[idRequiredReviewers].Status)
	}
}

// TestGroupApprovalRuleSatisfiesReviewersOverProjectEntryWithout is the case
// that made needsGroupLookup check approvals and not just protection: the
// project-level entry exists, so protection-rules passes on it alone and an
// "only look at the group when unprotected" trigger would never fire — while
// required-reviewers still needs the group entry to see its approval rule.
func TestGroupApprovalRuleSatisfiesReviewersOverProjectEntryWithout(t *testing.T) {
	projectLevel := []protectedEnvironment{{Name: "production", ApprovalRules: nil}}
	h := envMuxTiered(taggedEnvs([]string{"production"}), 200, projectLevel, 200,
		map[string]groupState{"g": {status: 200, entries: groupProduction(1)}})
	got := byID(collectWith(t, h, "g", "p"))

	if got[idRequiredReviewers].Status != model.StatusVerifiedPass {
		t.Errorf("required-reviewers = %q, want verified-pass — the approval requirement is on the "+
			"group-level entry, and the two rulesets compose; reason=%q",
			got[idRequiredReviewers].Status, got[idRequiredReviewers].Reason)
	}
}

// TestNoGroupLookupWhenProjectLevelAlreadyPasses guards the trigger from the
// other side: a project that passes both checks on its own config must not
// pay for the group walk, because no group entry could change that answer.
func TestNoGroupLookupWhenProjectLevelAlreadyPasses(t *testing.T) {
	var groupCalls int
	inner := envMuxTiered(taggedEnvs([]string{"production"}), 200,
		[]protectedEnvironment{{Name: "production", ApprovalRules: []approvalRule{{RequiredApprovals: 1}}}}, 200,
		map[string]groupState{"g": {status: 200, entries: groupProduction(1)}})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v4/groups/") {
			groupCalls++
		}
		inner.ServeHTTP(w, r)
	})

	got := byID(collectWith(t, h, "g", "p"))
	if got[idProtectionRules].Status != model.StatusVerifiedPass {
		t.Fatalf("protection-rules = %q, want verified-pass", got[idProtectionRules].Status)
	}
	if groupCalls != 0 {
		t.Errorf("group endpoint called %d times, want 0 — project-level config already answered both "+
			"checks with a pass", groupCalls)
	}
}

// TestAncestorGroupProtectionIsFound is the finding that forced a walk rather
// than a single lookup. GitLab's own docs say a subgroup "cannot override" a
// parent group's protected environment — so the parent's rule governs a
// project in the subgroup — but GET /groups/<subgroup>/protected_environments
// returns [] regardless. Measured live 2026-08-13 against
// qloud-ltd-group/pe-inherit-probe while the parent's entry was in place.
// Querying only the project's own namespace would false-fail identically, one
// level down.
func TestAncestorGroupProtectionIsFound(t *testing.T) {
	h := envMuxTiered(taggedEnvs([]string{"production"}), 200, nil, 200, map[string]groupState{
		"top/sub": {status: 200, entries: nil}, // what the live subgroup returns
		"top":     {status: 200, entries: groupProduction(1)},
	})
	got := byID(collectWith(t, h, "top/sub", "p"))

	if got[idProtectionRules].Status != model.StatusVerifiedPass {
		t.Errorf("protection-rules = %q, want verified-pass — the protection is on the parent group, and "+
			"the subgroup endpoint does not report it; reason=%q",
			got[idProtectionRules].Status, got[idProtectionRules].Reason)
	}
}

// TestAncestorApprovalRuleWinsOverNearerGroupWithout pins how two levels of
// group config merge. The nearer group protects the tier but demands no
// approval; the parent demands one. GitLab composes the rulesets rather than
// letting the nearer one override — "the user must be allowed in both" — so
// an approval demanded anywhere up the chain is demanded, and keeping only
// the deepest entry would lose it.
func TestAncestorApprovalRuleWinsOverNearerGroupWithout(t *testing.T) {
	h := envMuxTiered(taggedEnvs([]string{"production"}), 200, nil, 200, map[string]groupState{
		"top/sub": {status: 200, entries: groupProduction(0)},
		"top":     {status: 200, entries: groupProduction(1)},
	})
	got := byID(collectWith(t, h, "top/sub", "p"))

	if got[idRequiredReviewers].Status != model.StatusVerifiedPass {
		t.Errorf("required-reviewers = %q, want verified-pass — the parent group requires an approval and "+
			"the subgroup cannot override it away; reason=%q",
			got[idRequiredReviewers].Status, got[idRequiredReviewers].Reason)
	}
}

// TestGroupReadRefusalFailsButDisclosesTheBlindSpot pins the deliberate
// departure from ErrTierGated's usual doctrine. A 403 on the group endpoint
// does NOT become not-checkable: project-level protected environments work on
// Free, so the fail is entitled and actionable, and retiring it for every
// unprotected project because a Premium-only alternative route was refused
// would cost far more than it protects. The blind spot is disclosed instead —
// and that disclosure is the load-bearing half, since without it this fail is
// indistinguishable from one that ruled out both routes.
func TestGroupReadRefusalFailsButDisclosesTheBlindSpot(t *testing.T) {
	h := envMuxTiered(taggedEnvs([]string{"production"}), 200, nil, 200,
		map[string]groupState{"g": {status: http.StatusForbidden}})
	got := byID(collectWith(t, h, "g", "p"))

	for _, id := range []string{idProtectionRules, idRequiredReviewers} {
		if got[id].Status != model.StatusVerifiedFail {
			t.Errorf("%s = %q, want verified-fail — project-level evidence still supports it", id, got[id].Status)
		}
		if !strings.Contains(got[id].Reason, "could not be read") {
			t.Errorf("%s reason %q does not disclose that group-level config was unreadable", id, got[id].Reason)
		}
		if got[id].Facts["group_level_unreadable"] == nil {
			t.Errorf("%s facts do not record which group path was unreadable", id)
		}
	}
}

// TestPersonalNamespace404IsNotReportedAsABlindSpot is the other side of that
// disclosure. GitLab 404s /groups/:path for a personal namespace — the common
// Free case — because group-level protection is structurally impossible
// there, not because anything was hidden. Reporting it as an unreadable blind
// spot would put a misleading caveat on the majority of real fails.
func TestPersonalNamespace404IsNotReportedAsABlindSpot(t *testing.T) {
	h := envMuxTiered(taggedEnvs([]string{"production"}), 200, nil, 200, nil) // every group path 404s
	got := byID(collectWith(t, h, "g", "p"))

	for _, id := range []string{idProtectionRules, idRequiredReviewers} {
		if got[id].Status != model.StatusVerifiedFail {
			t.Errorf("%s = %q, want verified-fail", id, got[id].Status)
		}
		if strings.Contains(got[id].Reason, "could not be read") {
			t.Errorf("%s reason %q discloses a blind spot for a 404, which means \"no group exists here\", "+
				"not \"something was hidden\"", id, got[id].Reason)
		}
		if got[id].Facts["group_level_unreadable"] != nil {
			t.Errorf("%s records a 404 as an unreadable group", id)
		}
	}
}

// TestNested404IsDisclosedNotSwallowed is the regression test for a real
// bug caught in review: GitLab is not consistent about whether it 403s or
// 404s a group the token can't see (see client.go's own doc comment on
// this). For a SINGLE-segment org, a 404 genuinely can't be told apart
// from "no group at all" (TestPersonalNamespace404IsNotReportedAsABlindSpot
// above), so it stays silent. But GitLab does not allow subgroups under a
// personal namespace — so once org is nested ("g/sub"), every ancestor
// path in the walk, including the top-level one, is provably a real group,
// and a 404 anywhere in that walk can only mean refused/hidden. Before the
// fix, every 404 was swallowed unconditionally, which combined with this
// MR's own rubric text ("no caveat means both routes were ruled out") to
// make a false fail read as complete when it wasn't, one token-permission
// away from the every-fail-is-swallowed case this test pins.
func TestNested404IsDisclosedNotSwallowed(t *testing.T) {
	h := envMuxTiered(taggedEnvs([]string{"production"}), 200, nil, 200, nil) // every group path 404s
	got := byID(collectWith(t, h, "g/sub", "p"))

	for _, id := range []string{idProtectionRules, idRequiredReviewers} {
		if got[id].Status != model.StatusVerifiedFail {
			t.Errorf("%s = %q, want verified-fail — project-level evidence still supports it", id, got[id].Status)
		}
		if !strings.Contains(got[id].Reason, "could not be read") {
			t.Errorf("%s reason %q must disclose the blind spot — org is nested, so a 404 here can only mean "+
				"refused/hidden, never absent", id, got[id].Reason)
		}
		if got[id].Facts["group_level_unreadable"] == nil {
			t.Errorf("%s facts do not record which group path was unreadable", id)
		}
	}
}

func TestNamespacePaths(t *testing.T) {
	cases := []struct {
		org  string
		want []string
	}{
		{"g", []string{"g"}},
		{"top/sub", []string{"top/sub", "top"}},
		{"a/b/c", []string{"a/b/c", "a/b", "a"}},
		{"", nil},
		{"/", nil},
	}
	for _, tc := range cases {
		got := namespacePaths(tc.org)
		if len(got) != len(tc.want) {
			t.Errorf("namespacePaths(%q) = %v, want %v", tc.org, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("namespacePaths(%q) = %v, want %v", tc.org, got, tc.want)
				break
			}
		}
	}
}

// TestRecordedGroupResponseDecodes runs this package's own struct over the
// real group-level response, so the two claims the code rests on stay pinned
// to a recording rather than to memory: the entry's "name" is a deployment
// tier, and approval_rules decodes the same way it does at project level.
// Re-recording needs an entitled namespace — the one used expires 2026-09-08.
func TestRecordedGroupResponseDecodes(t *testing.T) {
	var got []protectedEnvironment
	if err := json.Unmarshal(gitlabfixture.MustLoad(t, "group-protected-environments.json"), &got); err != nil {
		t.Fatalf("decode recorded group response: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Name != "production" {
		t.Errorf("Name = %q, want %q — at group level this field is the deployment tier", got[0].Name, "production")
	}
	if !hasRequiredApproval(got[0]) {
		t.Errorf("hasRequiredApproval = false, want true — the recorded entry has required_approvals: 1")
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
		// org overrides the default "g" for states whose point is the
		// namespace path itself, i.e. the ancestor-group walk.
		org  string
		want map[string]model.Status
	}{
		{"protected with approval", envMux([]string{"production"}, 200, protectedWithApproval, 200), "",
			map[string]model.Status{idExists: pass, idProtectionRules: pass, idRequiredReviewers: pass, idBranchPolicy: nc}},
		{"unprotected", envMux([]string{"production"}, 200, nil, 200), "",
			map[string]model.Status{idExists: pass, idProtectionRules: fail, idRequiredReviewers: fail, idBranchPolicy: nc}},
		{"no prod-like name", envMux([]string{"staging"}, 200, nil, 200), "",
			map[string]model.Status{idExists: partial, idProtectionRules: partial, idRequiredReviewers: partial, idBranchPolicy: nc}},
		{"zero environments", envMux(nil, 200, nil, 200), "",
			map[string]model.Status{idExists: nc, idProtectionRules: nc, idRequiredReviewers: nc, idBranchPolicy: nc}},
		{"environments unreadable", envMux(nil, 403, nil, 200), "",
			map[string]model.Status{idExists: nc, idProtectionRules: nc, idRequiredReviewers: nc, idBranchPolicy: nc}},
		{"protected environments unreadable", envMux([]string{"production"}, 200, nil, 403), "",
			map[string]model.Status{idExists: nc, idProtectionRules: nc, idRequiredReviewers: nc, idBranchPolicy: nc}},
		// The four group-level states below reach no status the six above do
		// not, and they are in the matrix anyway: the guard compares which
		// statuses are emitted, so a second, undescribed route to an
		// already-documented status is exactly the rot it cannot see (its own
		// doc says so). Reaching each route here at least holds the rubric's
		// wording against a case that produces it.
		{"protected at group level only", envMuxTiered(taggedEnvs([]string{"production"}), 200, nil, 200,
			map[string]groupState{"g": {status: 200, entries: groupProduction(1)}}), "",
			map[string]model.Status{idExists: pass, idProtectionRules: pass, idRequiredReviewers: pass, idBranchPolicy: nc}},
		{"protected at ancestor group only", envMuxTiered(taggedEnvs([]string{"production"}), 200, nil, 200,
			map[string]groupState{"top/sub": {status: 200}, "top": {status: 200, entries: groupProduction(1)}}), "top/sub",
			map[string]model.Status{idExists: pass, idProtectionRules: pass, idRequiredReviewers: pass, idBranchPolicy: nc}},
		{"group protection without approval rule", envMuxTiered(taggedEnvs([]string{"production"}), 200, nil, 200,
			map[string]groupState{"g": {status: 200, entries: groupProduction(0)}}), "",
			map[string]model.Status{idExists: pass, idProtectionRules: pass, idRequiredReviewers: fail, idBranchPolicy: nc}},
		{"group config refused", envMuxTiered(taggedEnvs([]string{"production"}), 200, nil, 200,
			map[string]groupState{"g": {status: 403}}), "",
			map[string]model.Status{idExists: pass, idProtectionRules: fail, idRequiredReviewers: fail, idBranchPolicy: nc}},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			org := st.org
			if org == "" {
				org = "g"
			}
			res := collectWith(t, st.h, org, "p")
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
