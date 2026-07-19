package repoprotection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	ghgithub "github.com/google/go-github/v75/github"

	"github.com/sioakim/attestward/internal/collect"
	ghcollect "github.com/sioakim/attestward/internal/collect/github"
	"github.com/sioakim/attestward/internal/model"
)

// newTestCollector points a real ghcollect.Client at a local httptest
// server via client.REST.BaseURL — the same pattern
// internal/collect/github/orgsecurity/orgsecurity_test.go and
// cmd/attestward/scanorgcheck_test.go use. This package's Collect() builds its
// own client per repo internally (see repoprotection.go's New doc comment),
// so tests exercise the full Collector, not collectRepo directly, wherever
// that per-repo client construction matters.
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

// wireBranchRule matches BranchRules' custom wire format (see go-github's
// branchRuleWrapper in rules.go) — a flat JSON array of tagged rule entries,
// not a struct with per-field JSON tags.
type wireBranchRule struct {
	Type              string `json:"type"`
	RulesetSourceType string `json:"ruleset_source_type"`
	RulesetSource     string `json:"ruleset_source"`
	RulesetID         int64  `json:"ruleset_id"`
	Parameters        any    `json:"parameters,omitempty"`
}

func fullProtectionRules(rulesetID int64) []wireBranchRule {
	return []wireBranchRule{
		{Type: "pull_request", RulesetSourceType: "Repository", RulesetID: rulesetID,
			Parameters: ghgithub.PullRequestRuleParameters{RequiredApprovingReviewCount: 1}},
		{Type: "required_status_checks", RulesetSourceType: "Repository", RulesetID: rulesetID,
			Parameters: ghgithub.RequiredStatusChecksRuleParameters{RequiredStatusChecks: []*ghgithub.RuleStatusCheck{{Context: "ci/test"}}}},
		{Type: "non_fast_forward", RulesetSourceType: "Repository", RulesetID: rulesetID},
		{Type: "deletion", RulesetSourceType: "Repository", RulesetID: rulesetID},
	}
}

func newCollectorForServer(t *testing.T, server *httptest.Server) *Collector {
	t.Helper()
	// New builds its own ghcollect.Client per repo from a token, so there is
	// no client to redirect at the test server directly — instead this
	// override makes every freshly constructed client point at it, mirroring
	// how a real token would authenticate against api.github.com.
	c := New("ghp_test-token")
	c.newClientForTest = func(token string) *ghcollect.Client {
		// Runs inside ForEachRepo's worker goroutines, never the test's own
		// goroutine — t.Fatalf there would only abort that worker (via
		// runtime.Goexit), not the test, so a genuine parse failure must be
		// reported with Errorf instead.
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

func TestCollect_UnprotectedRepoAllChecksFail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/bad-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("/repos/attestward-demo/bad-repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Branch not protected"})
	})
	mux.HandleFunc("/repos/attestward-demo/bad-repo/rules/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []wireBranchRule{})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"bad-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 6 {
		t.Fatalf("len(results) = %d, want 6", len(results))
	}
	for _, r := range results {
		if r.Status != model.StatusVerifiedFail {
			t.Errorf("%s status = %q, want verified-fail; reason=%q", r.CheckID, r.Status, r.Reason)
		}
	}
}

// TestCollect_RulesetOnlyRepoAllChecksPass is the issue's own acceptance
// criterion: "Ruleset-only repo (no legacy protection) passes correctly —
// proven by fixture."
func TestCollect_RulesetOnlyRepoAllChecksPass(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/good-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("/repos/attestward-demo/good-repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Branch not protected"})
	})
	mux.HandleFunc("/repos/attestward-demo/good-repo/rules/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, fullProtectionRules(7))
	})
	mux.HandleFunc("/repos/attestward-demo/good-repo/rulesets/7", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"id": 7, "name": "main-protection"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"good-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 6 {
		t.Fatalf("len(results) = %d, want 6", len(results))
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

func TestCollect_LegacyOnlyRepoAllChecksPass(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/good-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("/repos/attestward-demo/good-repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"required_pull_request_reviews": map[string]any{"required_approving_review_count": 1},
			"required_status_checks":        map[string]any{"contexts": []string{"ci/test"}},
			"enforce_admins":                map[string]any{"enabled": true},
			"allow_force_pushes":            map[string]any{"enabled": false},
			"allow_deletions":               map[string]any{"enabled": false},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/good-repo/rules/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []wireBranchRule{})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"good-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range results {
		if r.Status != model.StatusVerifiedPass {
			t.Errorf("%s status = %q, want verified-pass; reason=%q", r.CheckID, r.Status, r.Reason)
		}
	}
}

func TestCollect_AlwaysBypassActorProducesPartialAdminEnforced(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/bypass-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("/repos/attestward-demo/bypass-repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Branch not protected"})
	})
	mux.HandleFunc("/repos/attestward-demo/bypass-repo/rules/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, fullProtectionRules(9))
	})
	mux.HandleFunc("/repos/attestward-demo/bypass-repo/rulesets/9", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"id":   9,
			"name": "main-protection",
			"bypass_actors": []map[string]any{
				{"actor_type": "OrganizationAdmin", "bypass_mode": "always"},
			},
		})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"bypass-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := map[string]model.CheckResult{}
	for _, r := range results {
		byID[r.CheckID] = r
	}
	if got := byID["C02.branch.admin-enforced"].Status; got != model.StatusPartial {
		t.Errorf("admin-enforced status = %q, want partial", got)
	}
	// Every other check is unaffected by the bypass actor.
	for id, r := range byID {
		if id == "C02.branch.admin-enforced" {
			continue
		}
		if r.Status != model.StatusVerifiedPass {
			t.Errorf("%s status = %q, want verified-pass (unaffected by the admin bypass actor)", id, r.Status)
		}
	}
}

// TestCollect_LegacyBypassAllowanceProducesPartialRequiredReviews is the
// fixture-level counterpart to
// TestResolveEffectiveProtection_LegacyBypassAllowanceDowngradesRequiredReviews
// (effective_test.go): a real GetBranchProtection response with a non-empty
// bypass_pull_request_allowances flows all the way through Collect() to a
// partial C02.branch.required-reviews, leaving every other check
// unaffected — costs no extra API call since the field is already part of
// the branch-protection response every repo in this suite already fetches.
func TestCollect_LegacyBypassAllowanceProducesPartialRequiredReviews(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/review-bypass-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("/repos/attestward-demo/review-bypass-repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"required_pull_request_reviews": map[string]any{
				"required_approving_review_count": 1,
				"bypass_pull_request_allowances": map[string]any{
					"users": []map[string]any{{"login": "octocat"}},
				},
			},
			"required_status_checks": map[string]any{"contexts": []string{"ci/test"}},
			"enforce_admins":         map[string]any{"enabled": true},
			"allow_force_pushes":     map[string]any{"enabled": false},
			"allow_deletions":        map[string]any{"enabled": false},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/review-bypass-repo/rules/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []wireBranchRule{})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"review-bypass-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := map[string]model.CheckResult{}
	for _, r := range results {
		byID[r.CheckID] = r
	}
	if got := byID["C02.branch.required-reviews"].Status; got != model.StatusPartial {
		t.Errorf("required-reviews status = %q, want partial; reason=%q", got, byID["C02.branch.required-reviews"].Reason)
	}
	for id, r := range byID {
		if id == "C02.branch.required-reviews" {
			continue
		}
		if r.Status != model.StatusVerifiedPass {
			t.Errorf("%s status = %q, want verified-pass (unaffected by the review bypass allowance)", id, r.Status)
		}
	}
}

// TestCollect_RulesetLookupFailureOnlyAffectsAdminEnforced proves a failed
// bypass-actor lookup (GET .../rulesets/{id}) narrows to not-checkable on
// exactly the one check that needs it — the other five still resolve from
// data GetRulesForBranch already returned.
func TestCollect_RulesetLookupFailureOnlyAffectsAdminEnforced(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/flaky-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("/repos/attestward-demo/flaky-repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Branch not protected"})
	})
	mux.HandleFunc("/repos/attestward-demo/flaky-repo/rules/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, fullProtectionRules(11))
	})
	mux.HandleFunc("/repos/attestward-demo/flaky-repo/rulesets/11", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"flaky-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := map[string]model.CheckResult{}
	for _, r := range results {
		byID[r.CheckID] = r
	}
	if got := byID["C02.branch.admin-enforced"].Status; got != model.StatusNotCheckable {
		t.Errorf("admin-enforced status = %q, want not-checkable (bypass-actor lookup failed)", got)
	}
	for id, r := range byID {
		if id == "C02.branch.admin-enforced" {
			continue
		}
		if r.Status != model.StatusVerifiedPass {
			t.Errorf("%s status = %q, want verified-pass (doesn't depend on the failed ruleset lookup)", id, r.Status)
		}
	}
}

func TestCollect_PermissionGated403AllNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/secret-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"secret-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 6 {
		t.Fatalf("len(results) = %d, want 6", len(results))
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", r.CheckID, r.Status)
		}
		if r.Reason == "" {
			t.Errorf("%s Reason is empty", r.CheckID)
		}
		if len(r.Provenance) == 0 {
			t.Errorf("%s has no provenance, want the failed repo.Get call's entry attached", r.CheckID)
		}
	}
}

func TestCollect_RepoNotFound404AllNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/ghost-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"ghost-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", r.CheckID, r.Status)
		}
		if _, known := checkTitles[r.CheckID]; !known {
			t.Errorf("unexpected CheckID %q — not one of the six C02 checks", r.CheckID)
		}
	}
}

func TestCollect_MultiRepoScanProducesSixResultsEach(t *testing.T) {
	mux := http.NewServeMux()
	for _, repo := range []string{"repo-a", "repo-b"} {
		repo := repo
		mux.HandleFunc("/repos/attestward-demo/"+repo, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, map[string]any{"default_branch": "main"})
		})
		mux.HandleFunc("/repos/attestward-demo/"+repo+"/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Branch not protected"})
		})
		mux.HandleFunc("/repos/attestward-demo/"+repo+"/rules/branches/main", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, []wireBranchRule{})
		})
	}

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"repo-a", "repo-b"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 12 {
		t.Fatalf("len(results) = %d, want 12 (6 checks x 2 repos)", len(results))
	}
	byRepo := map[string]int{}
	for _, r := range results {
		byRepo[r.Scope.Repo]++
		if len(r.Provenance) == 0 {
			t.Errorf("%s/%s has no provenance", r.Scope.Repo, r.CheckID)
		}
	}
	if byRepo["repo-a"] != 6 || byRepo["repo-b"] != 6 {
		t.Errorf("byRepo = %v, want 6 each", byRepo)
	}
}

// TestCollect_PreCanceledContextProducesNotCheckableNotPanic proves a scan
// canceled before ForEachRepo ever dispatches a repo's work (see
// ForEachRepo's own pre-check in internal/collect/github/pool.go, added
// after a real bug where an already-canceled context could still let work
// through) surfaces here as six honest not-checkable results per repo
// rather than a panic, a hang, or a silently incomplete/malformed result.
func TestCollect_PreCanceledContextProducesNotCheckableNotPanic(t *testing.T) {
	// No handlers registered at all: if Collect somehow tried to make a
	// real call despite the pre-canceled context, the test would fail loud
	// (404 from the mux's default handler) rather than silently succeeding
	// for the wrong reason.
	mux := http.NewServeMux()
	c := newCollectorForServer(t, newTestServer(t, mux))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := c.Collect(ctx, collect.Scope{Org: "attestward-demo", Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 6 {
		t.Fatalf("len(results) = %d, want 6", len(results))
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", r.CheckID, r.Status)
		}
		if r.Reason == "" {
			t.Errorf("%s Reason is empty, want it to mention cancellation", r.CheckID)
		}
	}
}

func TestChecksRegistered(t *testing.T) {
	if len(checkTitles) != 6 {
		t.Fatalf("len(checkTitles) = %d, want 6", len(checkTitles))
	}
	for id := range checkTitles {
		if _, ok := collect.Lookup(id); !ok {
			t.Errorf("check %q not found in the collect.CheckMeta registry", id)
		}
	}
}

// checkWantStatuses is a human-reviewed declaration of exactly which
// statuses each check can produce (see orgsecurity's own copy of this
// pattern for the full rationale). Four of C02's six checks are binary
// pass/fail-with-not-checkable; required-reviews and admin-enforced are
// this package's two checks with a genuine partial status — required-reviews
// since issue #54 added the legacy bypass_pull_request_allowances downgrade
// (see checkRequiredReviews' switch), admin-enforced since checkAdminEnforced's
// switch predates it.
var checkWantStatuses = map[string][]model.Status{
	"C02.branch.protection-exists":      {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	"C02.branch.required-reviews":       {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
	"C02.branch.required-status-checks": {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	"C02.branch.force-push-blocked":     {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	"C02.branch.deletion-blocked":       {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	"C02.branch.admin-enforced":         {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
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

// TestAdminEnforcedRemediationRequiresRemovingAllBypassActors locks in
// that the remediation doesn't just say to "narrow" a bypass actor from
// "Always bypass" to a conditional mode — checkAdminEnforced's own switch
// only reaches verified-pass when len(eff.bypassActors) == 0; any bypass
// actor at all, even a "Pull request only" one, caps the result at
// partial. Advice that says "narrow" without also saying "remove
// entirely" leaves a reader stuck at partial forever, believing they've
// fixed it.
func TestAdminEnforcedRemediationRequiresRemovingAllBypassActors(t *testing.T) {
	remediation := checkRemediations["C02.branch.admin-enforced"]
	if !strings.Contains(strings.ToLower(remediation), "remove") {
		t.Errorf("C02.branch.admin-enforced remediation doesn't say to remove bypass actors entirely (only removing all of them reaches verified-pass): %q", remediation)
	}
	if strings.Contains(remediation, "narrowly scope") {
		t.Errorf("C02.branch.admin-enforced remediation says to \"narrowly scope\" a bypass actor — that still leaves len(bypassActors) > 0, which caps the result at partial, never verified-pass: %q", remediation)
	}
}
