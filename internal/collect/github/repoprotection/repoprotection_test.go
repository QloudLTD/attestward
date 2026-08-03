package repoprotection

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

	ghgithub "github.com/google/go-github/v75/github"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/model"
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
	c := New("ghp_test-token", ghcollect.ClientConfig{})
	c.newClientForTest = func(token string) *ghcollect.Client {
		// Runs inside ForEachRepo's worker goroutines, never the test's own
		// goroutine — t.Fatalf there would only abort that worker (via
		// runtime.Goexit), not the test, so a genuine parse failure must be
		// reported with Errorf instead.
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

// TestCollect_GHESHost_RulesetOnlyRepoAllChecksPass mirrors
// TestCollect_RulesetOnlyRepoAllChecksPass against a GHES-shaped base URL
// (issue #13's GHES epic) — this collector's own endpoints were audited as
// ghcollect.GHESNoteSupported (see repoprotection.go's init()): basic repo/
// branch-protection/rulesets REST surface, not GitHub Advanced Security
// gated, expected to work unmodified on GHES. Alongside (not replacing)
// the github.com scenario, so both drift together.
func TestCollect_GHESHost_RulesetOnlyRepoAllChecksPass(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/attestward-demo/good-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("/api/v3/repos/attestward-demo/good-repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Branch not protected"})
	})
	mux.HandleFunc("/api/v3/repos/attestward-demo/good-repo/rules/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, fullProtectionRules(1))
	})
	mux.HandleFunc("/api/v3/repos/attestward-demo/good-repo/rulesets/1", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"id": 1, "name": "main-protection"})
	})

	c := newGHESCollectorForServer(t, newTestServer(t, mux))
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
		for _, p := range r.Provenance {
			if !strings.HasPrefix(p.Endpoint, "/api/v3") {
				t.Errorf("%s provenance Endpoint = %q, want a /api/v3 prefix (GHES routing)", r.CheckID, p.Endpoint)
			}
		}
	}
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

// rubricState is one fixture world for TestRubricsMatchObservedBehaviour.
// Every check in this collector bottoms out at the same three upstream reads
// — GET /repos/{org}/{repo}, GET .../branches/main/protection and
// GET .../rules/branches/main — so those three plus the per-ruleset
// bypass-actor lookup are the whole input surface.
type rubricState struct {
	name string
	// repoStatus non-200 short-circuits collectRepo before either
	// protection read happens, which is the only route to all six checks
	// reporting not-checkable together.
	repoStatus int
	// legacyStatus 404 is not an error: collectRepo reads it as "no legacy
	// protection configured", a normal input for a ruleset-only repo.
	legacyStatus  int
	legacy        map[string]any
	rules         []wireBranchRule
	rulesetID     int64
	rulesetStatus int
	ruleset       map[string]any
	want          map[string]model.Status
}

func (st rubricState) mux(t *testing.T, org, repo string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+org+"/"+repo, func(w http.ResponseWriter, _ *http.Request) {
		if st.repoStatus != http.StatusOK {
			writeJSON(t, w, st.repoStatus, map[string]any{"message": "nope"})
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		if st.legacyStatus != http.StatusOK {
			writeJSON(t, w, st.legacyStatus, map[string]any{"message": "Branch not protected"})
			return
		}
		writeJSON(t, w, http.StatusOK, st.legacy)
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/rules/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		// A nil slice would encode as JSON null; the rules endpoint always
		// returns an array, so send one even when it is empty.
		rules := st.rules
		if rules == nil {
			rules = []wireBranchRule{}
		}
		writeJSON(t, w, http.StatusOK, rules)
	})
	if st.rulesetID != 0 {
		mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/rulesets/%d", org, repo, st.rulesetID), func(w http.ResponseWriter, _ *http.Request) {
			if st.rulesetStatus != http.StatusOK {
				writeJSON(t, w, st.rulesetStatus, map[string]any{"message": "Forbidden"})
				return
			}
			writeJSON(t, w, http.StatusOK, st.ruleset)
		})
	}
	return mux
}

// reviewRuleWithCount builds the ruleset-side pull-request rule with an
// explicit required_approving_review_count, so the `< 1` boundary in
// applyRules can be exercised with a rule that exists and still requires
// nothing (GitHub allows a PR rule with zero required approvals).
func reviewRuleWithCount(rulesetID int64, count int) wireBranchRule {
	return wireBranchRule{
		Type: "pull_request", RulesetSourceType: "Repository", RulesetID: rulesetID,
		Parameters: ghgithub.PullRequestRuleParameters{RequiredApprovingReviewCount: count},
	}
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue #10).
//
// # Why this matrix is shaped the way it is
//
// All six C02 checks read ONE merged effectiveProtection value built from the
// SAME three responses, and four of them (status-checks, force-push,
// deletion, plus protection-exists) are single-boolean reads off that struct.
// That is a standing conflation risk with nothing structural against it: a
// matrix built only from "fully protected" and "fully unprotected" fixtures —
// which is what the older tests in this file are — reaches every status while
// moving all six checks in lockstep, so it could not tell
// checkDeletionBlocked reading eff.deletionBlocked apart from it reading
// eff.forcePushBlocked. The two fields have identical shape and are set side
// by side in both places they are derived.
//
// ⚠ "Both places" is the part that is easy to under-test, and this matrix got
// it wrong on the first pass. forcePushBlocked and deletionBlocked are
// derived TWICE, in two independent code paths: from legacy protection's
// allow_force_pushes/allow_deletions booleans in applyLegacy, and from the
// presence of a ruleset's NonFastForward/Deletion rule lists in applyRules.
// Splitting them on the legacy side does nothing for the ruleset side. Every
// ruleset-bearing state here except 13 uses fullProtectionRules, which sets
// all four rule types at once — so before state 13 was made asymmetric, the
// two ruleset-side derivations never disagreed anywhere in the package and
// swapping which rule list each read survived the ENTIRE suite, in both
// directions.
//
// So states 2-4 and 13 exist to make same-shaped checks disagree, and 13
// carries the ruleset half of that job alone:
//
//	state  2: legacy exists, permits everything -> exists PASS, other five FAIL
//	state  3: legacy blocks force pushes, allows deletions, reviews yes, checks no
//	state  4: legacy blocks deletions, allows force pushes, checks yes, reviews no
//	state 13: RULESET blocks force pushes and NOT deletion (a non_fast_forward
//	          rule with no deletion rule beside it), with a PR rule requiring
//	          ZERO approvals
//
// Every pair among {protection-exists, required-reviews,
// required-status-checks, force-push-blocked, deletion-blocked} disagrees in
// at least one state on EACH derivation path, and admin-enforced disagrees
// with all five in states 9, 10 and 12.
//
// The three not-obvious admin-enforced states are each a documented branch
// that a smaller matrix would leave unreached:
//
//	state  9: legacy exists with enforce_admins=false while a ruleset cleanly
//	          binds admins -> FAIL, because resolveEffectiveProtection requires
//	          EVERY contributing regime to bind admins, not just one
//	state 12: the same, plus a CONDITIONAL bypass actor -> still FAIL. This is
//	          the exact scenario the historical len(bypassActors) > 0 bug got
//	          backwards (adding a merely-conditional actor improved the
//	          reported status from fail to partial)
//	state 10: the bypass-actor lookup itself 403s -> admin-enforced alone goes
//	          not-checkable while the other five still resolve
//
// # Confirmed by mutation, not assumed
//
// Each of these was injected into the production code and traced to the exact
// states that caught it:
//
//   - checkDeletionBlocked reading eff.forcePushBlocked (the conflation this
//     matrix is built against): caught by states 3, 4 and 13, in both
//     directions, and by nothing else in the package's older lockstep
//     fixtures.
//   - applyRules' ruleset-side derivations swapped — forcePushBlocked keyed
//     off rules.Deletion, and separately deletionBlocked keyed off
//     rules.NonFastForward: each caught by state 13 ALONE. Both survived the
//     entire package suite until state 13 dropped its deletion rule, which is
//     the whole reason it no longer mirrors state 4 exactly.
//   - checkRequiredStatusChecks reading eff.reviewRequired instead of
//     len(eff.statusCheckNames): caught by states 3 and 4. NOT by state 13,
//     where reviews and status checks are both absent and so agree anyway —
//     which is the point: only the states that make them disagree can tell
//     the two apart.
//   - applyLegacy's `RequiredApprovingReviewCount >= 1` weakened to `>= 0`:
//     caught by state 4 alone, the only state whose legacy protection carries
//     a required_pull_request_reviews block that requires zero approvals.
//   - applyRules' `RequiredApprovingReviewCount < 1 { continue }` weakened to
//     `< 0`: caught by state 13 alone, the ruleset-side counterpart of the
//     legacy boundary above.
//   - resolveEffectiveProtection's legacyBindsAdmins guard dropped (the OR-vs-
//     AND bug its own comment records): caught by states 9 and 12.
//   - checkAdminEnforced's `case eff.hasAlwaysBypass` reverted to
//     `case len(eff.bypassActors) > 0`: caught by state 12 alone — it is the
//     only state where admins are unbound AND the sole bypass actor is
//     conditional, which is precisely the shape the bug misread.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	const org, repo = "attestward-demo", "svc"

	states := []rubricState{
		{
			// Nothing protects the branch under either regime: the only
			// route to protection-exists reporting verified-fail.
			name:         "no legacy protection and no ruleset",
			repoStatus:   http.StatusOK,
			legacyStatus: http.StatusNotFound,
			want: map[string]model.Status{
				"C02.branch.protection-exists":      model.StatusVerifiedFail,
				"C02.branch.required-reviews":       model.StatusVerifiedFail,
				"C02.branch.required-status-checks": model.StatusVerifiedFail,
				"C02.branch.force-push-blocked":     model.StatusVerifiedFail,
				"C02.branch.deletion-blocked":       model.StatusVerifiedFail,
				"C02.branch.admin-enforced":         model.StatusVerifiedFail,
			},
		},
		{
			// applyLegacy sets exists unconditionally, so a protection rule
			// that grants nothing still counts as "protection exists". This
			// is the state that splits protection-exists from all five
			// substantive checks at once.
			name:         "legacy protection exists but permits everything",
			repoStatus:   http.StatusOK,
			legacyStatus: http.StatusOK,
			legacy: map[string]any{
				"enforce_admins":     map[string]any{"enabled": false},
				"allow_force_pushes": map[string]any{"enabled": true},
				"allow_deletions":    map[string]any{"enabled": true},
			},
			want: map[string]model.Status{
				"C02.branch.protection-exists":      model.StatusVerifiedPass,
				"C02.branch.required-reviews":       model.StatusVerifiedFail,
				"C02.branch.required-status-checks": model.StatusVerifiedFail,
				"C02.branch.force-push-blocked":     model.StatusVerifiedFail,
				"C02.branch.deletion-blocked":       model.StatusVerifiedFail,
				"C02.branch.admin-enforced":         model.StatusVerifiedFail,
			},
		},
		{
			name:         "legacy blocks force pushes and requires reviews, but allows deletion and requires no checks",
			repoStatus:   http.StatusOK,
			legacyStatus: http.StatusOK,
			legacy: map[string]any{
				"required_pull_request_reviews": map[string]any{"required_approving_review_count": 2},
				"enforce_admins":                map[string]any{"enabled": true},
				"allow_force_pushes":            map[string]any{"enabled": false},
				"allow_deletions":               map[string]any{"enabled": true},
			},
			want: map[string]model.Status{
				"C02.branch.protection-exists":      model.StatusVerifiedPass,
				"C02.branch.required-reviews":       model.StatusVerifiedPass,
				"C02.branch.required-status-checks": model.StatusVerifiedFail,
				"C02.branch.force-push-blocked":     model.StatusVerifiedPass,
				"C02.branch.deletion-blocked":       model.StatusVerifiedFail,
				"C02.branch.admin-enforced":         model.StatusVerifiedPass,
			},
		},
		{
			// The exact mirror of the state above, so neither
			// force-push/deletion nor reviews/status-checks can be swapped
			// for the other without a failure in one direction or the
			// other. required_pull_request_reviews is PRESENT here with a
			// count of zero rather than omitted, which is what exercises
			// applyLegacy's `>= 1` boundary.
			name:         "legacy blocks deletion and requires checks, but allows force push and requires zero approvals",
			repoStatus:   http.StatusOK,
			legacyStatus: http.StatusOK,
			legacy: map[string]any{
				"required_pull_request_reviews": map[string]any{"required_approving_review_count": 0},
				"required_status_checks":        map[string]any{"contexts": []string{"ci/test"}},
				"enforce_admins":                map[string]any{"enabled": true},
				"allow_force_pushes":            map[string]any{"enabled": true},
				"allow_deletions":               map[string]any{"enabled": false},
			},
			want: map[string]model.Status{
				"C02.branch.protection-exists":      model.StatusVerifiedPass,
				"C02.branch.required-reviews":       model.StatusVerifiedFail,
				"C02.branch.required-status-checks": model.StatusVerifiedPass,
				"C02.branch.force-push-blocked":     model.StatusVerifiedFail,
				"C02.branch.deletion-blocked":       model.StatusVerifiedPass,
				"C02.branch.admin-enforced":         model.StatusVerifiedPass,
			},
		},
		{
			// The only route to required-reviews reporting partial: legacy
			// bypass_pull_request_allowances names someone who can skip the
			// review requirement outright. A ruleset has no equivalent field.
			name:         "legacy requires reviews but names a bypass allowance",
			repoStatus:   http.StatusOK,
			legacyStatus: http.StatusOK,
			legacy: map[string]any{
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
			},
			want: map[string]model.Status{
				"C02.branch.protection-exists":      model.StatusVerifiedPass,
				"C02.branch.required-reviews":       model.StatusPartial,
				"C02.branch.required-status-checks": model.StatusVerifiedPass,
				"C02.branch.force-push-blocked":     model.StatusVerifiedPass,
				"C02.branch.deletion-blocked":       model.StatusVerifiedPass,
				"C02.branch.admin-enforced":         model.StatusVerifiedPass,
			},
		},
		{
			// Ruleset-only, zero bypass actors: the clean all-pass world,
			// and the one that proves admin-enforced can pass with no legacy
			// protection present at all.
			name:          "ruleset-only repo with no bypass actors",
			repoStatus:    http.StatusOK,
			legacyStatus:  http.StatusNotFound,
			rules:         fullProtectionRules(21),
			rulesetID:     21,
			rulesetStatus: http.StatusOK,
			ruleset:       map[string]any{"id": 21, "name": "main-protection"},
			want: map[string]model.Status{
				"C02.branch.protection-exists":      model.StatusVerifiedPass,
				"C02.branch.required-reviews":       model.StatusVerifiedPass,
				"C02.branch.required-status-checks": model.StatusVerifiedPass,
				"C02.branch.force-push-blocked":     model.StatusVerifiedPass,
				"C02.branch.deletion-blocked":       model.StatusVerifiedPass,
				"C02.branch.admin-enforced":         model.StatusVerifiedPass,
			},
		},
		{
			// admin-enforced partial, route (a): admins ARE bound by every
			// contributing regime, but a conditional bypass actor exists.
			name:          "ruleset with a conditional bypass actor",
			repoStatus:    http.StatusOK,
			legacyStatus:  http.StatusNotFound,
			rules:         fullProtectionRules(22),
			rulesetID:     22,
			rulesetStatus: http.StatusOK,
			ruleset: map[string]any{
				"id": 22, "name": "main-protection",
				"bypass_actors": []map[string]any{
					{"actor_type": "Team", "bypass_mode": "pull_request"},
				},
			},
			want: map[string]model.Status{
				"C02.branch.protection-exists":      model.StatusVerifiedPass,
				"C02.branch.required-reviews":       model.StatusVerifiedPass,
				"C02.branch.required-status-checks": model.StatusVerifiedPass,
				"C02.branch.force-push-blocked":     model.StatusVerifiedPass,
				"C02.branch.deletion-blocked":       model.StatusVerifiedPass,
				"C02.branch.admin-enforced":         model.StatusPartial,
			},
		},
		{
			// admin-enforced partial, route (b): an unconditional bypass
			// actor, which blocks adminEnforced from ever being set and is
			// reported through a different arm of the same switch.
			name:          "ruleset with an unconditional bypass actor",
			repoStatus:    http.StatusOK,
			legacyStatus:  http.StatusNotFound,
			rules:         fullProtectionRules(23),
			rulesetID:     23,
			rulesetStatus: http.StatusOK,
			ruleset: map[string]any{
				"id": 23, "name": "main-protection",
				"bypass_actors": []map[string]any{
					{"actor_type": "OrganizationAdmin", "bypass_mode": "always"},
				},
			},
			want: map[string]model.Status{
				"C02.branch.protection-exists":      model.StatusVerifiedPass,
				"C02.branch.required-reviews":       model.StatusVerifiedPass,
				"C02.branch.required-status-checks": model.StatusVerifiedPass,
				"C02.branch.force-push-blocked":     model.StatusVerifiedPass,
				"C02.branch.deletion-blocked":       model.StatusVerifiedPass,
				"C02.branch.admin-enforced":         model.StatusPartial,
			},
		},
		{
			// Both regimes protect the branch, but legacy exempts admins.
			// admin-enforced alone fails while the other five pass — the
			// ruleset's clean admin binding must not paper over legacy's
			// exemption.
			name:          "legacy exempts admins while a ruleset binds them",
			repoStatus:    http.StatusOK,
			legacyStatus:  http.StatusOK,
			legacy:        map[string]any{"enforce_admins": map[string]any{"enabled": false}},
			rules:         fullProtectionRules(24),
			rulesetID:     24,
			rulesetStatus: http.StatusOK,
			ruleset:       map[string]any{"id": 24, "name": "main-protection"},
			want: map[string]model.Status{
				"C02.branch.protection-exists":      model.StatusVerifiedPass,
				"C02.branch.required-reviews":       model.StatusVerifiedPass,
				"C02.branch.required-status-checks": model.StatusVerifiedPass,
				"C02.branch.force-push-blocked":     model.StatusVerifiedPass,
				"C02.branch.deletion-blocked":       model.StatusVerifiedPass,
				"C02.branch.admin-enforced":         model.StatusVerifiedFail,
			},
		},
		{
			// The bypass-actor lookup is the one upstream read only
			// admin-enforced depends on, so its failure must narrow to that
			// check alone rather than taking the collector down with it.
			name:          "ruleset bypass-actor lookup forbidden",
			repoStatus:    http.StatusOK,
			legacyStatus:  http.StatusNotFound,
			rules:         fullProtectionRules(25),
			rulesetID:     25,
			rulesetStatus: http.StatusForbidden,
			want: map[string]model.Status{
				"C02.branch.protection-exists":      model.StatusVerifiedPass,
				"C02.branch.required-reviews":       model.StatusVerifiedPass,
				"C02.branch.required-status-checks": model.StatusVerifiedPass,
				"C02.branch.force-push-blocked":     model.StatusVerifiedPass,
				"C02.branch.deletion-blocked":       model.StatusVerifiedPass,
				"C02.branch.admin-enforced":         model.StatusNotCheckable,
			},
		},
		{
			// The repo read itself fails, so nothing downstream ran: the
			// only route to all six reporting not-checkable together.
			name:       "repo read forbidden",
			repoStatus: http.StatusForbidden,
			want: map[string]model.Status{
				"C02.branch.protection-exists":      model.StatusNotCheckable,
				"C02.branch.required-reviews":       model.StatusNotCheckable,
				"C02.branch.required-status-checks": model.StatusNotCheckable,
				"C02.branch.force-push-blocked":     model.StatusNotCheckable,
				"C02.branch.deletion-blocked":       model.StatusNotCheckable,
				"C02.branch.admin-enforced":         model.StatusNotCheckable,
			},
		},
		{
			// Legacy exempts admins AND the only bypass actor is
			// conditional. The result must still be verified-fail: admins
			// already aren't bound by every contributing regime, and a
			// conditional actor doesn't upgrade that to partial.
			name:          "legacy exempts admins and the ruleset has a conditional bypass actor",
			repoStatus:    http.StatusOK,
			legacyStatus:  http.StatusOK,
			legacy:        map[string]any{"enforce_admins": map[string]any{"enabled": false}},
			rules:         fullProtectionRules(26),
			rulesetID:     26,
			rulesetStatus: http.StatusOK,
			ruleset: map[string]any{
				"id": 26, "name": "main-protection",
				"bypass_actors": []map[string]any{
					{"actor_type": "Team", "bypass_mode": "pull_request"},
				},
			},
			want: map[string]model.Status{
				"C02.branch.protection-exists":      model.StatusVerifiedPass,
				"C02.branch.required-reviews":       model.StatusVerifiedPass,
				"C02.branch.required-status-checks": model.StatusVerifiedPass,
				"C02.branch.force-push-blocked":     model.StatusVerifiedPass,
				"C02.branch.deletion-blocked":       model.StatusVerifiedPass,
				"C02.branch.admin-enforced":         model.StatusVerifiedFail,
			},
		},
		{
			// The ruleset-side mirror of state 4, and the ONLY state whose
			// ruleset carries a non_fast_forward rule WITHOUT a deletion
			// rule. Every other ruleset-bearing state uses
			// fullProtectionRules, which sets all four rule types at once —
			// so without this asymmetry the two ruleset-side derivations in
			// applyRules move together everywhere and swapping which rule
			// list each reads survives the whole package suite (confirmed by
			// injection; see the mutation notes below). The pull-request
			// rule requires zero approvals, which is what exercises
			// applyRules' own `< 1` boundary.
			name:         "ruleset blocks force pushes but not deletion, and requires zero approvals",
			repoStatus:   http.StatusOK,
			legacyStatus: http.StatusNotFound,
			rules: []wireBranchRule{
				reviewRuleWithCount(27, 0),
				{Type: "non_fast_forward", RulesetSourceType: "Repository", RulesetID: 27},
			},
			rulesetID:     27,
			rulesetStatus: http.StatusOK,
			ruleset:       map[string]any{"id": 27, "name": "main-protection"},
			want: map[string]model.Status{
				"C02.branch.protection-exists":      model.StatusVerifiedPass,
				"C02.branch.required-reviews":       model.StatusVerifiedFail,
				"C02.branch.required-status-checks": model.StatusVerifiedFail,
				"C02.branch.force-push-blocked":     model.StatusVerifiedPass,
				"C02.branch.deletion-blocked":       model.StatusVerifiedFail,
				"C02.branch.admin-enforced":         model.StatusVerifiedPass,
			},
		},
	}

	// Guards the states above against the fixture drifting into something
	// that no longer splits the same-shaped checks apart.
	if got := len(states); got != 13 {
		t.Fatalf("len(states) = %d, want 13 — this matrix's whole point is the splitting states; see the doc comment before adding or removing one", got)
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
