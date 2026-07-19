package orgsecurity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/sioakim/attestward/internal/collect"
	ghcollect "github.com/sioakim/attestward/internal/collect/github"
	"github.com/sioakim/attestward/internal/model"
)

// newTestCollector points a real ghcollect.Client at a local httptest
// server via client.REST.BaseURL, the same pattern
// cmd/attestor/scanorgcheck_test.go uses — ghfixture's Transport can't be
// wired in from outside package github (its underlying construction needs
// the unexported provenance/rate-limit transports), so a real loopback
// server exercises the full auth+provenance+rate-limit chain unmodified.
func newTestCollector(t *testing.T, handler http.Handler) *Collector {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client := ghcollect.NewClient("ghp_test-token")
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	client.REST.BaseURL = baseURL

	return New(client)
}

// writeJSON runs inside an httptest.Server handler goroutine, never the
// test's own goroutine — t.Fatalf there would only abort that handler
// goroutine (via runtime.Goexit), not the test, so a genuine encode failure
// must be reported with Errorf instead.
func writeJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode fixture response: %v", err)
	}
}

func TestCollect_GoodOrgAllChecksPass(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/attestor-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"two_factor_requirement_enabled":         true,
			"default_repository_permission":          "read",
			"members_can_create_public_repositories": false,
		})
	})
	mux.HandleFunc("/orgs/attestor-demo/members", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{})
	})

	c := newTestCollector(t, mux)
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo"})
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
	}
}

func TestCollect_BadOrgAllChecksFail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/attestor-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"two_factor_requirement_enabled":         false,
			"default_repository_permission":          "write",
			"members_can_create_public_repositories": true,
		})
	})
	mux.HandleFunc("/orgs/attestor-demo/members", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{
			{"login": "alice"}, {"login": "bob"},
		})
	})

	c := newTestCollector(t, mux)
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := map[string]model.CheckResult{}
	for _, r := range results {
		byID[r.CheckID] = r
	}
	for id, r := range byID {
		if r.Status != model.StatusVerifiedFail {
			t.Errorf("%s status = %q, want verified-fail; reason=%q", id, r.Status, r.Reason)
		}
	}

	membersResult := byID["C01.org.members-without-2fa"]
	if membersResult.Facts["members_without_2fa_count"] != 2 {
		t.Errorf("members_without_2fa_count = %v, want 2", membersResult.Facts["members_without_2fa_count"])
	}
}

// TestCollect_MembersWithout2FA_NeverLeaksNames is the privacy rule from
// the issue: store the count, never the member list. Confirms no field
// anywhere in the result contains a member login/name.
func TestCollect_MembersWithout2FA_NeverLeaksNames(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/attestor-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"two_factor_requirement_enabled":         true,
			"default_repository_permission":          "read",
			"members_can_create_public_repositories": false,
		})
	})
	mux.HandleFunc("/orgs/attestor-demo/members", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{
			{"login": "alice-should-never-appear"}, {"login": "bob-should-never-appear"},
		})
	})

	c := newTestCollector(t, mux)
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range results {
		if r.CheckID != "C01.org.members-without-2fa" {
			continue
		}
		if len(r.Facts) != 1 {
			t.Fatalf("Facts = %v, want exactly {members_without_2fa_count: N}", r.Facts)
		}
		if _, ok := r.Facts["members_without_2fa_count"]; !ok {
			t.Fatal("Facts missing members_without_2fa_count")
		}
	}
}

func TestCollect_MembersWithout2FA_Paginates(t *testing.T) {
	page1 := make([]map[string]any, 100)
	for i := range page1 {
		page1[i] = map[string]any{"login": "user"}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/attestor-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"two_factor_requirement_enabled":         true,
			"default_repository_permission":          "read",
			"members_can_create_public_repositories": false,
		})
	})
	mux.HandleFunc("/orgs/attestor-demo/members", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			writeJSON(t, w, http.StatusOK, []map[string]any{{"login": "user"}})
			return
		}
		w.Header().Set("Link", `<https://api.github.com/orgs/attestor-demo/members?page=2>; rel="next"`)
		writeJSON(t, w, http.StatusOK, page1)
	})

	c := newTestCollector(t, mux)
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range results {
		if r.CheckID != "C01.org.members-without-2fa" {
			continue
		}
		if r.Facts["members_without_2fa_count"] != 101 {
			t.Errorf("members_without_2fa_count = %v, want 101 (both pages counted)", r.Facts["members_without_2fa_count"])
		}
		if len(r.Provenance) != 2 {
			t.Errorf("len(Provenance) = %d, want 2 (one per page)", len(r.Provenance))
		}
	}
}

func TestCollect_PermissionGated403AllNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/attestor-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newTestCollector(t, mux)
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo"})
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
		if r.Reason == "" {
			t.Errorf("%s Reason is empty, want an actionable explanation", r.CheckID)
		}
		// The org.Get call that produced the 403 is itself real, auditable
		// evidence backing Reason above — a not-checkable claim with no
		// provenance would be unaudited.
		if len(r.Provenance) == 0 {
			t.Errorf("%s has no provenance, want the failed org.Get call's entry attached", r.CheckID)
		}
	}
}

func TestCollect_UserAccountNotOrg404AllNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/some-user", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})

	c := newTestCollector(t, mux)
	results, err := c.Collect(context.Background(), collect.Scope{Org: "some-user"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", r.CheckID, r.Status)
		}
		if len(r.Provenance) == 0 {
			t.Errorf("%s has no provenance, want the failed org.Get call's entry attached", r.CheckID)
		}
	}
	// Every result must carry one of the four REAL check IDs, not a
	// generic collector-level ID — otherwise the rollup can't resolve them
	// against mappings/ssdf-800-218.yaml's checks[] lists (see Collect's
	// doc comment).
	for _, r := range results {
		if _, known := checkTitles[r.CheckID]; !known {
			t.Errorf("unexpected CheckID %q — not one of the four C01 checks", r.CheckID)
		}
	}
}

// TestCollect_KnownUserAccountSkipsAPICallEntirely proves the issue #102
// short-circuit: when the orchestrator already knows (from preflight)
// scope.AccountType is collect.AccountTypeUser, Collect must not attempt
// Organizations.Get at all — a handler that fails the test if hit is the
// only way to prove "no call was made", as opposed to
// TestCollect_UserAccountNotOrg404AllNotCheckable above, which proves the
// OLDER fallback behavior for when AccountType is unknown and the call is
// attempted and 404s.
func TestCollect_KnownUserAccountSkipsAPICallEntirely(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected API call %s %s — a known user-account target must short-circuit before any org-scoped call", r.Method, r.URL.Path)
	})

	c := newTestCollector(t, mux)
	results, err := c.Collect(context.Background(), collect.Scope{Org: "sioakim", AccountType: collect.AccountTypeUser})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != len(checkTitles) {
		t.Fatalf("len(results) = %d, want %d (one per registered check)", len(results), len(checkTitles))
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", r.CheckID, r.Status)
		}
		if !containsAll(r.Reason, "sioakim", "personal", "not an organization") {
			t.Errorf("%s reason = %q, want it to name the account and explain it's personal, not an organization", r.CheckID, r.Reason)
		}
		if _, known := checkTitles[r.CheckID]; !known {
			t.Errorf("unexpected CheckID %q — not one of the four C01 checks", r.CheckID)
		}
		// model.CheckResult.Provenance is `json:"provenance"` with no
		// omitempty, and the evidence-pack schema requires it as an array
		// — a nil slice marshals to JSON null, which fails pre-write
		// schema validation and would abort attestor scan entirely for
		// any user-account target (found in Fable review of PR #103).
		if r.Provenance == nil {
			t.Errorf("%s Provenance is nil, want a non-nil (possibly empty) slice — a nil Provenance marshals to JSON null and fails the evidence-pack schema's required array type", r.CheckID)
		}
	}
}

func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

func TestCollect_MissingFieldIsNotCheckableNotFalse(t *testing.T) {
	// The org response omits two_factor_requirement_enabled entirely (nil
	// pointer after JSON unmarshal) — must not be silently read as "false"
	// (2FA not required), which would be a fabricated verified-fail instead
	// of an honest not-checkable.
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/attestor-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"default_repository_permission":          "read",
			"members_can_create_public_repositories": false,
		})
	})
	mux.HandleFunc("/orgs/attestor-demo/members", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{})
	})

	c := newTestCollector(t, mux)
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range results {
		if r.CheckID == "C01.org.2fa-required" && r.Status != model.StatusNotCheckable {
			t.Errorf("2fa-required status = %q, want not-checkable when the field is absent from the API response", r.Status)
		}
	}
}

func TestCollect_ProvenanceRecordedForEveryResult(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/attestor-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"two_factor_requirement_enabled":         true,
			"default_repository_permission":          "read",
			"members_can_create_public_repositories": false,
		})
	})
	mux.HandleFunc("/orgs/attestor-demo/members", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{})
	})

	c := newTestCollector(t, mux)
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range results {
		if len(r.Provenance) == 0 {
			t.Errorf("%s has no provenance", r.CheckID)
		}
	}
}

// TestCollect_RegistersAllFourChecks proves the init()-registered CheckMeta
// entries match the same four check IDs Collect() actually produces — so
// `attestor checks list` never shows C01 as UNMAPPED.
func TestCollect_RegistersAllFourChecks(t *testing.T) {
	for id := range checkTitles {
		if _, ok := collect.Lookup(id); !ok {
			t.Errorf("check %q not found in the collect.CheckMeta registry", id)
		}
	}
	if len(checkTitles) != 4 {
		t.Fatalf("len(checkTitles) = %d, want 4", len(checkTitles))
	}
}

// checkWantStatuses is a human-reviewed declaration of exactly which
// statuses each check can produce — there's no structural way to derive
// this from the code, so it has to be a maintained expectation, checked
// against checkRubrics' actual keys below. All four C01 checks are binary
// pass/fail with a not-checkable fallback (see checkRubrics' own doc
// comment); this won't be true package-uniformly once other collectors
// with StatusPartial checks are backfilled — each of those needs its own
// per-check entry here, not a copy of this one.
var checkWantStatuses = map[string][]model.Status{
	"C01.org.2fa-required":              {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	"C01.org.members-without-2fa":       {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	"C01.org.default-repo-permission":   {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	"C01.org.members-can-create-public": {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
}

var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) /`)

// TestCollect_RegisteredMetadataCompleteForChecksReference proves every
// check registers the fields issue #30's checks-reference generator
// depends on, and that the data is trustworthy, not just present:
//   - Rubric has EXACTLY the entries checkWantStatuses declares — missing
//     an entry silently breaks the reference, but a spurious extra entry is
//     worse: it would generate documented prose claiming this check can
//     produce a status it never actually will, exactly the kind of
//     invented claim this project's ethos forbids (see CLAUDE.md's rule on
//     never inventing SSDF/CISA citations, extended here to rubric claims).
//   - every Endpoints entry starts with GET or HEAD — this project is
//     read-only forever (ADR-0004); a check registering a write verb here
//     would be a real, structural violation of that invariant, not just a
//     docs bug, so this test enforces it at the metadata layer too.
//   - checkRubrics/checkEndpoints have exactly as many entries as
//     checkTitles, so a typo'd map key (present in the map, but under the
//     wrong ID, so silently absent from the one that needed it) fails
//     loudly instead of just showing up as a missing-entry error on a
//     completely different check ID.
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
