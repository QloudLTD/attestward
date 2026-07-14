package orgsecurity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/model"
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
