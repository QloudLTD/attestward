package repoprotection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "github.com/sioakim/attestward/internal/collect/github"
)

func newTestClientForExport(t *testing.T, mux *http.ServeMux) *ghcollect.Client {
	t.Helper()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := ghcollect.NewClient("ghp_test-token")
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	client.REST.BaseURL = baseURL
	return client
}

// TestRequiredStatusCheckNames_MergesLegacyAndRuleset proves the exported
// helper produces the exact same merged result checkRequiredStatusChecks
// itself would, without needing a bypass-actor (ruleset detail) lookup —
// callers like C06 that only need status-check names shouldn't pay for
// that extra call.
func TestRequiredStatusCheckNames_MergesLegacyAndRuleset(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/mixed-repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"required_status_checks": map[string]any{"contexts": []string{"legacy-check"}},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/mixed-repo/rules/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []wireBranchRule{
			{Type: "required_status_checks", RulesetSourceType: "Repository", RulesetID: 1,
				Parameters: ghgithub.RequiredStatusChecksRuleParameters{RequiredStatusChecks: []*ghgithub.RuleStatusCheck{{Context: "ruleset-check"}}}},
		})
	})

	client := newTestClientForExport(t, mux)
	names, via, resp, err := RequiredStatusCheckNames(context.Background(), client, "attestward-demo", "mixed-repo", "main")
	if err != nil {
		t.Fatalf("RequiredStatusCheckNames: %v", err)
	}
	if resp != nil {
		t.Errorf("resp = %+v, want nil on success", resp)
	}
	wantNames := map[string]bool{"legacy-check": true, "ruleset-check": true}
	if len(names) != 2 {
		t.Fatalf("names = %v, want 2 entries", names)
	}
	for _, n := range names {
		if !wantNames[n] {
			t.Errorf("unexpected name %q in %v", n, names)
		}
	}
	wantVia := map[string]bool{"legacy": true, "ruleset": true}
	for _, v := range via {
		if !wantVia[v] {
			t.Errorf("unexpected via %q in %v", v, via)
		}
	}
}

// TestRequiredStatusCheckNames_NoLegacyProtectionIsNotAnError proves a 404
// on the legacy protection endpoint (meaning "no legacy protection
// configured", not a real error) doesn't abort the call — the same
// distinction collectRepo's own legacyErr handling makes.
func TestRequiredStatusCheckNames_NoLegacyProtectionIsNotAnError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/ruleset-only-repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Branch not protected"})
	})
	mux.HandleFunc("/repos/attestward-demo/ruleset-only-repo/rules/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []wireBranchRule{})
	})

	client := newTestClientForExport(t, mux)
	names, _, resp, err := RequiredStatusCheckNames(context.Background(), client, "attestward-demo", "ruleset-only-repo", "main")
	if err != nil {
		t.Fatalf("RequiredStatusCheckNames: %v", err)
	}
	if resp != nil {
		t.Errorf("resp = %+v, want nil", resp)
	}
	if len(names) != 0 {
		t.Errorf("names = %v, want empty", names)
	}
}

// TestRequiredStatusCheckNames_PermissionDenied403PropagatesError proves a
// real error (403, distinct from the 404-means-unprotected case above) is
// surfaced to the caller with its *github.Response intact, so a caller can
// classify it (permission vs. plan-gated vs. generic) the same way this
// package's own notCheckableReason does.
func TestRequiredStatusCheckNames_PermissionDenied403PropagatesError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/secret-repo/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	client := newTestClientForExport(t, mux)
	_, _, resp, err := RequiredStatusCheckNames(context.Background(), client, "attestward-demo", "secret-repo", "main")
	if err == nil {
		t.Fatal("RequiredStatusCheckNames = nil error, want an error for a 403")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("resp = %+v, want a 403 response", resp)
	}
}
