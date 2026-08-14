package secretshygiene

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// TestCollect_PublicRepoAdvancedSecurityGatedOnGHES_NamesEnterpriseServer
// drives a real Collect() call for a public repo with scope.IsGHES set —
// the actual condition advancedSecurityPublicRepoReason's GHES branch
// exists for. This package does not use the shared ghcollect.GatedRepoReason
// helper (its licensing model differs enough to need its own reason
// functions), so the generic per-package "shared helper" test other
// packages carry does not apply here and would test a function this
// package never calls. Mutating this package's advancedSecurityPublicRepoReason
// or securityAndAnalysisAbsentReason back to their github.com-only branch
// must fail the corresponding test below.
func TestCollect_PublicRepoAdvancedSecurityGatedOnGHES_NamesEnterpriseServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/orgs/acme", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"login": "acme"})
	})
	mux.HandleFunc("/api/v3/repos/acme/widgets", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"private": false,
			"security_and_analysis": map[string]any{
				"secret_scanning":                 map[string]any{"status": "enabled"},
				"secret_scanning_push_protection": map[string]any{"status": "enabled"},
			},
		})
	})
	mux.HandleFunc("/api/v3/repos/acme/widgets/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNoContent, nil)
	})

	c := newGHESCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{
		Org: "acme", Repos: []string{"widgets"}, IsGHES: true, GHESVersion: "3.12.4",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)["C04.secrets.advanced-security"]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("advanced-security status = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	if strings.Contains(got.Reason, "GHAS licensing only gates private-repo features") {
		t.Errorf("reason asserts the github.com public-repo exemption on a GHES target: %q", got.Reason)
	}
	if !strings.Contains(got.Reason, "Enterprise Server") {
		t.Errorf("reason does not name GitHub Enterprise Server: %q", got.Reason)
	}
}

// TestCollect_SecurityAndAnalysisAbsentGatedOnGHES_NamesEnterpriseServer
// drives a real Collect() call for a private repo whose response has no
// security_and_analysis block at all, with scope.IsGHES set — the actual
// condition securityAndAnalysisAbsentReason's GHES branch exists for.
func TestCollect_SecurityAndAnalysisAbsentGatedOnGHES_NamesEnterpriseServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/orgs/acme", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"login": "acme"})
	})
	mux.HandleFunc("/api/v3/repos/acme/widgets", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"private": true})
	})
	mux.HandleFunc("/api/v3/repos/acme/widgets/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNoContent, nil)
	})

	c := newGHESCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{
		Org: "acme", Repos: []string{"widgets"}, IsGHES: true, GHESVersion: "3.12.4",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, id := range []string{"C04.secrets.scanning-enabled", "C04.secrets.push-protection", "C04.secrets.advanced-security"} {
		got := byID(results)[id]
		if got.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable; reason=%q", id, got.Status, got.Reason)
		}
		if strings.Contains(got.Reason, "plan-gated") {
			t.Errorf("%s reason claims a plan gate on a GHES target: %q", id, got.Reason)
		}
		if !strings.Contains(got.Reason, "Enterprise Server") {
			t.Errorf("%s reason does not name GitHub Enterprise Server: %q", id, got.Reason)
		}
	}
}
