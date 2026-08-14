package envseparation

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// TestGHESGateProseIsRoutedThroughTheSharedHelper pins the shared helper's
// own contract: a GHES target never sees the word "plan-gated". It does
// NOT prove this package calls the helper with scope.IsGHES set — see
// TestCollect_EnvironmentsGatedOnGHES_NamesEnterpriseServerNotPlan below
// for that, added after review found this test alone left every call
// site's actual routing unguarded: reverting scope.IsGHES to a hardcoded
// false at this package's own GatedRepoReason call site left the whole
// suite green.
func TestGHESGateProseIsRoutedThroughTheSharedHelper(t *testing.T) {
	ghes := ghcollect.GatedRepoReason(true, "3.12.4", "the feature this collector reads", "acme", "widgets")
	if strings.Contains(ghes, "plan-gated") {
		t.Errorf("GHES reason claims a plan gate: %q", ghes)
	}
	if !strings.Contains(ghes, "Enterprise Server") {
		t.Errorf("GHES reason does not name the host type: %q", ghes)
	}
}

// TestCollect_EnvironmentsGatedOnGHES_NamesEnterpriseServerNotPlan drives a
// real Collect() call with scope.IsGHES set and the environments listing
// itself 404ing — the actual condition notCheckableReason's
// GatedRepoReason branch exists for. Mutating this package's call site
// back to GatedRepoReason(false, "", ...) must fail this test.
func TestCollect_EnvironmentsGatedOnGHES_NamesEnterpriseServerNotPlan(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/acme/widgets/environments", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})

	c := newGHESCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{
		Org: "acme", Repos: []string{"widgets"}, IsGHES: true, GHESVersion: "3.12.4",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != len(checkTitles) {
		t.Fatalf("len(results) = %d, want %d", len(results), len(checkTitles))
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable; reason=%q", r.CheckID, r.Status, r.Reason)
		}
		if strings.Contains(r.Reason, "plan-gated") {
			t.Errorf("%s reason claims a plan gate on a GHES target: %q", r.CheckID, r.Reason)
		}
		if !strings.Contains(r.Reason, "Enterprise Server") {
			t.Errorf("%s reason does not name GitHub Enterprise Server: %q", r.CheckID, r.Reason)
		}
	}
}
