package vdp

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
// TestCollect_PrivateReportingGatedOnGHES_NamesEnterpriseServerNotPlan
// below for that, added after review found this test alone left the call
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

// TestCollect_PrivateReportingGatedOnGHES_NamesEnterpriseServerNotPlan
// mirrors TestCollect_PrivateReportingPlanGated404_NotCheckable but with
// scope.IsGHES set — the actual condition notCheckableReason's
// GatedRepoReason branch exists for. Mutating this package's call site
// back to GatedRepoReason(false, "", ...) must fail this test.
func TestCollect_PrivateReportingGatedOnGHES_NamesEnterpriseServerNotPlan(t *testing.T) {
	org, repo := "acme", "private-repo"
	mux := http.NewServeMux()
	registerSecurityMDLookup(t, mux, org, repo, map[string]string{repo + ":SECURITY.md": goodSecurityMD})
	registerPrivateReportingStatus(t, mux, org, repo, http.StatusNotFound)
	registerDotGithubRepoMissing(t, mux, org)

	c := newGHESCollectorForServer(t, mux)
	results, err := c.Collect(context.Background(), collect.Scope{
		Org: org, Repos: []string{repo}, IsGHES: true, GHESVersion: "3.12.4",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[privateReportingID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("private-reporting = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	if strings.Contains(got.Reason, "plan-gated") {
		t.Errorf("private-reporting reason claims a plan gate on a GHES target: %q", got.Reason)
	}
	if !strings.Contains(got.Reason, "Enterprise Server") {
		t.Errorf("private-reporting reason does not name GitHub Enterprise Server: %q", got.Reason)
	}
}
