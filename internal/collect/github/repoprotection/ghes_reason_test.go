package repoprotection

import (
	"context"
	"net/http"
	"strings"
	"testing"

	ghgithub "github.com/google/go-github/v75/github"

	"gitlab.com/sioakeim/attestward/internal/collect"

	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// TestGHESGateProseIsRoutedThroughTheSharedHelper is the per-collector half
// of a guard that has now failed review three times in a row: the fix for
// github.com-flavoured gate prose on a GitHub Enterprise Server target kept
// being revertable with a green suite, because nothing asserted the GHES
// branch was reached from this package at all.
//
// It deliberately tests the shared helper's contract rather than mocking a
// whole collector run: what must hold is that a GHES target never sees the
// word "plan-gated" — GHES has no per-org or per-repo plan tier — and that
// this package is wired to the helper that guarantees it. If a future edit
// hand-rolls a reason here again, the reviewer's grep for "plan-gated"
// outside gatekind.go is what catches it; this pins the helper's own
// behaviour so the reason text cannot silently regress underneath it.
func TestGHESGateProseIsRoutedThroughTheSharedHelper(t *testing.T) {
	ghes := ghcollect.GatedRepoReason(true, "3.12.4", "the feature this collector reads", "acme", "widgets")
	if strings.Contains(ghes, "plan-gated") {
		t.Errorf("GHES reason claims a plan gate: %q", ghes)
	}
	if !strings.Contains(ghes, "Enterprise Server") {
		t.Errorf("GHES reason does not name the host type: %q", ghes)
	}
}

// TestNotCheckableReason_404AfterAProvenFetchIsNotAMissingRepo pins the fix
// for a Reason contradicted by its own evidence: on a GHES release without
// the repository-rulesets API, GetRulesForBranch 404s on a repository that
// was just read successfully, and all six C02 checks reported it as not
// found — while the successful fetch sat in the same result's Provenance.
func TestNotCheckableReason_404AfterAProvenFetchIsNotAMissingRepo(t *testing.T) {
	resp := &ghgithub.Response{Response: &http.Response{StatusCode: http.StatusNotFound}}

	notFound := notCheckableReason(resp, nil, "acme", "widgets", false, collect.Scope{})
	if !strings.Contains(notFound, "not found") {
		t.Errorf("before any successful fetch, reason = %q, want the missing-repo wording", notFound)
	}

	afterFetch := notCheckableReason(resp, nil, "acme", "widgets", true, collect.Scope{IsGHES: true, GHESVersion: "3.12.4"})
	if strings.Contains(afterFetch, "not found, or not visible") {
		t.Errorf("after a proven fetch, reason still claims the repo is missing: %q — its own provenance disproves that", afterFetch)
	}
	if !strings.Contains(afterFetch, "read successfully earlier") {
		t.Errorf("reason does not say the repository was already read: %q", afterFetch)
	}
}

// TestCollect_RulesetsGatedOnGHES_NamesEnterpriseServerNotPlan drives a
// real Collect() call reproducing the exact scenario the package doc
// comment describes: the repo fetch succeeds, legacy branch-protection
// 404s (a normal "no legacy protection" input, not an error), and the
// rulesets API itself 404s — the GHES-without-rulesets-API case. This is
// the scenario TestNotCheckableReason_404AfterAProvenFetchIsNotAMissingRepo
// above does NOT cover: that test only asserts the ". This repository was
// read successfully earlier" suffix, which survives unchanged even if
// GatedRepoReason's own arguments are mutated back to (false, "", ...) —
// proven by review, which found exactly that mutation left this package's
// entire suite green. Mutating this package's GatedRepoReason call site
// back to (false, "", ...) must fail THIS test.
func TestCollect_RulesetsGatedOnGHES_NamesEnterpriseServerNotPlan(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/acme/widgets", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("/api/v3/repos/acme/widgets/branches/main/protection", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Branch not protected"})
	})
	mux.HandleFunc("/api/v3/repos/acme/widgets/rules/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})

	c := newGHESCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{
		Org: "acme", Repos: []string{"widgets"}, IsGHES: true, GHESVersion: "3.12.4",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != len(checkIDs) {
		t.Fatalf("len(results) = %d, want %d", len(results), len(checkIDs))
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
