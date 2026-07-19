package sasthistory

import (
	"testing"

	"github.com/sioakim/attestward/internal/collect/github/runhistory"
	"github.com/sioakim/attestward/internal/model"
)

// TestCheckRanPerRelease_MixedMissingAndFailed_IsVerifiedFail exercises a
// scenario no test previously covered directly: one release has zero
// matched runs at all (missing), another has a matched run that never
// succeeded (failed), and a third ran cleanly. anyMissing must take
// priority over the "ran for every evaluated release" partial/pass
// distinction — a single truly-uncovered release is a real gap regardless
// of how the other releases fared.
func TestCheckRanPerRelease_MixedMissingAndFailed_IsVerifiedFail(t *testing.T) {
	filteredReleases := []runhistory.ReleaseInfo{
		{TagName: "v1.0.0"},
		{TagName: "v1.1.0"},
		{TagName: "v1.2.0"},
	}
	coverage := []runhistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: runhistory.CoverageMissing},
		{Release: filteredReleases[1], Status: runhistory.CoverageFailed},
		{Release: filteredReleases[2], Status: runhistory.CoverageRan},
	}

	got := checkRanPerRelease("attestor-demo", "mixed-repo", filteredReleases, coverage, 0, nil)

	if got.Status != model.StatusVerifiedFail {
		t.Errorf("Status = %q, want %q; reason=%q", got.Status, model.StatusVerifiedFail, got.Reason)
	}

	table, ok := got.Facts["per_release"].([]map[string]any)
	if !ok || len(table) != 3 {
		t.Fatalf("per_release facts = %v, want 3 entries", got.Facts["per_release"])
	}
	wantStatuses := map[string]string{"v1.0.0": "missing", "v1.1.0": "failed", "v1.2.0": "ran"}
	for _, row := range table {
		tag, _ := row["tag"].(string)
		status, _ := row["status"].(string)
		if want := wantStatuses[tag]; status != want {
			t.Errorf("release %q status = %q, want %q", tag, status, want)
		}
	}
}
