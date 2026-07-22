package sasthistory

import (
	"errors"
	"testing"

	"github.com/sioakim/attestward/internal/collect/azuredevops/pipelinehistory"
	"github.com/sioakim/attestward/internal/model"
)

var errBoom = errors.New("boom")

// TestCheckRanPerRelease_MixedMissingAndFailed_IsVerifiedFail exercises a
// scenario no full-Collect scenario test covers directly: one release has
// zero matched builds at all (missing), another has a matched build that
// never succeeded (failed), and a third ran cleanly. anyMissing must take
// priority over the "ran for every evaluated release" partial/pass
// distinction — a single truly-uncovered release is a real gap regardless
// of how the other releases fared. Mirrors the GitHub twin's identical
// test.
func TestCheckRanPerRelease_MixedMissingAndFailed_IsVerifiedFail(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{
		{TagName: "v1.0.0"},
		{TagName: "v1.1.0"},
		{TagName: "v1.2.0"},
	}
	coverage := []pipelinehistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: pipelinehistory.CoverageMissing},
		{Release: filteredReleases[1], Status: pipelinehistory.CoverageFailed},
		{Release: filteredReleases[2], Status: pipelinehistory.CoverageRan},
	}

	got := checkRanPerRelease("attestward-demo", "mixed-repo", filteredReleases, coverage, nil, nil, nil)

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

// TestCheckRanPerRelease_DroppedTagsNamedInFacts proves this collector's
// own deliberate choice (see the package doc comment): dropped tag NAMES,
// not just a count, land in Facts — a report reader auditing a stricter
// ADO result (versus the GitHub twin's window-gated count) can see exactly
// which tags to investigate.
func TestCheckRanPerRelease_DroppedTagsNamedInFacts(t *testing.T) {
	got := checkRanPerRelease("attestward-demo", "repo", nil, nil, []string{"v0.9.0-rc1", "v0.8.0-beta"}, nil, nil)

	if got.Status != model.StatusPartial {
		t.Errorf("Status = %q, want partial; reason=%q", got.Status, got.Reason)
	}
	dropped, ok := got.Facts["dropped_tags"].([]string)
	if !ok || len(dropped) != 2 || dropped[0] != "v0.9.0-rc1" || dropped[1] != "v0.8.0-beta" {
		t.Errorf("dropped_tags facts = %#v, want [\"v0.9.0-rc1\" \"v0.8.0-beta\"]", got.Facts["dropped_tags"])
	}
}

// TestCheckRanPerRelease_BuildsErrIsNotCheckable proves a build-history
// fetch failure (the single Builds List call covering every matched
// pipeline for this repo) makes ran-per-release not-checkable rather than
// silently reporting zero coverage as a confirmed verified-fail.
func TestCheckRanPerRelease_BuildsErrIsNotCheckable(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	got := checkRanPerRelease("attestward-demo", "repo", filteredReleases, nil, nil, errBoom, nil)
	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
}
