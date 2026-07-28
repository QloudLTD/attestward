package sasthistory

import (
	"errors"
	"strings"
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

	got := checkRanPerRelease("attestward-demo", "mixed-repo", filteredReleases, coverage, 0, true, nil, nil, nil)

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

// TestCheckRanPerRelease_ZeroMatchedWithSkip_NotCheckableNotFail is the
// review finding on #202: with zero matched workflows, every release's
// coverage reads CoverageMissing regardless of WHY matched is empty — a
// genuine absence and an inspection failure look identical to
// LinkRunsToReleases. If a same-repo skip is the reason, asserting
// verified-fail would contradict C05.sast.tool-configured's own
// not-checkable for the identical evidence (two panels of one pack, opposite
// claims). Must read not-checkable instead, with the skip surfaced in Facts.
func TestCheckRanPerRelease_ZeroMatchedWithSkip_NotCheckableNotFail(t *testing.T) {
	filteredReleases := []runhistory.ReleaseInfo{{TagName: "v1.0.0"}}
	coverage := []runhistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: runhistory.CoverageMissing},
	}
	skipped := []runhistory.SkippedWorkflow{{Path: ".github/workflows/mystery.yml", Reason: "fetch content failed: 404"}}

	got := checkRanPerRelease("attestward-demo", "flaky-repo", filteredReleases, coverage, 0, false, skipped, nil, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable (a same-repo skip must cap what would otherwise be verified-fail); reason=%q", got.Status, got.Reason)
	}
	skipFacts, ok := got.Facts["skipped_workflows"].([]map[string]any)
	if !ok || len(skipFacts) != 1 || skipFacts[0]["path"] != ".github/workflows/mystery.yml" {
		t.Errorf("skipped_workflows facts = %#v, want one entry naming mystery.yml", got.Facts["skipped_workflows"])
	}
}

// TestCheckRanPerRelease_ZeroMatchedNoSkip_StillVerifiedFail proves the new
// guard is skip-gated, not a blanket "zero matched = not-checkable" —
// without any skip, zero matched workflows and a missing release is still a
// real, confirmed gap.
func TestCheckRanPerRelease_ZeroMatchedNoSkip_StillVerifiedFail(t *testing.T) {
	filteredReleases := []runhistory.ReleaseInfo{{TagName: "v1.0.0"}}
	coverage := []runhistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: runhistory.CoverageMissing},
	}

	got := checkRanPerRelease("attestward-demo", "bare-repo", filteredReleases, coverage, 0, false, nil, nil, nil)

	if got.Status != model.StatusVerifiedFail {
		t.Errorf("Status = %q, want verified-fail (no skip, so this is a confirmed absence); reason=%q", got.Status, got.Reason)
	}
}

// TestCheckRanPerRelease_RunsErr_NotCheckableFactsOmitPerRelease is issue
// #287's regression case: collectRepo's own workflow run-history fetch
// (runhistory.FetchWorkflowRuns) can fail for a matched workflow while
// everything else succeeds — the coverage slice passed in would then be
// silently derived from an incomplete runs pool (a release the failed
// workflow actually covered would still read CoverageMissing). Even with
// coverage claiming every release is missing (which, pre-fix, drove
// verified-fail), a non-nil runsErr must override that and produce
// not-checkable instead, with Facts["per_release"] entirely absent — the
// coverage table itself is untrustworthy evidence here, not just its
// consequence.
func TestCheckRanPerRelease_RunsErr_NotCheckableFactsOmitPerRelease(t *testing.T) {
	filteredReleases := []runhistory.ReleaseInfo{{TagName: "v1.2.0"}}
	coverage := []runhistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: runhistory.CoverageMissing},
	}
	runsErr := errors.New("workflow 1 (.github/workflows/codeql.yml): GET .../runs: 403 secondary rate limit")

	got := checkRanPerRelease("attestward-demo", "rate-limited-repo", filteredReleases, coverage, 0, true, nil, runsErr, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable (the run-history fetch itself failed — coverage can't be trusted); reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "run history") {
		t.Errorf("Reason = %q, want it to mention the run-history fetch failure", got.Reason)
	}
	if v, ok := got.Facts["per_release"]; ok {
		t.Errorf("Facts[per_release] = %v, want the key absent — coverage was computed from an incomplete runs pool, not a confirmed observation", v)
	}
	if dropped, ok := got.Facts["dropped_tags"].(int); !ok || dropped != 0 {
		t.Errorf("Facts[dropped_tags] = %v, want 0 (still reported — unaffected by the run-history failure)", got.Facts["dropped_tags"])
	}
}
