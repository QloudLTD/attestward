package scahistory

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/collect/azuredevops/pipelinehistory"
	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/model"
)

var errBoom = errors.New("boom")

// TestCheckRanPerRelease_MixedMissingAndFailed_IsVerifiedFail mirrors C05's
// identical test: anyMissing must take priority over the "ran for every
// evaluated release" partial/pass distinction.
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

	got := checkRanPerRelease("attestward-demo", "mixed-repo", filteredReleases, coverage, nil, nil, nil, false, nil)

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

// TestCheckRanPerRelease_DroppedTagsNamedInFacts proves this check reuses
// C05's own deliberate choice (see the package doc comment's judgment call
// 1): dropped tag NAMES, not just a count, land in Facts.
func TestCheckRanPerRelease_DroppedTagsNamedInFacts(t *testing.T) {
	got := checkRanPerRelease("attestward-demo", "repo", nil, nil, []string{"v0.9.0-rc1", "v0.8.0-beta"}, nil, nil, false, nil)

	if got.Status != model.StatusPartial {
		t.Errorf("Status = %q, want partial; reason=%q", got.Status, got.Reason)
	}
	dropped, ok := got.Facts["dropped_tags"].([]string)
	if !ok || len(dropped) != 2 || dropped[0] != "v0.9.0-rc1" || dropped[1] != "v0.8.0-beta" {
		t.Errorf("dropped_tags facts = %#v, want [\"v0.9.0-rc1\" \"v0.8.0-beta\"]", got.Facts["dropped_tags"])
	}
}

// TestCheckRanPerRelease_BuildsErrIsNotCheckable proves a build-history
// fetch failure makes ran-per-release not-checkable rather than silently
// reporting zero coverage as a confirmed verified-fail.
func TestCheckRanPerRelease_BuildsErrIsNotCheckable(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	got := checkRanPerRelease("attestward-demo", "repo", filteredReleases, nil, nil, nil, errBoom, false, nil)
	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
}

// TestCheckRanPerRelease_RelErrIsNotCheckable proves a release-resolution
// failure is handled LOCALLY by this check (unlike C05, where it's a
// shared upstream failure the caller handles before ever reaching any
// check function — see the package doc comment's judgment call 6).
func TestCheckRanPerRelease_RelErrIsNotCheckable(t *testing.T) {
	got := checkRanPerRelease("attestward-demo", "repo", nil, nil, nil, errBoom, nil, false, nil)
	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
}

// TestCheckRanPerRelease_InjectionOnly_IsNotCheckable is the acceptance
// test for the package doc comment's judgment call 7: GHAzDO dependency
// scanning injection being this repo's only SCA evidence must not produce
// a confident verified-fail here (there is no matched pipeline whose
// builds this check could link any release to), even when releases
// resolved cleanly and would otherwise read as CoverageMissing.
func TestCheckRanPerRelease_InjectionOnly_IsNotCheckable(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	coverage := []pipelinehistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: pipelinehistory.CoverageMissing},
	}
	got := checkRanPerRelease("attestward-demo", "repo", filteredReleases, coverage, nil, nil, nil, true, nil)
	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable (injection-only evidence can't be linked to a release); reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "no verified way to observe") {
		t.Errorf("Reason = %q, want it to explain this collector has no verified way to observe injected scanning per release", got.Reason)
	}
}

// TestCheckToolConfigured_SameRepoSkipCapsWouldBeFailToNotCheckable is the
// acceptance test for issue #178's "build it in from the start" fix (see
// the package doc comment's judgment call 5): with zero matched pipelines
// and GHAzDO dependency scanning injection not configured, a same-repo
// skip must cap the result at not-checkable rather than a confident
// verified-fail.
func TestCheckToolConfigured_SameRepoSkipCapsWouldBeFailToNotCheckable(t *testing.T) {
	skips := []pipelinehistory.SkippedPipeline{
		{DefinitionID: 7, Name: "weird-pipeline", RepositoryID: "repo-1", Reason: "fetch YAML content failed: boom"},
	}
	got := checkToolConfigured("attestward-demo", "repo", nil, skips, pipelinehistory.RepoEnablementInfo{}, nil, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable (a same-repo skip must cap what would otherwise be verified-fail); reason=%q", got.Status, got.Reason)
	}
	skipped, ok := got.Facts["skipped_pipelines"].([]map[string]any)
	if !ok || len(skipped) != 1 || skipped[0]["name"] != "weird-pipeline" || skipped[0]["reason"] != "fetch YAML content failed: boom" {
		t.Errorf("skipped_pipelines facts = %#v, want one entry naming weird-pipeline and its reason", got.Facts["skipped_pipelines"])
	}
}

// TestCheckToolConfigured_NoEvidenceNoSkips_IsVerifiedFail proves the skip
// cap only fires when a same-repo skip actually exists — a genuine,
// evidence-complete absence still reports verified-fail.
func TestCheckToolConfigured_NoEvidenceNoSkips_IsVerifiedFail(t *testing.T) {
	got := checkToolConfigured("attestward-demo", "repo", nil, nil, pipelinehistory.RepoEnablementInfo{}, nil, nil)
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("Status = %q, want verified-fail; reason=%q", got.Status, got.Reason)
	}
	skipped, ok := got.Facts["skipped_pipelines"].([]map[string]any)
	if !ok || len(skipped) != 0 {
		t.Errorf("skipped_pipelines facts = %#v, want an empty (non-nil) slice", got.Facts["skipped_pipelines"])
	}
}

// TestCheckToolConfigured_RealMatchPlusSameRepoSkip_StillVerifiedPass is
// the untested crux composition (found in review): a genuine
// high-confidence pipeline match must still produce verified-pass even
// when an UNRELATED pipeline in the same repo was also skipped — the skip
// cap only ever applies to what would otherwise be verified-fail, never
// downgrades an already-positive result. skipped_pipelines Facts still
// name the skip, since it's surfaced unconditionally regardless of the
// check's own status.
func TestCheckToolConfigured_RealMatchPlusSameRepoSkip_StillVerifiedPass(t *testing.T) {
	matched := []pipelinehistory.MatchedPipeline{
		{
			DefinitionID: 1, Name: "ci", RepositoryID: "repo-1",
			Matches: []mapping.ScannerMatch{{SignatureID: "ghazdo-dependency-scanning", Name: "GitHub Advanced Security for Azure DevOps Dependency Scanning", Category: mapping.CategorySCA, Confidence: mapping.ConfidenceHigh}},
		},
	}
	skips := []pipelinehistory.SkippedPipeline{
		{DefinitionID: 2, Name: "unrelated-pipeline", RepositoryID: "repo-1", Reason: "fetch YAML content failed: boom"},
	}
	got := checkToolConfigured("attestward-demo", "repo", matched, skips, pipelinehistory.RepoEnablementInfo{}, nil, nil)

	if got.Status != model.StatusVerifiedPass {
		t.Errorf("Status = %q, want verified-pass (a real match must not be downgraded by an unrelated skip); reason=%q", got.Status, got.Reason)
	}
	skipped, ok := got.Facts["skipped_pipelines"].([]map[string]any)
	if !ok || len(skipped) != 1 || skipped[0]["name"] != "unrelated-pipeline" {
		t.Errorf("skipped_pipelines facts = %#v, want one entry naming unrelated-pipeline (surfaced unconditionally, even on a pass)", got.Facts["skipped_pipelines"])
	}
}

// TestCheckToolConfigured_EnablementGenericError_FactsIncludeSkips proves
// the enablement-failure guard's own not-checkable return carries the
// same skipped_pipelines Facts entry every other return path does (found
// in review: an earlier version computed skipDetails AFTER this guard, so
// this path returned no Facts at all, contradicting this function's own
// "Facts land unconditionally" claim).
func TestCheckToolConfigured_EnablementGenericError_FactsIncludeSkips(t *testing.T) {
	skips := []pipelinehistory.SkippedPipeline{
		{DefinitionID: 3, Name: "some-pipeline", RepositoryID: "repo-1", Reason: "parse YAML failed: boom"},
	}
	enablementErr := &azuredevops.StatusError{StatusCode: http.StatusInternalServerError, Method: "GET", Endpoint: "advsec.dev.azure.com/…", Body: "boom"}

	got := checkToolConfigured("attestward-demo", "repo", nil, skips, pipelinehistory.RepoEnablementInfo{}, enablementErr, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	skipped, ok := got.Facts["skipped_pipelines"].([]map[string]any)
	if !ok || len(skipped) != 1 || skipped[0]["name"] != "some-pipeline" {
		t.Errorf("skipped_pipelines facts = %#v, want one entry naming some-pipeline — the enablement-failure guard must carry Facts too", got.Facts["skipped_pipelines"])
	}
}
