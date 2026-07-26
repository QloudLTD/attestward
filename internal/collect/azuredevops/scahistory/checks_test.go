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

	got := checkRanPerRelease("attestward-demo", "mixed-repo", filteredReleases, coverage, nil, nil, nil, nil, false, true, nil, nil)

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
	got := checkRanPerRelease("attestward-demo", "repo", nil, nil, []string{"v0.9.0-rc1", "v0.8.0-beta"}, nil, nil, nil, false, true, nil, nil)

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
	got := checkRanPerRelease("attestward-demo", "repo", filteredReleases, nil, nil, nil, errBoom, nil, false, true, nil, nil)
	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
}

// TestCheckRanPerRelease_RelErrIsNotCheckable proves a release-resolution
// failure is handled LOCALLY by this check (unlike C05, where it's a
// shared upstream failure the caller handles before ever reaching any
// check function — see the package doc comment's judgment call 6).
func TestCheckRanPerRelease_RelErrIsNotCheckable(t *testing.T) {
	got := checkRanPerRelease("attestward-demo", "repo", nil, nil, nil, errBoom, nil, nil, false, false, nil, nil)
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
	got := checkRanPerRelease("attestward-demo", "repo", filteredReleases, coverage, nil, nil, nil, nil, true, false, nil, nil)
	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable (injection-only evidence can't be linked to a release); reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "no verified way to observe") {
		t.Errorf("Reason = %q, want it to explain this collector has no verified way to observe injected scanning per release", got.Reason)
	}
}

// TestCheckRanPerRelease_InjectionOnlyWithSkip_InjectionOnlyReasonWins is
// the review finding on #202's merge resolution (mirrors
// azuredevops/sasthistory's identical
// TestCheckRanPerRelease_DefaultSetupOnlyWithSkip_DefaultSetupReasonWins):
// injectionOnly and a same-repo skip can both be true at once (GHAzDO
// dependency scanning injection enabled, zero signature-matched pipelines,
// AND one other pipeline in the repo whose YAML couldn't be resolved).
// injectionOnly must win: checkToolConfigured has already reported
// verified-pass for this identical evidence, and the skip reason's own
// wording ("no matched SCA pipeline evidence... a confirmed absence can't
// be asserted") would be actively wrong next to that verified-pass. The
// skip's Facts must still be attached, though.
func TestCheckRanPerRelease_InjectionOnlyWithSkip_InjectionOnlyReasonWins(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	coverage := []pipelinehistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: pipelinehistory.CoverageMissing},
	}
	skipped := []pipelinehistory.SkippedPipeline{{DefinitionID: 2, Name: "unresolved-pipeline", Reason: "yamlFilename missing"}}

	got := checkRanPerRelease("attestward-demo", "injection-plus-skip-repo", filteredReleases, coverage, nil, nil, nil, nil, true, false, skipped, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "GHAzDO dependency scanning injection") {
		t.Errorf("Reason = %q, want the injection-only explanation to win over the skip explanation when both apply", got.Reason)
	}
	if strings.Contains(got.Reason, "could not be fully inspected") {
		t.Errorf("Reason = %q, the skip-caused wording must not win here — it would read as a confirmed absence next to tool-configured's verified-pass for the same evidence", got.Reason)
	}
	skipFacts, ok := got.Facts["skipped_pipelines"].([]map[string]any)
	if !ok || len(skipFacts) != 1 || skipFacts[0]["name"] != "unresolved-pipeline" {
		t.Errorf("skipped_pipelines facts = %#v, want one entry naming unresolved-pipeline (the skip record must survive even though its own reason didn't win)", got.Facts["skipped_pipelines"])
	}
}

// TestCheckRanPerRelease_ZeroMatchedWithSkip_NotCheckableNotFail is the
// review finding on #202/#207: with zero matched pipelines, every
// release's coverage reads CoverageMissing regardless of WHY matched is
// empty — a genuine absence and an inspection failure look identical to
// LinkRunsToReleases. If a same-repo skip is the reason, asserting
// verified-fail would contradict C06.sca.tool-configured's own
// not-checkable for the identical evidence (two panels of one pack,
// opposite claims). Must read not-checkable instead, with the skip
// surfaced in Facts.
func TestCheckRanPerRelease_ZeroMatchedWithSkip_NotCheckableNotFail(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	coverage := []pipelinehistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: pipelinehistory.CoverageMissing},
	}
	skipped := []pipelinehistory.SkippedPipeline{{DefinitionID: 1, Name: "unresolved-pipeline", Reason: "yamlFilename missing"}}

	got := checkRanPerRelease("attestward-demo", "flaky-repo", filteredReleases, coverage, nil, nil, nil, nil, false, false, skipped, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable (a same-repo skip must cap what would otherwise be verified-fail); reason=%q", got.Status, got.Reason)
	}
	skipFacts, ok := got.Facts["skipped_pipelines"].([]map[string]any)
	if !ok || len(skipFacts) != 1 || skipFacts[0]["name"] != "unresolved-pipeline" {
		t.Errorf("skipped_pipelines facts = %#v, want one entry naming unresolved-pipeline", got.Facts["skipped_pipelines"])
	}
}

// TestCheckRanPerRelease_ZeroMatchedNoSkip_StillVerifiedFail proves the new
// guard is skip-gated, not a blanket "zero matched = not-checkable" —
// without any skip (and without injection-only evidence either), zero
// matched pipelines and a missing release is still a real, confirmed gap.
func TestCheckRanPerRelease_ZeroMatchedNoSkip_StillVerifiedFail(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	coverage := []pipelinehistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: pipelinehistory.CoverageMissing},
	}

	got := checkRanPerRelease("attestward-demo", "bare-repo", filteredReleases, coverage, nil, nil, nil, nil, false, false, nil, nil)

	if got.Status != model.StatusVerifiedFail {
		t.Errorf("Status = %q, want verified-fail (no skip, so this is a confirmed absence); reason=%q", got.Status, got.Reason)
	}
}

// TestCheckRanPerRelease_EnablementErr_NotCheckableNotFail is issue #244's
// regression case, mirroring C05 sasthistory's identical
// TestCheckRanPerRelease_EnablementErr_NotCheckableNotFail: issue #236
// narrowed C06.sca.tool-configured's verified-fail to require a genuinely
// observed enablement response, routing every enablement error (404
// included) to not-checkable instead of an inference from the status code
// — but that fix only touched checkToolConfigured. This check reads the
// identical enablement result (whether GHAzDO dependency scanning
// injection covers a repo with zero matched pipelines) and, before this
// fix, never gated on enablementErr at all: zero matched pipelines and an
// enablement-query failure fell straight through to the coverage
// computation, which always reads CoverageMissing for zero matched
// pipelines and reports verified-fail. That reintroduced exactly the "two
// panels of one pack, opposite claims" contradiction this guard already
// exists to prevent (see TestCheckRanPerRelease_ZeroMatchedWithSkip_NotCheckableNotFail
// for the same-repo-skip case #207 fixed first) — just reached through
// enablementErr instead of a same-repo skip: tool-configured now correctly
// says "we can't tell" right next to ran-per-release saying "it didn't
// run", for the same repo, from the same evidence gap.
func TestCheckRanPerRelease_EnablementErr_NotCheckableNotFail(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	coverage := []pipelinehistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: pipelinehistory.CoverageMissing},
	}
	enablementErr := &azuredevops.StatusError{StatusCode: http.StatusNotFound}

	got := checkRanPerRelease("attestward-demo", "enablement-404-repo", filteredReleases, coverage, nil, nil, nil, enablementErr, false, false, nil, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable (an enablement-query failure means whether injection covers this repo can't be confirmed — a confirmed absence can't be asserted over that); reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "repo-enablement query itself failed") {
		t.Errorf("Reason = %q, want it to name the enablement-query failure as the cause", got.Reason)
	}
}

// TestCheckRanPerRelease_EnablementErrAndSkip_BothNamedInReason mirrors C05
// sasthistory's identical test: proves the combined guard names both
// causes when they co-occur (an enablement-query failure and an unrelated
// same-repo pipeline skip are causally independent — one is about the
// enablement endpoint, the other about a specific pipeline's
// YAML/build-definition — so both can be true at once).
func TestCheckRanPerRelease_EnablementErrAndSkip_BothNamedInReason(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	coverage := []pipelinehistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: pipelinehistory.CoverageMissing},
	}
	enablementErr := &azuredevops.StatusError{StatusCode: http.StatusNotFound}
	skipped := []pipelinehistory.SkippedPipeline{{DefinitionID: 3, Name: "unresolved-pipeline", Reason: "yamlFilename missing"}}

	got := checkRanPerRelease("attestward-demo", "enablement-404-plus-skip-repo", filteredReleases, coverage, nil, nil, nil, enablementErr, false, false, skipped, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "repo-enablement query itself failed") {
		t.Errorf("Reason = %q, want the enablement-query failure named", got.Reason)
	}
	if !strings.Contains(got.Reason, "1 pipeline(s)") {
		t.Errorf("Reason = %q, want the same-repo skip count also named", got.Reason)
	}
	skipFacts, ok := got.Facts["skipped_pipelines"].([]map[string]any)
	if !ok || len(skipFacts) != 1 || skipFacts[0]["name"] != "unresolved-pipeline" {
		t.Errorf("skipped_pipelines facts = %#v, want one entry naming unresolved-pipeline", got.Facts["skipped_pipelines"])
	}
}

// TestCheckRanPerRelease_EnablementErrWithDroppedTags_FactsPreserved
// mirrors C05 sasthistory's identical test: proves the combined guard
// never silently drops a repo's dropped_tags Facts just because an
// enablement-query failure also applies.
func TestCheckRanPerRelease_EnablementErrWithDroppedTags_FactsPreserved(t *testing.T) {
	enablementErr := &azuredevops.StatusError{StatusCode: http.StatusNotFound}
	dropped := []string{"v0.9.0-rc1"}

	got := checkRanPerRelease("attestward-demo", "enablement-404-dropped-tags-repo", nil, nil, dropped, nil, nil, enablementErr, false, false, nil, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	droppedFacts, ok := got.Facts["dropped_tags"].([]string)
	if !ok || len(droppedFacts) != 1 || droppedFacts[0] != "v0.9.0-rc1" {
		t.Errorf("dropped_tags facts = %#v, want [\"v0.9.0-rc1\"] — the pack must not silently lose the record of an unresolvable tag just because an enablement-query failure also applies", got.Facts["dropped_tags"])
	}
}

// TestCheckRanPerRelease_InjectionOnlyWithDroppedTags_FactsPreserved is
// issue #256, mirroring #252's identical fix (and identical proof) in C05
// sasthistory's defaultSetupOnly branch: this branch attached Facts only
// when sameRepoSkips was non-empty, so a repo with GHAzDO dependency
// scanning injection on AND dropped-but-undateable release tags returned
// not-checkable with no Facts at all — silently losing the record of an
// unresolvable tag.
func TestCheckRanPerRelease_InjectionOnlyWithDroppedTags_FactsPreserved(t *testing.T) {
	dropped := []string{"v0.9.0-rc1"}

	got := checkRanPerRelease("attestward-demo", "injection-only-dropped-tags-repo", nil, nil, dropped, nil, nil, nil, true, false, nil, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	droppedFacts, ok := got.Facts["dropped_tags"].([]string)
	if !ok || len(droppedFacts) != 1 || droppedFacts[0] != "v0.9.0-rc1" {
		t.Errorf("dropped_tags facts = %#v, want [\"v0.9.0-rc1\"] — the pack must not silently lose the record of an unresolvable tag just because dependency scanning injection also explains the status", got.Facts["dropped_tags"])
	}
}

// TestCheckRanPerRelease_BuildsErrWithDroppedTags_FactsPreserved is issue
// #256's own second holdout — found by checking for the same shape #254
// found in C05 one review round after #252, not assumed absent here:
// reachable with a signature-matched pipeline, one dateable release, one
// undateable release tag, and a failed build-history fetch.
func TestCheckRanPerRelease_BuildsErrWithDroppedTags_FactsPreserved(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	dropped := []string{"v0.9.0-rc1"}

	got := checkRanPerRelease("attestward-demo", "builds-err-dropped-tags-repo", filteredReleases, nil, dropped, nil, errBoom, nil, false, true, nil, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	droppedFacts, ok := got.Facts["dropped_tags"].([]string)
	if !ok || len(droppedFacts) != 1 || droppedFacts[0] != "v0.9.0-rc1" {
		t.Errorf("dropped_tags facts = %#v, want [\"v0.9.0-rc1\"] — the pack must not silently lose the record of an unresolvable tag just because the build-history fetch also failed", got.Facts["dropped_tags"])
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
