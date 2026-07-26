package sasthistory

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/sioakim/attestward/internal/collect/azuredevops"
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

	got := checkRanPerRelease("attestward-demo", "mixed-repo", filteredReleases, coverage, nil, nil, nil, false, true, nil, nil)

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
	got := checkRanPerRelease("attestward-demo", "repo", nil, nil, []string{"v0.9.0-rc1", "v0.8.0-beta"}, nil, nil, false, true, nil, nil)

	if got.Status != model.StatusPartial {
		t.Errorf("Status = %q, want partial; reason=%q", got.Status, got.Reason)
	}
	dropped, ok := got.Facts["dropped_tags"].([]string)
	if !ok || len(dropped) != 2 || dropped[0] != "v0.9.0-rc1" || dropped[1] != "v0.8.0-beta" {
		t.Errorf("dropped_tags facts = %#v, want [\"v0.9.0-rc1\" \"v0.8.0-beta\"]", got.Facts["dropped_tags"])
	}
}

// TestCheckRanPerRelease_DefaultSetupOnly_NotCheckableNotFail is issue
// #184's regression case, mirroring azuredevops/scahistory's identical
// injectionOnly test: a repo whose only SAST evidence is GHAzDO CodeQL
// default setup (zero matched pipelines) must not read verified-fail —
// that would contradict checkToolConfigured's verified-pass for the same
// evidence. It must read not-checkable, since this collector has no
// verified way to observe default-setup's own run history per release.
func TestCheckRanPerRelease_DefaultSetupOnly_NotCheckableNotFail(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	coverage := []pipelinehistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: pipelinehistory.CoverageMissing},
	}

	got := checkRanPerRelease("attestward-demo", "default-setup-only-repo", filteredReleases, coverage, nil, nil, nil, true, false, nil, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable (default-setup-only evidence can't be observed per release); reason=%q", got.Status, got.Reason)
	}
}

// TestCheckRanPerRelease_DefaultSetupOnlyWithSkip_DefaultSetupReasonWins is
// the review finding on #202's merge resolution: defaultSetupOnly and a
// same-repo skip can both be true at once (GHAzDO CodeQL default setup
// enabled, zero signature-matched pipelines, AND one other pipeline in the
// repo whose YAML couldn't be resolved), and the six existing unit tests
// never exercised that combination — each covers exactly one guard in
// isolation. Reversing the two guards' order in checks.go left the whole
// suite green, proving nothing pinned which Reason wins.
//
// The default-setup reason must win: checkToolConfigured has already
// reported verified-pass for this identical evidence, and the skip
// reason's own wording ("no matched SAST pipeline evidence... a confirmed
// absence can't be asserted") would be actively wrong next to that
// verified-pass, not just a worse explanation — it would reintroduce the
// exact cross-check contradiction this guard exists to remove. The skip's
// Facts must still be attached, though, so the pack doesn't lose the
// record of an uninspectable pipeline just because default setup explains
// the status.
func TestCheckRanPerRelease_DefaultSetupOnlyWithSkip_DefaultSetupReasonWins(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	coverage := []pipelinehistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: pipelinehistory.CoverageMissing},
	}
	skipped := []pipelinehistory.SkippedPipeline{{DefinitionID: 2, Name: "unresolved-pipeline", Reason: "yamlFilename missing"}}

	got := checkRanPerRelease("attestward-demo", "default-setup-plus-skip-repo", filteredReleases, coverage, nil, nil, nil, true, false, skipped, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "GHAzDO CodeQL default setup") {
		t.Errorf("Reason = %q, want the default-setup explanation to win over the skip explanation when both apply", got.Reason)
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
// review finding on #202: with zero matched pipelines, every release's
// coverage reads CoverageMissing regardless of WHY matched is empty — a
// genuine absence and an inspection failure look identical to
// LinkRunsToReleases. If a same-repo skip is the reason, asserting
// verified-fail would contradict C05.sast.tool-configured's own
// not-checkable for the identical evidence (two panels of one pack, opposite
// claims). Must read not-checkable instead, with the skip surfaced in Facts.
func TestCheckRanPerRelease_ZeroMatchedWithSkip_NotCheckableNotFail(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	coverage := []pipelinehistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: pipelinehistory.CoverageMissing},
	}
	skipped := []pipelinehistory.SkippedPipeline{{DefinitionID: 1, Name: "unresolved-pipeline", Reason: "yamlFilename missing"}}

	got := checkRanPerRelease("attestward-demo", "flaky-repo", filteredReleases, coverage, nil, nil, nil, false, false, skipped, nil)

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
// without any skip (and without default-setup-only evidence either), zero
// matched pipelines and a missing release is still a real, confirmed gap.
func TestCheckRanPerRelease_ZeroMatchedNoSkip_StillVerifiedFail(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	coverage := []pipelinehistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: pipelinehistory.CoverageMissing},
	}

	got := checkRanPerRelease("attestward-demo", "bare-repo", filteredReleases, coverage, nil, nil, nil, false, false, nil, nil)

	if got.Status != model.StatusVerifiedFail {
		t.Errorf("Status = %q, want verified-fail (no skip, so this is a confirmed absence); reason=%q", got.Status, got.Reason)
	}
}

// TestCheckRanPerRelease_EnablementErr_NotCheckableNotFail is issue #235's
// regression case: #233 narrowed C05.sast.tool-configured's verified-fail
// to require a genuinely observed enablement response, routing every
// enablement error (404 included) to not-checkable instead of an inference
// from the status code — but that fix only touched checkToolConfigured.
// This check reads the identical enablement result (whether GHAzDO CodeQL
// default setup covers a repo with zero matched pipelines) and, before this
// fix, never gated on enablementErr at all: zero matched pipelines and an
// enablement-query failure fell straight through to the coverage
// computation, which always reads CoverageMissing for zero matched
// pipelines and reports verified-fail. That reintroduced exactly the "two
// panels of one pack, opposite claims" contradiction this guard already
// exists to prevent (see TestCheckRanPerRelease_ZeroMatchedWithSkip_NotCheckableNotFail
// for the same-repo-skip case #202 fixed first) — just reached through
// enablementErr instead of a same-repo skip: tool-configured now correctly
// says "we can't tell" right next to ran-per-release saying "it didn't
// run", for the same repo, from the same evidence gap.
func TestCheckRanPerRelease_EnablementErr_NotCheckableNotFail(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	coverage := []pipelinehistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: pipelinehistory.CoverageMissing},
	}
	enablementErr := &azuredevops.StatusError{StatusCode: http.StatusNotFound}

	got := checkRanPerRelease("attestward-demo", "enablement-404-repo", filteredReleases, coverage, nil, nil, enablementErr, false, false, nil, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable (an enablement-query failure means whether default setup covers this repo can't be confirmed — a confirmed absence can't be asserted over that); reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "repo-enablement query itself failed") {
		t.Errorf("Reason = %q, want it to name the enablement-query failure as the cause", got.Reason)
	}
}

// TestCheckRanPerRelease_EnablementErrAndSkip_BothNamedInReason proves the
// combined guard names both causes when they co-occur (an enablement-query
// failure and an unrelated same-repo pipeline skip are causally
// independent — one is about the enablement endpoint, the other about a
// specific pipeline's YAML/build-definition — so both can be true at once),
// mirroring TestCheckRanPerRelease_DefaultSetupOnlyWithSkip_DefaultSetupReasonWins's
// discipline of pinning what a two-cause Reason actually says rather than
// only testing each cause in isolation.
func TestCheckRanPerRelease_EnablementErrAndSkip_BothNamedInReason(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	coverage := []pipelinehistory.ReleaseCoverage{
		{Release: filteredReleases[0], Status: pipelinehistory.CoverageMissing},
	}
	enablementErr := &azuredevops.StatusError{StatusCode: http.StatusNotFound}
	skipped := []pipelinehistory.SkippedPipeline{{DefinitionID: 3, Name: "unresolved-pipeline", Reason: "yamlFilename missing"}}

	got := checkRanPerRelease("attestward-demo", "enablement-404-plus-skip-repo", filteredReleases, coverage, nil, nil, enablementErr, false, false, skipped, nil)

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

// TestCheckRanPerRelease_EnablementErrWithDroppedTags_FactsPreserved is the
// regression test for a real bug the independent review of #245 found in
// the combined guard above: with an enablement-query failure, zero matched
// pipelines, and dropped-but-undateable tags leaving nothing in the
// lookback window, the combined guard used to fire (correctly, on
// enablementErr) but only ever populated Facts when sameRepoSkips was
// non-empty — so a repo whose tags couldn't be dated lost that record
// entirely (Facts went from {dropped_tags: [...]} to nil), even though the
// later len(filteredReleases) == 0 branch would have preserved it had the
// combined guard not intercepted the call first. dropped_tags is now
// always included, matching that later branch's own convention.
func TestCheckRanPerRelease_EnablementErrWithDroppedTags_FactsPreserved(t *testing.T) {
	enablementErr := &azuredevops.StatusError{StatusCode: http.StatusNotFound}
	dropped := []string{"v0.9.0-rc1"}

	got := checkRanPerRelease("attestward-demo", "enablement-404-dropped-tags-repo", nil, nil, dropped, nil, enablementErr, false, false, nil, nil)

	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	droppedFacts, ok := got.Facts["dropped_tags"].([]string)
	if !ok || len(droppedFacts) != 1 || droppedFacts[0] != "v0.9.0-rc1" {
		t.Errorf("dropped_tags facts = %#v, want [\"v0.9.0-rc1\"] — the pack must not silently lose the record of an unresolvable tag just because an enablement-query failure also applies", got.Facts["dropped_tags"])
	}
}

// TestCheckRanPerRelease_BuildsErrIsNotCheckable proves a build-history
// fetch failure (the single Builds List call covering every matched
// pipeline for this repo) makes ran-per-release not-checkable rather than
// silently reporting zero coverage as a confirmed verified-fail.
func TestCheckRanPerRelease_BuildsErrIsNotCheckable(t *testing.T) {
	filteredReleases := []pipelinehistory.ReleaseInfo{{TagName: "v1.0.0"}}
	got := checkRanPerRelease("attestward-demo", "repo", filteredReleases, nil, nil, errBoom, nil, false, true, nil, nil)
	if got.Status != model.StatusNotCheckable {
		t.Errorf("Status = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
}
