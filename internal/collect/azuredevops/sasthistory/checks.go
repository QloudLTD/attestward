package sasthistory

import (
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/collect/azuredevops/pipelinehistory"
	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/model"
)

// advSecNotCheckableReason distinguishes a 404 (this collector's own
// confirmed-absence signal — see isAdvSecNotFoundErr's own doc comment for
// why only this code, not every azuredevops.IsAdvSecGated code, earns that
// treatment) from a 403 (genuinely ambiguous: a missing vso.advsec scope
// reads identically to an unlicensed org/project), falling back to a
// generic message otherwise. Both gated cases are still [fixture-verify]:
// which of 403/404 (or both) a real unlicensed-org response actually
// returns is unconfirmed until issue #34/#151's S5 empirical pass.
func advSecNotCheckableReason(err error, org, repo string) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) {
		switch se.StatusCode {
		case http.StatusNotFound:
			return fmt.Sprintf(
				"GHAzDO repo-enablement query returned 404 for %s/%s — GHAzDO (GitHub Advanced Security for "+
					"Azure DevOps) isn't licensed for this org/project [fixture-verify: whether 404 always "+
					"means specifically this, rather than some other absence, is unconfirmed until issue "+
					"#34/#151's S5 empirical pass]", org, repo)
		case http.StatusForbidden:
			return fmt.Sprintf(
				"GHAzDO repo-enablement query returned 403 for %s/%s — ambiguous: either the token lacks the "+
					"vso.advsec scope, or the org/project isn't licensed for GHAzDO; Azure DevOps returns the "+
					"same status for both, so this can't be told apart from the response alone [fixture-verify, "+
					"issue #34/#151's S5 pass]", org, repo)
		}
	}
	return fmt.Sprintf("could not query GHAzDO repo enablement for %s/%s: %v", org, repo, err)
}

// isAdvSecNotFoundErr reports whether err is a *azuredevops.StatusError
// with status 404 specifically — the one code among
// azuredevops.IsAdvSecGated's two (403, 404) this collector treats as a
// confirmed "GHAzDO isn't provisioned for this org/project" fact in
// checkToolConfigured's fall-through. A 403 is deliberately excluded from
// that treatment (found in review): it can mean either that same absence,
// OR simply that this token lacks the vso.advsec scope on an org where
// GHAzDO genuinely IS licensed and default setup IS enabled — asserting
// verified-fail for that second case would be a false negative any
// scope-less PAT could trigger against a perfectly-configured repo, while
// checkDefaultSetup (which never distinguishes gated-vs-not) would
// honestly report not-checkable for the identical response. Whether a
// real unlicensed org's response is 403, 404, or both is unconfirmed
// [fixture-verify] until issue #34/#151's S5 empirical pass.
func isAdvSecNotFoundErr(err error) bool {
	var se *azuredevops.StatusError
	return errors.As(err, &se) && se.StatusCode == http.StatusNotFound
}

// matchConfidence reports whether matched contains any SAST match at all
// (hasAny) and whether any of those matches are at least medium confidence
// (hasHighOrMedium) — shared by checkToolConfigured and checkCadence so
// both apply the exact same "low-confidence-only" definition, mirroring
// the GitHub twin's identical helper.
func matchConfidence(matched []pipelinehistory.MatchedPipeline) (hasAny, hasHighOrMedium bool) {
	for _, mp := range matched {
		for _, m := range mp.Matches {
			hasAny = true
			if m.Confidence != mapping.ConfidenceLow {
				hasHighOrMedium = true
			}
		}
	}
	return hasAny, hasHighOrMedium
}

// checkToolConfigured implements the confidence-capping rule from the
// issue: a low-confidence-only match (pipeline/step name heuristic alone,
// no ado_task or run-pattern match) can never alone justify verified-pass
// — it caps at partial.
//
// It also guards against a subtler failure mode, mirroring the GitHub
// twin's identical guard for its own default-setup call: the GHAzDO
// repo-enablement query can fail for reasons that don't mean "not
// enabled" (a genuine API error, not a confirmed absence). If there's no
// pipeline-based evidence at all (hasAny false) and the enablement query
// itself failed with anything other than a 404, asserting verified-fail
// would claim a fact this collector doesn't actually have evidence for —
// this check goes not-checkable instead. Only a 404 is excluded from this
// guard (a confirmed "not provisioned" fact, mirroring the GitHub twin's
// plan-gated exclusion) — a 403 is deliberately NOT excluded (found in
// review): it's ambiguous between "not licensed" and "token lacks
// vso.advsec", and treating it as a confirmed fail would produce a false
// verified-fail on a licensed org + enabled default setup + a scope-less
// PAT, while the sibling checkDefaultSetup honestly reports not-checkable
// for that identical response — see isAdvSecNotFoundErr's own doc comment.
//
// sameRepoSkips are this repo's own entries from
// pipelinehistory.MatchPipelines' skipped return (issue #178): surfaced in
// Facts unconditionally (name + reason per entry), and — only when every
// other signal here would otherwise produce verified-fail — capping that
// at not-checkable instead, since a pipeline this collector couldn't
// fully inspect means "no SAST tool configured" rests on incomplete
// evidence, not a confirmed absence. Mirrors the identical treatment
// already shipped for azuredevops/scahistory's checkToolConfigured.
func checkToolConfigured(org, repo string, matched []pipelinehistory.MatchedPipeline, sameRepoSkips []pipelinehistory.SkippedPipeline, enablement pipelinehistory.RepoEnablementInfo, enablementErr error, prov []model.Provenance) model.CheckResult {
	const id = idToolConfigured

	hasAny, hasHighOrMedium := matchConfidence(matched)

	skipDetails := make([]map[string]any, 0, len(sameRepoSkips))
	for _, sp := range sameRepoSkips {
		skipDetails = append(skipDetails, map[string]any{"name": sp.Name, "reason": sp.Reason})
	}
	hasSkips := len(sameRepoSkips) > 0

	if !hasAny && enablementErr != nil && !isAdvSecNotFoundErr(enablementErr) {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("no SAST tool detected in any pipeline, and the GHAzDO repo-enablement query itself failed: %s", advSecNotCheckableReason(enablementErr, org, repo)),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"skipped_pipelines": skipDetails},
		}
	}

	setupConfigured := enablementErr == nil && enablement.CodeQLEnabled

	names := map[string]bool{}
	for _, mp := range matched {
		for _, m := range mp.Matches {
			names[m.Name] = true
		}
	}

	status, reason := model.StatusVerifiedFail, "no SAST tool detected in any pipeline, and GHAzDO CodeQL default setup is not configured"
	switch {
	case hasHighOrMedium || setupConfigured:
		status = model.StatusVerifiedPass
		reason = "a SAST tool is configured"
	case hasAny:
		status = model.StatusPartial
		reason = "only a low-confidence (pipeline/step-name-only) match was found — not enough signal alone to confirm a SAST tool is genuinely configured"
	case hasSkips:
		status = model.StatusNotCheckable
		reason = fmt.Sprintf("no matched SAST pipeline evidence and GHAzDO CodeQL default setup is not configured, but %d pipeline(s) in this repo could not be fully inspected — a confirmed absence can't be asserted over incomplete evidence", len(sameRepoSkips))
	}

	toolNames := make([]string, 0, len(names))
	for n := range names {
		toolNames = append(toolNames, n)
	}
	sort.Strings(toolNames)

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"tool_names":                  toolNames,
			"ghazdo_codeql_default_setup": setupConfigured,
			"low_confidence_match_only":   hasAny && !hasHighOrMedium && !setupConfigured,
			"skipped_pipelines":           skipDetails,
		},
	}
}

// checkRanPerRelease implements the issue's three-tier semantics: a
// release with zero matched builds at all is a real gap (verified-fail); a
// release where the tool ran but never succeeded is "configured but not
// operating cleanly" (partial); only every release having at least one
// successful build is verified-pass.
//
// dropped names every release tag matching the lookback window's tag
// pattern whose DATE pipelinehistory.ResolveReleases could not resolve —
// the tag's own commit SHA is always already in hand straight from the
// refs listing itself (ObjectID for a lightweight tag, PeeledObjectID for
// an annotated one), so "could not be dated" is the accurate description
// here, not "could not be resolved to a commit" (found in review: an
// earlier draft of this comment/these reasons said the latter, which is
// simply wrong — the commit is never what's missing). See the package
// doc comment for why this collector applies the GitHub twin's "any drop
// caps at partial" rule to that UNCONDITIONAL list, a deliberate choice,
// not an oversight.
//
// defaultSetupOnly is true when GHAzDO CodeQL default setup is this repo's
// ONLY SAST evidence — no signature-matched pipeline at all (issue #184,
// twin of #183's C06 sca-history fix; keep the wording symmetric with
// that check's own identical injectionOnly guard). Default-setup scans
// aren't observable through the Pipelines/Builds APIs this collector uses
// — the package doc comment explains why, and checkCadence already
// applies exactly this principle — so with zero matched pipelines,
// coverage has nothing to link any release's build to, and every release
// would read CoverageMissing: this check would otherwise report
// verified-fail ("no matched SAST run at all") in the same breath
// checkToolConfigured reports verified-pass for the identical evidence.
//
// hasMatchedPipelines/sameRepoSkips are checked next (issue #202's review
// finding), same reasoning as defaultSetupOnly but a different cause: with
// zero matched pipelines, every release's coverage reads CoverageMissing
// regardless of why matched is empty — a genuine absence and an inspection
// failure look identical to LinkRunsToReleases. If a same-repo skip exists
// (and default setup isn't already covering the case), that's not a
// confirmed absence, and reporting verified-fail here would contradict
// C05.sast.tool-configured's own not-checkable for the identical evidence
// (two panels of one pack, opposite claims).
//
// defaultSetupOnly is checked BEFORE sameRepoSkips, and this precedence is
// load-bearing, not incidental (pinned by
// TestCheckRanPerRelease_DefaultSetupOnlyWithSkip_DefaultSetupReasonWins):
// when defaultSetupOnly is true, checkToolConfigured has already reported
// verified-pass for the identical evidence ("a SAST tool is configured").
// The sameRepoSkips branch's own wording — "no matched SAST pipeline
// evidence... a confirmed absence can't be asserted" — would be actively
// wrong next to that verified-pass, not merely a worse explanation; it
// reintroduces the exact cross-check contradiction this whole guard exists
// to remove. The defaultSetupOnly reason is correct regardless of whether a
// same-repo skip also happened to exist, so it wins unconditionally when
// both are true — a same-repo skip's Facts are still attached below so the
// pack doesn't silently drop the record of an uninspectable pipeline just
// because default setup explains the status.
func checkRanPerRelease(org, repo string, filteredReleases []pipelinehistory.ReleaseInfo, coverage []pipelinehistory.ReleaseCoverage, dropped []string, buildsErr error, defaultSetupOnly, hasMatchedPipelines bool, sameRepoSkips []pipelinehistory.SkippedPipeline, prov []model.Provenance) model.CheckResult {
	const id = idRanPerRelease

	if defaultSetupOnly {
		result := model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "a SAST tool is configured via GHAzDO CodeQL default setup, but this collector has no verified way to observe its scan history per release via the Pipelines/Builds APIs it uses — ran-per-release can only be computed from a matched pipeline's own build history",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
		if len(sameRepoSkips) > 0 {
			skipDetails := make([]map[string]any, 0, len(sameRepoSkips))
			for _, sp := range sameRepoSkips {
				skipDetails = append(skipDetails, map[string]any{"name": sp.Name, "reason": sp.Reason})
			}
			result.Facts = map[string]any{"skipped_pipelines": skipDetails}
		}
		return result
	}

	if !hasMatchedPipelines && len(sameRepoSkips) > 0 {
		skipDetails := make([]map[string]any, 0, len(sameRepoSkips))
		for _, sp := range sameRepoSkips {
			skipDetails = append(skipDetails, map[string]any{"name": sp.Name, "reason": sp.Reason})
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("no matched SAST pipeline evidence, but %d pipeline(s) in this repo could not be fully inspected — a confirmed absence can't be asserted over incomplete evidence", len(sameRepoSkips)),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"skipped_pipelines": skipDetails},
		}
	}

	if len(filteredReleases) == 0 {
		status, reason := model.StatusNotCheckable, "no release tags match the configured pattern within the lookback window"
		if len(dropped) > 0 {
			status = model.StatusPartial
			reason = fmt.Sprintf("%d release tag(s) matching the pattern could not be dated, so no release could be evaluated", len(dropped))
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
			Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"dropped_tags": dropped},
		}
	}

	if buildsErr != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not fetch build history to evaluate release coverage: %v", buildsErr),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	allRan, anyMissing := true, false
	table := make([]map[string]any, 0, len(coverage))
	for _, cvg := range coverage {
		table = append(table, map[string]any{"tag": cvg.Release.TagName, "status": string(cvg.Status)})
		if cvg.Status != pipelinehistory.CoverageRan {
			allRan = false
		}
		if cvg.Status == pipelinehistory.CoverageMissing {
			anyMissing = true
		}
	}

	status, reason := model.StatusPartial, "a matched SAST pipeline ran for every release, but not always successfully"
	switch {
	case anyMissing:
		status, reason = model.StatusVerifiedFail, "at least one release in the lookback window has no matched SAST build at all"
	case allRan && len(dropped) == 0:
		status, reason = model.StatusVerifiedPass, fmt.Sprintf("a SAST tool ran successfully for all %d release(s) in the lookback window", len(coverage))
	case allRan:
		status, reason = model.StatusPartial, fmt.Sprintf("a SAST tool ran successfully for all %d evaluated release(s), but %d release tag(s) could not be dated and were excluded from evaluation", len(coverage), len(dropped))
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"per_release": table, "dropped_tags": dropped},
	}
}

// checkCadence's own pass/fail is deliberately narrow — "is there any
// operational history at all to report on" — mirroring the GitHub twin.
// It applies the same confidence cap as checkToolConfigured: a
// low-confidence-only match can produce real-looking build counts, so
// reporting verified-pass here while tool-configured caps at partial for
// the identical evidence would read as a contradiction.
//
// The not-checkable gate is keyed on matched-pipeline evidence (hasAny)
// alone, not GHAzDO CodeQL default setup — see the package doc comment
// for exactly why: this collector has no verified way to observe
// default-setup's own scan history via the Pipelines/Builds APIs it
// uses (no build-definition-backed pipeline exists for it to match
// against), unlike GitHub's own default setup (a real,
// run-history-bearing virtual workflow this collector CAN query), so
// there is nothing this collector could compute cadence from when
// default setup is the only configured evidence [fixture-verify,
// issue #34/#155's S9 pass].
func checkCadence(org, repo string, matched []pipelinehistory.MatchedPipeline, enablement pipelinehistory.RepoEnablementInfo, enablementErr error, cadence pipelinehistory.CadenceStats, buildsErr error, prov []model.Provenance) model.CheckResult {
	const id = idCadence

	hasAny, hasHighOrMedium := matchConfidence(matched)
	setupConfigured := enablementErr == nil && enablement.CodeQLEnabled

	if !hasAny {
		reason := "no SAST tool is configured; cadence cannot be computed"
		if setupConfigured {
			reason = "a SAST tool is configured via GHAzDO CodeQL default setup, but this collector has no verified way to observe its scan history via the Pipelines/Builds APIs it uses — cadence can only be computed from a matched pipeline's own build history"
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: reason,
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	if buildsErr != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not fetch build history to compute cadence: %v", buildsErr),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	// lowConfidenceOnly deliberately omits "&& !setupConfigured" here,
	// unlike the GitHub twin's own identical formula (which DOES exclude
	// its defaultSetupConfigured(ds)) — found in review, a divergence
	// stated here on purpose, not a copy-paste gap: GitHub's default setup
	// contributes real, independently observable run history to cadence's
	// own RunCount (see the package doc comment), so a low-confidence
	// pipeline match alongside a genuinely-observed default-setup run
	// there is legitimately not "low-confidence-only" evidence. GHAzDO's
	// default setup contributes ZERO observable builds to this
	// collector's own RunCount (this collector has no verified way to
	// observe it at all, see checkToolConfigured's/the package's doc
	// comments) — so if every build actually counted in RunCount came
	// from a low-confidence-only pipeline match, setupConfigured being
	// true must not upgrade that to verified-pass; cadence stays capped
	// at partial regardless of GHAzDO enablement.
	lowConfidenceOnly := hasAny && !hasHighOrMedium

	status, reason := model.StatusVerifiedFail, "no SAST builds were found in the lookback window"
	switch {
	case cadence.RunCount == 0:
		// keep the verified-fail default set above
	case lowConfidenceOnly:
		status, reason = model.StatusPartial, fmt.Sprintf("%d build(s) observed, but only a low-confidence (pipeline/step-name-only) match identified the tool — not enough signal to confirm this cadence reflects genuine SAST activity", cadence.RunCount)
	default:
		status, reason = model.StatusVerifiedPass, fmt.Sprintf("%d SAST build(s) observed in the lookback window", cadence.RunCount)
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"run_count":                 cadence.RunCount,
			"runs_per_week":             cadence.RunsPerWeek,
			"longest_gap_days":          cadence.LongestGapDays,
			"low_confidence_match_only": lowConfidenceOnly,
		},
	}
}

func checkDefaultSetup(org, repo string, enablement pipelinehistory.RepoEnablementInfo, err error, prov []model.Provenance) model.CheckResult {
	const id = idDefaultSetup
	if err != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: advSecNotCheckableReason(err, org, repo),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	status, reason := model.StatusVerifiedFail, "GHAzDO CodeQL default setup is not configured for this repository"
	if enablement.CodeQLEnabled {
		status, reason = model.StatusVerifiedPass, "GHAzDO CodeQL default setup is configured for this repository"
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"codeql_enabled": enablement.CodeQLEnabled},
	}
}
