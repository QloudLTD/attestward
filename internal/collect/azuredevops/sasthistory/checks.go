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

// advSecNotCheckableReason distinguishes a 404 from a 403, falling back to
// a generic message otherwise — both now empirically settled (issue #190):
// S9's live run (2026-07-23, dev.azure.com/seciq, GHAzDO-unlicensed)
// observed the repo-enablement endpoint returning HTTP 200 with every flag
// false/null, never 403/404 — see pipelinehistory.FetchRepoEnablement's own
// doc comment for the same finding. That's narrower than it first looks
// (issue #225 review): S9's own scan PAT already carried vso.advsec, so a
// missing-scope 403 was never actually reachable in that run either —
// what's confirmed is only that licensing ISN'T the cause of a 403/404
// reaching this function. "The token lacks the vso.advsec scope" is the
// most likely remaining explanation for a 403, not an observed fact; other
// permission causes (tenant conditional access, an IP allow-list,
// project-level denial, an org policy restricting PAT access) can't be
// excluded from the response alone. What actually produces a 404 remains
// genuinely unconfirmed (S9 recorded no such response either) — and unlike
// an earlier version of this package (fixed in issue #226), a 404 is no
// longer treated as equivalent to "confirmed off" anywhere: every
// enablement error, 404 included, routes checkToolConfigured to
// not-checkable when there's no other evidence, the same as checkDefaultSetup
// already did for every error. The Reason strings below stay citation-free
// on purpose:
// they land in a specific customer's own evidence.json/report.md, and
// naming a third party's org/date there would be confusing at best,
// leaking at worst — the citation belongs here and in the generated
// rubric, not in a customer's signed pack.
func advSecNotCheckableReason(err error, org, repo string) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) {
		switch se.StatusCode {
		case http.StatusNotFound:
			return fmt.Sprintf(
				"GHAzDO repo-enablement query returned 404 for %s/%s — the cause is unconfirmed: an "+
					"unlicensed org/project reads HTTP 200 with every flag false/null instead, so licensing "+
					"is not a likely explanation for a 404 here — what actually produces one remains open "+
					"[fixture-verify]", org, repo)
		case http.StatusForbidden:
			return fmt.Sprintf(
				"GHAzDO repo-enablement query returned 403 for %s/%s — most likely the token lacks the "+
					"vso.advsec scope (licensing is ruled out as the cause: an unlicensed org/project's "+
					"enablement endpoint reads HTTP 200, not 403); other permission causes can't be "+
					"excluded from the response alone", org, repo)
		}
	}
	return fmt.Sprintf("could not query GHAzDO repo enablement for %s/%s: %v", org, repo, err)
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
// itself failed — for ANY reason, no exceptions — asserting verified-fail
// would claim a fact this collector doesn't actually have evidence for —
// this check goes not-checkable instead.
//
// Every enablement error is treated identically here now (issue #226,
// fixing a real defect #225's review surfaced but didn't fix): a previous
// version special-cased a 404 as "confirmed off" and let it fall through
// to the normal pass/fail logic — grounded in the belief that 404 meant
// "GHAzDO isn't licensed," which S9's live run falsified (issue #190): an
// unlicensed org/project reads HTTP 200 with every flag false/null, never
// 404. That left a signed verified-fail resting on an inference the
// evidence no longer supports: if this endpoint's pinned preview API
// version (`api-version=7.2-preview.3`) is ever retired, or any other
// cause produces a 404, a licensed org with CodeQL default setup
// genuinely ON would get a false "no SAST tool detected" verdict. Fixed
// by narrowing verified-fail to the one state that's actually
// observable and structured — enablementErr == nil (the query
// succeeded) AND enablement.CodeQLEnabled == false (the response itself
// says off, not an inference from a status code) — and routing every
// error, 404 included, to not-checkable, matching sibling
// checkDefaultSetup's own always-not-checkable-on-any-error treatment
// exactly. No signal is lost for a genuinely-off org: that state was
// always observable as this same HTTP-200-false response (proven by
// TestCollect_NoSASTToolAtAll_ToolConfiguredFailsCadenceNotCheckable,
// unaffected by this change since it involves no enablement error at
// all) — only the false confirmation inferred from an unconfirmed 404 is
// gone. A 403 was already routed here before this change (most likely a
// missing vso.advsec scope; licensing itself IS ruled out as the cause —
// see advSecNotCheckableReason above; other permission causes can't be
// excluded from the response alone) — that part is unchanged, only 404
// now joins it instead of being treated as equivalent to "off".
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

	if !hasAny && enablementErr != nil {
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

	// ghazdo_codeql_default_setup and low_confidence_match_only both derive
	// from setupConfigured, which silently collapses to false whenever
	// enablementErr != nil — a query failure reads identically to a
	// genuine, observed HTTP-200-false response. Asserting either as a
	// confirmed fact from an unconfirmed query is the exact inference
	// #226/#235/#244/#246/#248 already removed from this collector's
	// statuses, Reason strings, and rubric text, surviving here in Facts
	// instead (issue #258 — a Facts consumer reading evidence.json directly
	// has no adjacent not-checkable status to reconcile it against, unlike
	// a report.md reader). Included only when the enablement query actually
	// succeeded, so an unconfirmed state is honestly absent from the pack
	// rather than misreported as a confirmed false.
	facts := map[string]any{
		"tool_names":        toolNames,
		"skipped_pipelines": skipDetails,
	}
	if enablementErr == nil {
		facts["ghazdo_codeql_default_setup"] = setupConfigured
		facts["low_confidence_match_only"] = hasAny && !hasHighOrMedium && !setupConfigured
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: facts,
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
// enablementErr joins that same guard as a third cause (issue #235, found
// in review of #233): #233 narrowed checkToolConfigured's own verified-fail
// to require a genuinely observed enablement response, routing every
// enablement error — 404 included — to not-checkable instead. That fix
// only touched checkToolConfigured. This check reads the identical
// enablement result but never gated on enablementErr at all, so the exact
// scenario #233 fixed for tool-configured — no matched pipelines, the
// enablement query failed, so whether CodeQL default setup covers this
// repo can't be confirmed — left ran-per-release falling through to the
// normal coverage computation, which for zero matched pipelines always
// reads CoverageMissing and reports verified-fail. That reintroduced the
// identical "two panels of one pack, opposite claims" contradiction this
// guard already exists to prevent, just reached through enablementErr
// instead of sameRepoSkips: tool-configured saying "we can't tell" next to
// ran-per-release saying "it didn't run", for the same repo, from the same
// evidence gap. enablementErr can never be non-nil at the same time
// defaultSetupOnly is true — defaultSetupOnly's own formula requires
// enablementErr == nil — so this addition can't disturb the
// defaultSetupOnly-wins precedence discussed below.
//
// defaultSetupOnly is checked BEFORE this combined guard, and that
// precedence is load-bearing, not incidental (pinned by
// TestCheckRanPerRelease_DefaultSetupOnlyWithSkip_DefaultSetupReasonWins):
// when defaultSetupOnly is true, checkToolConfigured has already reported
// verified-pass for the identical evidence ("a SAST tool is configured").
// The combined guard's own wording — "no matched SAST pipeline evidence...
// a confirmed absence can't be asserted" — would be actively wrong next to
// that verified-pass, not merely a worse explanation; it reintroduces the
// exact cross-check contradiction this whole guard exists to remove. The
// defaultSetupOnly reason is correct regardless of whether a same-repo
// skip or an enablement error also happened to exist, so it wins
// unconditionally when both are true — a same-repo skip's Facts are still
// attached below so the pack doesn't silently drop the record of an
// uninspectable pipeline just because default setup explains the status.
func checkRanPerRelease(org, repo string, filteredReleases []pipelinehistory.ReleaseInfo, coverage []pipelinehistory.ReleaseCoverage, dropped []string, buildsErr, enablementErr error, defaultSetupOnly, hasMatchedPipelines bool, sameRepoSkips []pipelinehistory.SkippedPipeline, prov []model.Provenance) model.CheckResult {
	const id = idRanPerRelease

	if defaultSetupOnly {
		// dropped_tags is included unconditionally, matching the same
		// convention #250 established for the combined guard below and for
		// the len(filteredReleases) == 0 branch further down — found in
		// review of #250 (issue #252): this branch was one of two holdouts
		// still attaching Facts only when sameRepoSkips was non-empty (the
		// buildsErr branch further below was the other, found one review
		// round later — issue #254), so a repo with default setup on AND
		// dropped-but-undateable release tags lost the dropped-tag record
		// entirely.
		facts := map[string]any{"dropped_tags": dropped}
		if len(sameRepoSkips) > 0 {
			skipDetails := make([]map[string]any, 0, len(sameRepoSkips))
			for _, sp := range sameRepoSkips {
				skipDetails = append(skipDetails, map[string]any{"name": sp.Name, "reason": sp.Reason})
			}
			facts["skipped_pipelines"] = skipDetails
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "a SAST tool is configured via GHAzDO CodeQL default setup, but this collector has no verified way to observe its scan history per release via the Pipelines/Builds APIs it uses — ran-per-release can only be computed from a matched pipeline's own build history",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: facts,
		}
	}

	if !hasMatchedPipelines && (enablementErr != nil || len(sameRepoSkips) > 0) {
		reason := "no matched SAST pipeline evidence"
		switch {
		case enablementErr != nil && len(sameRepoSkips) > 0:
			reason += fmt.Sprintf(", the GHAzDO repo-enablement query itself failed (%s) so whether GHAzDO CodeQL default setup covers this repo instead can't be confirmed either, and %d pipeline(s) in this repo could not be fully inspected", advSecNotCheckableReason(enablementErr, org, repo), len(sameRepoSkips))
		case enablementErr != nil:
			reason += fmt.Sprintf(", and the GHAzDO repo-enablement query itself failed, so whether GHAzDO CodeQL default setup covers this repo instead can't be confirmed either: %s", advSecNotCheckableReason(enablementErr, org, repo))
		default:
			reason += fmt.Sprintf(", but %d pipeline(s) in this repo could not be fully inspected", len(sameRepoSkips))
		}
		reason += " — a confirmed absence can't be asserted over incomplete evidence"

		// dropped_tags is included unconditionally (found in review of
		// #245: an earlier version of this fix only ever set Facts when
		// sameRepoSkips was non-empty, so a repo with dropped-but-
		// undateable tags AND an enablement-query failure lost the
		// dropped-tag record entirely — this guard now runs before the
		// len(filteredReleases) == 0 check below ever gets a chance to
		// attach it). Matches that later branch's own convention of
		// always including dropped_tags, even when empty, rather than
		// conditionally.
		facts := map[string]any{"dropped_tags": dropped}
		if len(sameRepoSkips) > 0 {
			skipDetails := make([]map[string]any, 0, len(sameRepoSkips))
			for _, sp := range sameRepoSkips {
				skipDetails = append(skipDetails, map[string]any{"name": sp.Name, "reason": sp.Reason})
			}
			facts["skipped_pipelines"] = skipDetails
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: reason,
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: facts,
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
		// dropped_tags is included unconditionally, matching every other
		// return path in this function (issue #252, and this specific
		// holdout found in review of #254): a repo with a signature-matched
		// pipeline, one dateable release, one undateable release tag, and a
		// failed build-history fetch used to return not-checkable with no
		// Facts at all — losing the dropped-tag record the same way the
		// defaultSetupOnly and combined-guard branches above used to.
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not fetch build history to evaluate release coverage: %v", buildsErr),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"dropped_tags": dropped},
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
		// enablementErr is checked before falling back to "no SAST tool is
		// configured" (issue #246, found in review of #245): that wording
		// asserts a configuration fact the collector doesn't actually have
		// when the only reason setupConfigured is false is that the
		// enablement query itself failed — the same inference #226 removed
		// from checkToolConfigured's status, surviving here in prose only
		// (this check's own status was already correctly not-checkable
		// either way). Mirrors checkToolConfigured's identical wording for
		// its own analogous branch, with one deliberate addition: the other
		// two cases here both end by naming the consequence for cadence
		// specifically ("cadence can only be computed from…" / "cadence
		// cannot be computed") — checkToolConfigured's own sentence has no
		// such consequence to name, since it IS the tool-configured
		// question, but copying it verbatim here left this the one branch
		// that didn't say what the gap means for cadence (found in review
		// of #254).
		var reason string
		switch {
		case setupConfigured:
			reason = "a SAST tool is configured via GHAzDO CodeQL default setup, but this collector has no verified way to observe its scan history via the Pipelines/Builds APIs it uses — cadence can only be computed from a matched pipeline's own build history"
		case enablementErr != nil:
			reason = fmt.Sprintf("no SAST tool detected in any pipeline, and the GHAzDO repo-enablement query itself failed, so cadence cannot be computed: %s", advSecNotCheckableReason(enablementErr, org, repo))
		default:
			reason = "no SAST tool is configured; cadence cannot be computed"
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
