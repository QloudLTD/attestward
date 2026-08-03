package sasthistory

import (
	"fmt"
	"net/http"
	"sort"

	ghgithub "github.com/google/go-github/v75/github"

	"gitlab.com/sioakeim/attestward/internal/collect"
	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/collect/github/runhistory"
	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/internal/model"
)

func notCheckableReason(resp *ghgithub.Response, err error, org, repo string, scope collect.Scope) string {
	if resp != nil {
		switch {
		case resp.StatusCode == http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to read %s/%s", org, repo)
		case ghcollect.IsPlanGated(resp.StatusCode):
			return ghcollect.GatedRepoReason(scope.IsGHES, scope.GHESVersion, "feature", org, repo)
		}
	}
	return fmt.Sprintf("could not query %s/%s: %v", org, repo, err)
}

func defaultSetupConfigured(ds *ghgithub.DefaultSetupConfiguration) bool {
	return ds != nil && ds.GetState() == "configured"
}

// unconfirmedDSFailure reports whether the default-setup query itself
// failed in a way this collector can't read anything into — as opposed to
// a plan-gated failure (GHAS/default-setup genuinely unavailable), which
// IS a confirmed "not configured" fact. GetDefaultSetupConfiguration
// returns a nil ds on ANY error, so defaultSetupConfigured(ds) can't
// itself distinguish "confirmed off" from "query failed"; a Facts value
// or Reason derived from it needs this distinction to avoid asserting a
// fact this collector doesn't actually have evidence for. Shared by
// checkToolConfigured and checkCadence (issue #268, the same reasoning
// matchConfidence's own doc comment gives for being shared) rather than
// two independently-maintained copies of the identical carve-out.
func unconfirmedDSFailure(dsResp *ghgithub.Response, dsErr error) bool {
	return dsErr != nil && (dsResp == nil || !ghcollect.IsPlanGated(dsResp.StatusCode))
}

// toolConfigured reports whether any evidence at all (workflow match of
// any confidence, or CodeQL default setup) indicates a SAST tool is
// configured — used by checkCadence to decide whether "zero runs" means
// "not-checkable, nothing to have cadence for" or "verified-fail, tool
// configured but silent."
func toolConfigured(matched []runhistory.MatchedWorkflow, ds *ghgithub.DefaultSetupConfiguration) bool {
	return len(matched) > 0 || defaultSetupConfigured(ds)
}

// matchConfidence reports whether matched contains any SAST match at all
// (hasAny) and whether any of those matches are at least medium confidence
// (hasHighOrMedium) — shared by checkToolConfigured and checkCadence so
// both apply the exact same "low-confidence-only" definition rather than
// two independently-maintained copies drifting apart.
func matchConfidence(matched []runhistory.MatchedWorkflow) (hasAny, hasHighOrMedium bool) {
	for _, mw := range matched {
		for _, m := range mw.Matches {
			hasAny = true
			if m.Confidence != mapping.ConfidenceLow {
				hasHighOrMedium = true
			}
		}
	}
	return hasAny, hasHighOrMedium
}

// checkToolConfigured implements the confidence-capping rule from the
// issue: a low-confidence-only match (workflow name heuristic alone, no
// action slug or CLI pattern) can never alone justify verified-pass — it
// caps at partial, an honest acknowledgment that the signal is weak.
//
// It also guards against a subtler failure mode: GetDefaultSetupConfiguration
// returns a nil ds on ANY error, indistinguishable from a genuine
// successful "not configured" response. If there's no workflow-based
// evidence at all (hasAny false) and the default-setup query itself
// failed with something other than a legitimate plan-gated/not-found
// signal (dsResp/dsErr), defaultSetupConfigured(ds) reading false is not
// a real observation — it's an artifact of the failed call. Asserting
// verified-fail ("CodeQL default setup is not configured") in that case
// would claim a fact this collector doesn't actually have evidence for;
// this check goes not-checkable instead. A plan-gated failure (GHAS/
// default-setup genuinely unavailable, e.g. unlicensed) is a real "not
// configured" fact and is excluded from this guard. When there IS other
// workflow-based evidence (hasAny true), that evidence alone already
// determines pass/partial regardless of ds, so the guard doesn't apply —
// see TestCollect_DefaultSetupCallFailsOnlyThatCheckNotCheckable.
//
// skipped is this repo's runhistory.MatchWorkflows skip list (issue #178):
// surfaced in Facts unconditionally (path + reason per entry), and — only
// when every other signal here would otherwise produce verified-fail —
// capping that at not-checkable instead, since a workflow this collector
// couldn't fully inspect means "no SAST tool configured" rests on
// incomplete evidence, not a confirmed absence. Mirrors the identical
// treatment already shipped for azuredevops/scahistory's checkToolConfigured.
func checkToolConfigured(org, repo string, matched []runhistory.MatchedWorkflow, skipped []runhistory.SkippedWorkflow, ds *ghgithub.DefaultSetupConfiguration, dsResp *ghgithub.Response, dsErr error, scope collect.Scope, prov []model.Provenance) model.CheckResult {
	const id = "C05.sast.tool-configured"

	hasAny, hasHighOrMedium := matchConfidence(matched)

	skipDetails := make([]map[string]any, 0, len(skipped))
	for _, sw := range skipped {
		skipDetails = append(skipDetails, map[string]any{"path": sw.Path, "reason": sw.Reason})
	}
	hasSkips := len(skipped) > 0

	// unconfirmedDSFailure is a real default-setup query failure this
	// collector can't read anything into — as opposed to a plan-gated
	// failure (GHAS/default-setup genuinely unavailable), which IS a
	// confirmed "not configured" fact, same distinction the doc comment
	// above draws. Used below for both the not-checkable guard and the
	// Facts gate (issue #258): GetDefaultSetupConfiguration returns a nil
	// ds on ANY error, so defaultSetupConfigured(ds) can't itself
	// distinguish "confirmed off" from "query failed" — using its bare
	// value in Facts would assert a fact this collector doesn't actually
	// have evidence for whenever the failure isn't plan-gated.
	unconfirmedDS := unconfirmedDSFailure(dsResp, dsErr)

	if !hasAny && unconfirmedDS {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("no SAST tool detected in any workflow, and the CodeQL default-setup query itself failed: %s", notCheckableReason(dsResp, dsErr, org, repo, scope)),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"skipped_workflows": skipDetails},
		}
	}

	names := map[string]bool{}
	for _, mw := range matched {
		for _, m := range mw.Matches {
			names[m.Name] = true
		}
	}
	setupConfigured := defaultSetupConfigured(ds)

	status, reason := model.StatusVerifiedFail, "no SAST tool detected in any workflow, and CodeQL default setup is not configured"
	switch {
	case hasHighOrMedium || setupConfigured:
		status = model.StatusVerifiedPass
		reason = "a SAST tool is configured"
	case hasAny:
		status = model.StatusPartial
		reason = "only a low-confidence (workflow-name-only) match was found — not enough signal alone to confirm a SAST tool is genuinely configured"
	case hasSkips:
		status = model.StatusNotCheckable
		reason = fmt.Sprintf("no matched SAST workflow evidence and CodeQL default setup is not configured, but %d workflow(s) in this repo could not be fully inspected — a confirmed absence can't be asserted over incomplete evidence", len(skipped))
	}

	toolNames := make([]string, 0, len(names))
	for n := range names {
		toolNames = append(toolNames, n)
	}
	sort.Strings(toolNames)

	// codeql_default_setup and low_confidence_match_only both derive from
	// setupConfigured, unreliable under exactly unconfirmedDS — see its own
	// comment above. Included only when the default-setup query actually
	// resolved (succeeded, or a confirmed plan-gated absence), so an
	// unconfirmed state is honestly absent from the pack rather than
	// misreported as a confirmed false (issue #258).
	facts := map[string]any{
		"tool_names":        toolNames,
		"skipped_workflows": skipDetails,
	}
	if !unconfirmedDS {
		facts["codeql_default_setup"] = setupConfigured
		facts["low_confidence_match_only"] = hasAny && !hasHighOrMedium && !setupConfigured
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: facts,
	}
}

// checkRanPerRelease implements the issue's three-tier semantics: a
// release with zero matched runs at all is a real gap (verified-fail); a
// release where the tool ran but never succeeded is "configured but not
// operating cleanly" (partial, per the issue's own explicit wording); only
// every release having at least one successful run is verified-pass.
//
// droppedTags counts release tags that matched the lookback window's tag
// pattern but couldn't be resolved to a commit (see collectRepo) — those
// releases are excluded from coverage entirely, so a clean result under
// this circumstance is a false confidence: dropping to partial (never
// verified-pass, and never masking a genuine verified-fail from the
// releases that DID resolve) is the honest reflection of "some releases in
// scope were never actually evaluated."
func checkRanPerRelease(org, repo string, filteredReleases []runhistory.ReleaseInfo, coverage []runhistory.ReleaseCoverage, droppedTags int, hasMatchedWorkflows bool, skipped []runhistory.SkippedWorkflow, runsErr error, prov []model.Provenance) model.CheckResult {
	const id = "C05.sast.ran-per-release"

	// A skip-caused false verified-fail (issue #202's review finding): with
	// zero matched workflows, every release's coverage reads
	// CoverageMissing regardless of why matched is empty — a genuine
	// absence and an inspection failure look identical to
	// runhistory.LinkRunsToReleases. If a same-repo skip exists, that's not
	// a confirmed absence, and reporting verified-fail here would
	// contradict checkToolConfigured's own not-checkable for the identical
	// evidence (two panels of the same pack, opposite claims). Mirrors
	// checkToolConfigured's own skip-Facts + capping treatment.
	if !hasMatchedWorkflows && len(skipped) > 0 {
		skipDetails := make([]map[string]any, 0, len(skipped))
		for _, sw := range skipped {
			skipDetails = append(skipDetails, map[string]any{"path": sw.Path, "reason": sw.Reason})
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("no matched SAST workflow evidence, but %d workflow(s) in this repo could not be fully inspected — a confirmed absence can't be asserted over incomplete evidence", len(skipped)),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"skipped_workflows": skipDetails},
		}
	}

	if len(filteredReleases) == 0 {
		status, reason := model.StatusNotCheckable, "no releases match the configured release tag pattern within the lookback window"
		if droppedTags > 0 {
			status = model.StatusPartial
			reason = fmt.Sprintf("%d release tag(s) matched the lookback window but could not be resolved to a commit, so no release could be evaluated", droppedTags)
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
			Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"dropped_tags": droppedTags},
		}
	}

	// The coverage table is built unconditionally, runsErr or not — the
	// runsErr guard just below needs anyMissing to decide whether it
	// actually matters (issue #291): coverage status and RunCount are
	// monotone non-decreasing in the runs pool, since LinkRunsToReleases
	// can only turn CoverageMissing into CoverageFailed/CoverageRan as more
	// runs are added, never the reverse. A table that already reads "ran"
	// (or "failed" — attempted, just not successfully) for every release
	// can't be invalidated by whatever the failed fetch would have added;
	// only a table with a CoverageMissing entry actually depends on run
	// data this collector doesn't have, since more data could still have
	// filled that gap.
	allRan, anyMissing := true, false
	table := make([]map[string]any, 0, len(coverage))
	for _, c := range coverage {
		table = append(table, map[string]any{"tag": c.Release.TagName, "status": string(c.Status)})
		if c.Status != runhistory.CoverageRan {
			allRan = false
		}
		if c.Status == runhistory.CoverageMissing {
			anyMissing = true
		}
	}

	// runsErr (issue #287, narrowed by #291): collectRepo's workflow
	// run-history fetch failed for at least one matched workflow, so the
	// merged runs pool the coverage table above is computed from is
	// potentially incomplete — a release reading CoverageMissing here could
	// really be a release the failed workflow covered, not a confirmed
	// absence. That only matters when the table above actually asserts an
	// absence (anyMissing) — see the monotonicity comment above for why a
	// table with no missing release is trustworthy regardless. Mirrors
	// azuredevops/sasthistory's identical buildsErr guard for the
	// unconditional-taint case ADO has no partial pool to narrow.
	//
	// Reason uses runsErr's plain %v rather than routing through
	// notCheckableReason: that helper maps any 403 to "token lacks
	// permission to read org/repo," which is actively wrong for the
	// scenario #287 exists to name — a secondary rate limit, not a
	// permissions problem — and notCheckableReason has no way to tell them
	// apart from a bare *github.Response (FetchWorkflowRuns doesn't return
	// one). The raw API error text is less polished but not misleading;
	// don't "fix" this into notCheckableReason without solving that first.
	if runsErr != nil && anyMissing {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not fetch workflow run history to evaluate release coverage: %v", runsErr),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"dropped_tags": droppedTags},
		}
	}

	status, reason := model.StatusPartial, "a matched SAST tool ran for every release, but not always successfully"
	switch {
	case anyMissing:
		status, reason = model.StatusVerifiedFail, "at least one release in the lookback window has no matched SAST run at all"
	case allRan && droppedTags == 0:
		status, reason = model.StatusVerifiedPass, fmt.Sprintf("a SAST tool ran successfully for all %d release(s) in the lookback window", len(coverage))
	case allRan:
		status, reason = model.StatusPartial, fmt.Sprintf("a SAST tool ran successfully for all %d evaluated release(s), but %d release tag(s) could not be resolved and were excluded from evaluation", len(coverage), droppedTags)
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"per_release": table, "dropped_tags": droppedTags},
	}
}

// checkCadence's own pass/fail is deliberately narrow — "is there any
// operational history at all to report on" — not a judgment about whether
// the cadence itself is good; the actual numbers are Facts for the report
// to render and a human to judge. It applies the same confidence cap as
// checkToolConfigured: a low-confidence-only match can produce real-looking
// run counts (the workflow genuinely ran, it's just unconfirmed that it's
// actually a SAST tool), so reporting verified-pass here while
// tool-configured caps at partial for the identical evidence would read as
// a contradiction — "unsure it's configured, but certain it ran on
// schedule."
//
// dsResp/dsErr (issue #268, the last default-setup/enablement-derived
// instance of the four-surface conflation #258 fixed for Facts elsewhere):
// lowConfidenceOnly's own
// !defaultSetupConfigured(ds) can't distinguish "default setup confirmed
// off" from "the query failed" any more than checkToolConfigured's
// identical expression could — GetDefaultSetupConfiguration returns a nil
// ds either way. Status/Reason keep using lowConfidenceOnly unguarded,
// same as checkToolConfigured's own setupConfigured-driven status/Reason
// stay unguarded — only the Facts value gets the unconfirmedDSFailure gate
// below, matching #258's precedent exactly rather than inventing a second
// shape.
func checkCadence(org, repo string, matched []runhistory.MatchedWorkflow, ds *ghgithub.DefaultSetupConfiguration, dsResp *ghgithub.Response, dsErr error, cadence runhistory.CadenceStats, runsErr error, prov []model.Provenance) model.CheckResult {
	const id = "C05.sast.cadence"

	if !toolConfigured(matched, ds) {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "no SAST tool is configured; cadence cannot be computed",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	// runsErr (issue #287): a SAST tool IS configured, but at least one
	// matched workflow's run-history fetch failed, so cadence.RunCount
	// below is a potential undercount, not a confirmed zero. Checked
	// before computing lowConfidenceOnly/status, mirroring
	// azuredevops/sasthistory's own buildsErr placement (right after its
	// identical tool-configured guard).
	//
	// Deliberately NOT narrowed the way checkRanPerRelease's identical
	// guard was (issue #291) — this asymmetry is the entire point of
	// #291, not an inconsistency to resolve. checkRanPerRelease can narrow
	// its taint to "only when the partial pool would already assert an
	// absence" because coverage status is monotone in the runs pool (more
	// runs can only turn CoverageMissing into CoverageFailed/CoverageRan,
	// never the reverse). run_count/runs_per_week/longest_gap_days here
	// are NOT monotone the same way: a partial pool could understate
	// RunCount, and — more importantly — could overstate LongestGapDays
	// (a run the failed workflow actually produced, sitting inside what
	// looks like the longest gap in the partial pool, would close that
	// gap once fetched). So ANY runsErr keeps tainting this check's whole
	// result unconditionally; do not "fix" this to match
	// checkRanPerRelease's narrower guard without solving that overstatement
	// risk first. Reason uses runsErr's plain %v rather than
	// notCheckableReason for the same reason checkRanPerRelease's own
	// guard does — see its doc comment.
	if runsErr != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not fetch workflow run history to compute cadence: %v", runsErr),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	hasAny, hasHighOrMedium := matchConfidence(matched)
	lowConfidenceOnly := hasAny && !hasHighOrMedium && !defaultSetupConfigured(ds)

	status, reason := model.StatusVerifiedFail, "no SAST runs were found in the lookback window"
	switch {
	case cadence.RunCount == 0:
		// keep the verified-fail default set above
	case lowConfidenceOnly:
		status, reason = model.StatusPartial, fmt.Sprintf("%d run(s) observed, but only a low-confidence (workflow-name-only) match identified the tool — not enough signal to confirm this cadence reflects genuine SAST activity", cadence.RunCount)
	default:
		status, reason = model.StatusVerifiedPass, fmt.Sprintf("%d SAST run(s) observed in the lookback window", cadence.RunCount)
	}

	// low_confidence_match_only is included only when the default-setup
	// query actually resolved (succeeded, or a confirmed plan-gated
	// absence) — same #258 gate checkToolConfigured applies to its own
	// copy of this value, so an unconfirmed state is honestly absent
	// rather than misreported as a confirmed true/false.
	facts := map[string]any{
		"run_count":        cadence.RunCount,
		"runs_per_week":    cadence.RunsPerWeek,
		"longest_gap_days": cadence.LongestGapDays,
	}
	if !unconfirmedDSFailure(dsResp, dsErr) {
		facts["low_confidence_match_only"] = lowConfidenceOnly
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: facts,
	}
}

// checkDefaultSetup probes GET /repos/{owner}/{repo}/code-scanning/default-setup
// — one of the endpoints issue #12's GHES epic names as licence/version-
// gated on GHES, unlike the shared repo/workflow/releases fetches
// notCheckableReason otherwise serves, which aren't GHAS-licensed
// features. ghesVersion (empty for github.com or an undetected GHES
// version) lets ghcollect.ClassifyGate override notCheckableReason's
// github.com-flavored "plan-gated" default with an accurate GHES reason
// when this specific endpoint is what gated.
func checkDefaultSetup(org, repo string, ds *ghgithub.DefaultSetupConfiguration, resp *ghgithub.Response, err error, scope collect.Scope, prov []model.Provenance) model.CheckResult {
	const id = "C05.sast.default-setup"
	if err != nil {
		reason := notCheckableReason(resp, err, org, repo, scope)
		statusCode := 0
		if resp != nil {
			statusCode = resp.StatusCode
		}
		var facts map[string]any
		if gate := ghcollect.ClassifyGate(statusCode, scope.IsGHES, scope.GHESVersion, ""); gate == ghcollect.GateKindLicence || gate == ghcollect.GateKindVersion {
			reason = ghcollect.GateReason(gate, fmt.Sprintf("CodeQL default setup for %s/%s", org, repo), scope.GHESVersion, "")
			// Only recorded when it was actually observed. Writing
			// "ghes_version": "" would assert an empty observation into a
			// signed pack, directly contradicting the Reason this same
			// branch produces when the version is unknown.
			if scope.GHESVersion != "" {
				facts = map[string]any{"ghes_version": scope.GHESVersion}
			}
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: reason,
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov, Facts: facts,
		}
	}

	state := ds.GetState()
	status, reason := model.StatusVerifiedFail, fmt.Sprintf("CodeQL default setup is %q", state)
	if state == "configured" {
		status, reason = model.StatusVerifiedPass, "CodeQL default setup is configured"
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"state": state, "languages": ds.Languages},
	}
}
