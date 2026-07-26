package sasthistory

import (
	"fmt"
	"net/http"
	"sort"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "github.com/sioakim/attestward/internal/collect/github"
	"github.com/sioakim/attestward/internal/collect/github/runhistory"
	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/model"
)

func notCheckableReason(resp *ghgithub.Response, err error, org, repo string) string {
	if resp != nil {
		switch {
		case resp.StatusCode == http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to read %s/%s", org, repo)
		case ghcollect.IsPlanGated(resp.StatusCode):
			return fmt.Sprintf("feature not available for %s/%s (plan-gated, or repository not found)", org, repo)
		}
	}
	return fmt.Sprintf("could not query %s/%s: %v", org, repo, err)
}

func defaultSetupConfigured(ds *ghgithub.DefaultSetupConfiguration) bool {
	return ds != nil && ds.GetState() == "configured"
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
func checkToolConfigured(org, repo string, matched []runhistory.MatchedWorkflow, skipped []runhistory.SkippedWorkflow, ds *ghgithub.DefaultSetupConfiguration, dsResp *ghgithub.Response, dsErr error, prov []model.Provenance) model.CheckResult {
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
	// above draws. Shared below between the not-checkable guard and the
	// Facts gate (issue #258): GetDefaultSetupConfiguration returns a nil
	// ds on ANY error, so defaultSetupConfigured(ds) can't itself
	// distinguish "confirmed off" from "query failed" — using its bare
	// value in Facts would assert a fact this collector doesn't actually
	// have evidence for whenever the failure isn't plan-gated.
	unconfirmedDSFailure := dsErr != nil && (dsResp == nil || !ghcollect.IsPlanGated(dsResp.StatusCode))

	if !hasAny && unconfirmedDSFailure {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("no SAST tool detected in any workflow, and the CodeQL default-setup query itself failed: %s", notCheckableReason(dsResp, dsErr, org, repo)),
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
	// setupConfigured, unreliable under exactly unconfirmedDSFailure — see
	// its own comment above. Included only when the default-setup query
	// actually resolved (succeeded, or a confirmed plan-gated absence), so
	// an unconfirmed state is honestly absent from the pack rather than
	// misreported as a confirmed false (issue #258).
	facts := map[string]any{
		"tool_names":        toolNames,
		"skipped_workflows": skipDetails,
	}
	if !unconfirmedDSFailure {
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
func checkRanPerRelease(org, repo string, filteredReleases []runhistory.ReleaseInfo, coverage []runhistory.ReleaseCoverage, droppedTags int, hasMatchedWorkflows bool, skipped []runhistory.SkippedWorkflow, prov []model.Provenance) model.CheckResult {
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
func checkCadence(org, repo string, matched []runhistory.MatchedWorkflow, ds *ghgithub.DefaultSetupConfiguration, cadence runhistory.CadenceStats, prov []model.Provenance) model.CheckResult {
	const id = "C05.sast.cadence"

	if !toolConfigured(matched, ds) {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "no SAST tool is configured; cadence cannot be computed",
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

func checkDefaultSetup(org, repo string, ds *ghgithub.DefaultSetupConfiguration, resp *ghgithub.Response, err error, prov []model.Provenance) model.CheckResult {
	const id = "C05.sast.default-setup"
	if err != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: notCheckableReason(resp, err, org, repo),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
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
