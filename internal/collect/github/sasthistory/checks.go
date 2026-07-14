package sasthistory

import (
	"fmt"
	"net/http"
	"sort"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/mapping"
	"github.com/sioakim/ssdf/internal/model"
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
func toolConfigured(matched []matchedWorkflow, ds *ghgithub.DefaultSetupConfiguration) bool {
	return len(matched) > 0 || defaultSetupConfigured(ds)
}

// matchConfidence reports whether matched contains any SAST match at all
// (hasAny) and whether any of those matches are at least medium confidence
// (hasHighOrMedium) — shared by checkToolConfigured and checkCadence so
// both apply the exact same "low-confidence-only" definition rather than
// two independently-maintained copies drifting apart.
func matchConfidence(matched []matchedWorkflow) (hasAny, hasHighOrMedium bool) {
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
func checkToolConfigured(org, repo string, matched []matchedWorkflow, ds *ghgithub.DefaultSetupConfiguration, prov []model.Provenance) model.CheckResult {
	const id = "C05.sast.tool-configured"

	hasAny, hasHighOrMedium := matchConfidence(matched)
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
			"tool_names":                toolNames,
			"codeql_default_setup":      setupConfigured,
			"low_confidence_match_only": hasAny && !hasHighOrMedium && !setupConfigured,
		},
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
func checkRanPerRelease(org, repo string, filteredReleases []releaseInfo, coverage []releaseCoverage, droppedTags int, prov []model.Provenance) model.CheckResult {
	const id = "C05.sast.ran-per-release"

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
		if c.Status != coverageRan {
			allRan = false
		}
		if c.Status == coverageMissing {
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
func checkCadence(org, repo string, matched []matchedWorkflow, ds *ghgithub.DefaultSetupConfiguration, cadence cadenceStats, prov []model.Provenance) model.CheckResult {
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
