package scahistory

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

// criticalTriageThresholdDays mirrors the GitHub twin's identical constant
// — the one documented-default judgment threshold this check applies (the
// issue's own words); everything else about severity/age is a fact, never
// a judgment.
const criticalTriageThresholdDays = 30.0

// advSecNotCheckableReason distinguishes a 404 (a confirmed "GHAzDO isn't
// licensed for this org/project" fact) from a 403 (genuinely ambiguous: a
// missing vso.advsec scope reads identically to an unlicensed
// org/project), falling back to a generic message otherwise. what names
// which GHAzDO query failed ("repo-enablement" or "dependency-alerts") so
// the same helper serves both call sites in this package. Duplicated from
// C05 sasthistory's identical-shaped helper — see the package doc
// comment's judgment call 6 for why this isn't hoisted into a shared
// location yet. Both gated cases remain [fixture-verify]: which of 403/404
// (or both) a real unlicensed-org response actually returns is unconfirmed
// until issue #34/#155's S9 empirical pass.
func advSecNotCheckableReason(err error, org, repo, what string) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) {
		switch se.StatusCode {
		case http.StatusNotFound:
			return fmt.Sprintf(
				"GHAzDO %s query returned 404 for %s/%s — GHAzDO (GitHub Advanced Security for Azure DevOps) "+
					"isn't licensed for this org/project [fixture-verify: whether 404 always means specifically "+
					"this, rather than some other absence, is unconfirmed until issue #34/#155's S9 empirical "+
					"pass]", what, org, repo)
		case http.StatusForbidden:
			return fmt.Sprintf(
				"GHAzDO %s query returned 403 for %s/%s — ambiguous: either the token lacks the vso.advsec "+
					"scope, or the org/project isn't licensed for GHAzDO; Azure DevOps returns the same status "+
					"for both, so this can't be told apart from the response alone [fixture-verify, issue "+
					"#34/#155's S9 pass]", what, org, repo)
		}
	}
	return fmt.Sprintf("could not query GHAzDO %s for %s/%s: %v", what, org, repo, err)
}

// isAdvSecNotFoundErr reports whether err is a *azuredevops.StatusError
// with status 404 specifically — duplicated from C05 sasthistory's
// identical predicate (see this package's doc comment's judgment call 6
// for why). A 403 is deliberately excluded from "confirmed absence"
// treatment wherever this is checked: it can mean either genuine
// unlicensing OR simply that this token lacks the vso.advsec scope on an
// org where GHAzDO genuinely IS licensed and configured.
func isAdvSecNotFoundErr(err error) bool {
	var se *azuredevops.StatusError
	return errors.As(err, &se) && se.StatusCode == http.StatusNotFound
}

// matchConfidence reports whether matched contains any SCA match at all
// (hasAny) and whether any of those matches are at least medium confidence
// (hasHighOrMedium) — mirrors sasthistory's identical helper; not shared
// across packages since each collector's matched-pipeline stream is
// independently fetched and there's no shared caller to justify hoisting
// this into pipelinehistory.
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
// no ado_task or run-pattern match) can never alone justify verified-pass —
// it caps at partial. See the package doc comment's judgment call 2 for
// why dependencyScanningInjectionEnabled (not codeSecurityEnabled) is the
// GHAzDO signal this check treats as equivalent evidence to a real pipeline
// match.
//
// It also guards against a subtler failure mode, mirroring C05's identical
// guard: if there's no pipeline-based evidence at all (hasAny false) and
// the GHAzDO repo-enablement query itself failed with anything other than
// a 404, asserting verified-fail would claim a fact this collector doesn't
// actually have evidence for — this check goes not-checkable instead. Only
// a 404 is excluded from this guard (a confirmed "not provisioned" fact) —
// a 403 is deliberately NOT excluded, for the same reason C05's identical
// guard excludes it (see isAdvSecNotFoundErr's own doc comment).
//
// sameRepoSkips are this repo's own entries from
// pipelinehistory.MatchPipelines' skipped return (issue #178 — see the
// package doc comment's judgment call 5): surfaced in Facts unconditionally
// (name + reason per entry), and — only when every other signal here would
// otherwise produce verified-fail — capping that at not-checkable instead,
// since a pipeline this collector couldn't fully inspect means "no SCA
// tool configured" rests on incomplete evidence, not a confirmed absence.
func checkToolConfigured(org, repo string, matched []pipelinehistory.MatchedPipeline, sameRepoSkips []pipelinehistory.SkippedPipeline, enablement pipelinehistory.RepoEnablementInfo, enablementErr error, prov []model.Provenance) model.CheckResult {
	const id = idToolConfigured

	hasAny, hasHighOrMedium := matchConfidence(matched)

	// skipDetails/hasSkips are computed before the enablement-failure guard
	// below (found in review: an earlier version computed these further
	// down, so the guard's own not-checkable return carried no Facts at
	// all — contradicting this function's own "skips land in Facts
	// unconditionally" claim). Every return path from here on now carries
	// this same Facts entry.
	skipDetails := make([]map[string]any, 0, len(sameRepoSkips))
	for _, sp := range sameRepoSkips {
		skipDetails = append(skipDetails, map[string]any{"name": sp.Name, "reason": sp.Reason})
	}
	hasSkips := len(sameRepoSkips) > 0

	if !hasAny && enablementErr != nil && !isAdvSecNotFoundErr(enablementErr) {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("no SCA tool detected in any pipeline, and the GHAzDO repo-enablement query itself failed: %s", advSecNotCheckableReason(enablementErr, org, repo, "repo-enablement")),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"skipped_pipelines": skipDetails},
		}
	}

	setupConfigured := enablementErr == nil && enablement.DependencyScanningInjectionEnabled
	codeSecurityEnabled := enablementErr == nil && enablement.CodeSecurityEnabled

	names := map[string]bool{}
	for _, mp := range matched {
		for _, m := range mp.Matches {
			names[m.Name] = true
		}
	}

	status, reason := model.StatusVerifiedFail, "no SCA tool detected in any pipeline, and GHAzDO dependency scanning injection is not configured"
	switch {
	case hasHighOrMedium || setupConfigured:
		status = model.StatusVerifiedPass
		reason = "an SCA tool is configured"
	case hasAny:
		status = model.StatusPartial
		reason = "only a low-confidence (pipeline/step-name-only) match was found — not enough signal alone to confirm an SCA tool is genuinely configured"
	case hasSkips:
		status = model.StatusNotCheckable
		reason = fmt.Sprintf("no matched SCA pipeline evidence and dependency scanning injection is not configured, but %d pipeline(s) in this repo could not be fully inspected — a confirmed absence can't be asserted over incomplete evidence", len(sameRepoSkips))
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
			"tool_names":                            toolNames,
			"dependency_scanning_injection_enabled": setupConfigured,
			"code_security_enabled":                 codeSecurityEnabled,
			"low_confidence_match_only":             hasAny && !hasHighOrMedium && !setupConfigured,
			"skipped_pipelines":                     skipDetails,
		},
	}
}

// checkRanPerRelease implements the same three-tier semantics as C05's
// identically-named check: a release with zero matched builds at all is a
// real gap (verified-fail); a release where the tool ran but never
// succeeded is "configured but not operating cleanly" (partial); only every
// release having at least one successful build is verified-pass. See the
// package doc comment's judgment call 1 for why the unconditional dropped-
// tags rule is applied as-is, and judgment call 6 for why relErr (unlike
// C05) is handled locally here rather than by the caller's shared
// early-return.
//
// injectionOnly is true when GHAzDO dependency scanning injection is this
// repo's ONLY SCA evidence — no signature-matched pipeline at all (found
// in review: a self-contradictory pair this check originally produced).
// Injected scanning runs inside whatever pipeline builds a repo already
// has, invisibly to this collector's own signature matcher — with zero
// matched pipelines, coverage has nothing to link any release's build to,
// so every release reads CoverageMissing and this check would otherwise
// report verified-fail ("zero matched SCA builds") in the same breath
// checkToolConfigured reports verified-pass for the identical evidence.
//
// hasMatchedPipelines/sameRepoSkips (issue #207) are checked next, same
// reasoning as injectionOnly but a different cause: with zero matched
// pipelines, every release's coverage reads CoverageMissing regardless of
// why matched is empty — a genuine absence and an inspection failure look
// identical to LinkRunsToReleases. If a same-repo skip exists (and
// injection-only isn't already covering the case), that's not a confirmed
// absence, and reporting verified-fail here would contradict
// C06.sca.tool-configured's own not-checkable for the identical evidence
// (two panels of one pack, opposite claims).
//
// injectionOnly is checked BEFORE sameRepoSkips, and this precedence is
// load-bearing, not incidental (pinned by
// TestCheckRanPerRelease_InjectionOnlyWithSkip_InjectionOnlyReasonWins):
// when injectionOnly is true, checkToolConfigured has already reported
// verified-pass for the identical evidence ("an SCA tool is configured").
// The sameRepoSkips branch's own wording — "no matched SCA pipeline
// evidence... a confirmed absence can't be asserted" — would be actively
// wrong next to that verified-pass, not merely a worse explanation; it
// reintroduces the exact cross-check contradiction this whole guard exists
// to remove. The injectionOnly reason is correct regardless of whether a
// same-repo skip also happened to exist, so it wins unconditionally when
// both are true — a same-repo skip's Facts are still attached below so the
// pack doesn't silently drop the record of an uninspectable pipeline just
// because injection-only explains the status.
func checkRanPerRelease(org, repo string, filteredReleases []pipelinehistory.ReleaseInfo, coverage []pipelinehistory.ReleaseCoverage, dropped []string, relErr, buildsErr error, injectionOnly, hasMatchedPipelines bool, sameRepoSkips []pipelinehistory.SkippedPipeline, prov []model.Provenance) model.CheckResult {
	const id = idRanPerRelease

	if relErr != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not resolve this repo's release tags: %v", relErr),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	if injectionOnly {
		result := model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "an SCA tool is configured via GHAzDO dependency scanning injection, but this collector has no verified way to observe its scan history per release via the Pipelines/Builds APIs it uses — ran-per-release can only be computed from a matched pipeline's own build history",
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
			Reason: fmt.Sprintf("no matched SCA pipeline evidence, but %d pipeline(s) in this repo could not be fully inspected — a confirmed absence can't be asserted over incomplete evidence", len(sameRepoSkips)),
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

	status, reason := model.StatusPartial, "a matched SCA pipeline ran for every release, but not always successfully"
	switch {
	case anyMissing:
		status, reason = model.StatusVerifiedFail, "at least one release in the lookback window has no matched SCA build at all"
	case allRan && len(dropped) == 0:
		status, reason = model.StatusVerifiedPass, fmt.Sprintf("an SCA tool ran successfully for all %d release(s) in the lookback window", len(coverage))
	case allRan:
		status, reason = model.StatusPartial, fmt.Sprintf("an SCA tool ran successfully for all %d evaluated release(s), but %d release tag(s) could not be dated and were excluded from evaluation", len(coverage), len(dropped))
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"per_release": table, "dropped_tags": dropped},
	}
}

// checkDependabotConfig reports not-checkable unconditionally — Azure
// DevOps has no per-repo config-file convention analogous to
// .github/dependabot.yml (see the package doc comment's judgment call 3).
// It carries no Provenance: no API call backs this check on any platform
// state, so attaching the shared pipeline/release provenance would imply
// evidence this check never actually consulted.
func checkDependabotConfig(org, repo string) model.CheckResult {
	const id = idDependabotConfig
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "Azure DevOps has no per-repo dependency-scan config-file convention — GHAzDO dependency scanning is enablement-driven (see C06.sca.tool-configured), not configured via a checked-in file the way .github/dependabot.yml is on GitHub",
		Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: []model.Provenance{},
	}
}

// checkDependencyReview reports not-checkable unconditionally — Azure
// DevOps has no pull-request dependency-review gate equivalent to GitHub's
// dependency-review-action (see the package doc comment's judgment call
// 3). Carries no Provenance, for the same reason checkDependabotConfig
// doesn't.
func checkDependencyReview(org, repo string) model.CheckResult {
	const id = idDependencyReview
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "Azure DevOps has no pull-request dependency-review gate equivalent to GitHub's dependency-review-action — GHAzDO's dependency-scanning alerts (see C06.sca.alerts-triaged) surface vulnerabilities but do not block a PR merge on them",
		Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: []model.Provenance{},
	}
}

// checkAlertsTriaged reports active-critical dependency-scanning alert
// counts/ages as facts — never a judgment beyond the single documented
// threshold (criticalTriageThresholdDays) and the not-checkable gates
// below.
//
// A confirmed 404 maps to not-checkable, not verified-fail (found in
// review, correcting this check's original design): "GHAzDO isn't
// licensed for this org/project" is only a LIKELY reading of 404 here —
// the same [fixture-verify] hedge every other advsec-backed check in this
// epic already carries — and the GitHub twin's own doc comment for its
// analogous check (alertsDisabledMessageSubstring) records this exact
// style of assumption failing once already: an earlier version of that
// check copied a 404-means-disabled pattern from an unrelated endpoint
// without verifying it held for GitHub's real Dependabot-alerts response,
// and it didn't (GitHub's actual disabled-repo response is a 403 with a
// specific message, not a 404 at all). Reporting a confident verified-fail
// here would repeat that same mistake for THIS endpoint before issue
// #34/#155's S9 empirical pass has confirmed anything about it. This is a
// deliberate, temporary conservatism, not a claim that verified-fail is
// the wrong end state — S9 is the named point to revisit and likely
// upgrade this to verified-fail, once the evidence bar this collector
// holds itself to is actually met. A 403 stays ambiguous/not-checkable
// regardless, same as every other advsec-backed check in this epic.
func checkAlertsTriaged(org, repo string, criticalCount int, oldestAgeDays float64, oldestAgeKnown bool, err error, prov []model.Provenance) model.CheckResult {
	const id = idAlertsTriaged

	if err != nil {
		if isAdvSecNotFoundErr(err) {
			return model.CheckResult{
				CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
				Reason: fmt.Sprintf("GHAzDO dependency-scanning alerts query returned 404 for %s/%s — likely means GHAzDO isn't licensed for this org/project, but that reading is unconfirmed [fixture-verify, issue #34/#155's S9 pass — see this check's own doc comment for why this stays not-checkable rather than verified-fail until then]", org, repo),
				Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			}
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: advSecNotCheckableReason(err, org, repo, "dependency-alerts"),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	// oldestAgeKnown is false only when criticalCount > 0 but every one of
	// those alerts' firstSeenDate values failed to parse (see
	// summarizeAlerts' own doc comment) — reporting verified-pass in that
	// case would claim "no alert open beyond the window" over ages this
	// collector never actually determined (found in review: an earlier
	// version silently read the zero-value oldestAgeDays as "0 days old,"
	// a false pass).
	status, reason := model.StatusVerifiedPass, fmt.Sprintf("no active critical dependency-scanning alert open beyond the %.0f-day triage window", criticalTriageThresholdDays)
	switch {
	case criticalCount > 0 && !oldestAgeKnown:
		status = model.StatusPartial
		reason = fmt.Sprintf("%d active critical alert(s) found, but none of their firstSeenDate values could be parsed — can't confirm whether any has been open beyond the %.0f-day triage window", criticalCount, criticalTriageThresholdDays)
	case criticalCount > 0 && oldestAgeDays > criticalTriageThresholdDays:
		status = model.StatusPartial
		reason = fmt.Sprintf("%d active critical alert(s), oldest %.0f day(s) — beyond the %.0f-day triage window", criticalCount, oldestAgeDays, criticalTriageThresholdDays)
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"open_critical_count":       criticalCount,
			"oldest_critical_age_days":  oldestAgeDays,
			"oldest_critical_age_known": oldestAgeKnown,
			"triage_threshold_days":     criticalTriageThresholdDays,
		},
	}
}
