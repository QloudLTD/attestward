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

// advSecNotCheckableReason distinguishes a 404 from a 403, falling back to
// a generic message otherwise. what names which GHAzDO query failed
// ("repo-enablement" or "dependency-alerts") so the same helper serves both
// call sites in this package, but only "repo-enablement" carries a direct
// empirical citation (issue #190): S9's live run (2026-07-23,
// dev.azure.com/seciq, GHAzDO-unlicensed) observed the repo-enablement
// endpoint returning HTTP 200 with every flag false/null, never 403/404 —
// see pipelinehistory.FetchRepoEnablement's own doc comment for the same
// finding. That's narrower than it first looks (issue #225 review): S9's
// own scan PAT already carried vso.advsec, so a missing-scope 403 was
// never actually reachable in that run either — what's confirmed is only
// that licensing ISN'T the cause of a 403/404 reaching this function for
// the repo-enablement endpoint. "The token lacks the vso.advsec scope" is
// the most likely remaining explanation for a 403 there, not an observed
// fact; other permission causes can't be excluded from the response alone.
// The dependency-alerts endpoint's own not-enabled signal is a confirmed
// HTTP 400 with typeKey AdvSecNotEnabledException (see
// isAdvSecNotEnabledErr, matched before this fallback is ever reached for
// that call site), but S9 recorded nothing about what a 403/404 from THAT
// specific endpoint means, so its hedge stays [fixture-verify] rather than
// borrowing the repo-enablement endpoint's answer for an endpoint that was
// never tested. The Reason strings below stay citation-free on purpose:
// they land in a specific customer's own evidence.json/report.md, and
// naming a third party's org/date there would be confusing at best,
// leaking at worst — the citation belongs here and in the generated
// rubric, not in a customer's signed pack. Duplicated from C05
// sasthistory's identical-shaped helper — see the package doc comment's
// judgment call 6 for why this isn't hoisted into a shared location yet.
func advSecNotCheckableReason(err error, org, repo, what string) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) {
		enablementConfirmed := what == "repo-enablement"
		switch se.StatusCode {
		case http.StatusNotFound:
			if enablementConfirmed {
				return fmt.Sprintf(
					"GHAzDO %s query returned 404 for %s/%s — the cause is unconfirmed: an unlicensed "+
						"org/project reads HTTP 200 with every flag false/null instead, so licensing is "+
						"not a likely explanation for a 404 here — what actually produces one remains "+
						"open [fixture-verify]", what, org, repo)
			}
			return fmt.Sprintf(
				"GHAzDO %s query returned 404 for %s/%s — the cause is unconfirmed [fixture-verify: no "+
					"recorded response covers what a 404 from this endpoint specifically means]", what, org, repo)
		case http.StatusForbidden:
			if enablementConfirmed {
				return fmt.Sprintf(
					"GHAzDO %s query returned 403 for %s/%s — most likely the token lacks the vso.advsec "+
						"scope (licensing is ruled out as the cause: an unlicensed org/project's enablement "+
						"endpoint reads HTTP 200, not 403); other permission causes can't be excluded from "+
						"the response alone", what, org, repo)
			}
			return fmt.Sprintf(
				"GHAzDO %s query returned 403 for %s/%s — ambiguous: either the token lacks the vso.advsec "+
					"scope, or some other cause this collector can't distinguish from the response alone "+
					"[fixture-verify: no recorded response covers a 403 from this specific endpoint]", what, org, repo)
		}
	}
	return fmt.Sprintf("could not query GHAzDO %s for %s/%s: %v", what, org, repo, err)
}

// isAdvSecNotFoundErr reports whether err is a *azuredevops.StatusError
// with status 404 specifically — duplicated from C05 sasthistory's
// identical predicate (see this package's doc comment's judgment call 6
// for why). A 403 is deliberately excluded from "confirmed absence"
// treatment wherever this is checked: it most likely means this token
// lacks the vso.advsec scope on an org where GHAzDO genuinely IS licensed
// and configured, though other permission causes can't be excluded from
// the response alone — see advSecNotCheckableReason's own doc comment for
// why licensing itself is ruled out as the cause, and why that's a
// narrower claim than it first looks.
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
// a 404 is excluded from this guard — not because it's a confirmed "not
// provisioned" fact (what a 404 actually means here remains genuinely
// unconfirmed; see isAdvSecNotFoundErr's own doc comment) but because this
// collector treats it as equivalent to "off" as a deliberate policy
// choice — a 403 is deliberately NOT excluded, for the same reason C05's
// identical guard excludes it (see isAdvSecNotFoundErr's own doc comment).
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

// isAdvSecNotEnabledErr reports whether err is a *azuredevops.StatusError
// whose body carries typeKey "AdvSecNotEnabledException" — the confirmed
// signal GHAzDO dependency-scanning alerts are not enabled for a repo,
// empirically settled by S9's live run (2026-07-23, dev.azure.com/seciq,
// GHAzDO-unlicensed): GET .../alerts responded HTTP 400 with message
// "VS2150009: Advanced Security is not enabled for this repository." and
// this exact typeKey — the third answer nobody guessed (the [fixture-verify]
// hedge this predicate retires only ever considered 403/404). Matching the
// typeKey rather than the status code alone (400 is far too generic to
// treat as confirmed on its own) or the message text (GitHub's own
// alertsDisabledMessageSubstring shows free-text matching is the more
// fragile choice when a structured field is available) is deliberate.
func isAdvSecNotEnabledErr(err error) bool {
	var se *azuredevops.StatusError
	return errors.As(err, &se) && se.StatusCode == http.StatusBadRequest && se.TypeKey == "AdvSecNotEnabledException"
}

// checkAlertsTriaged reports active-critical dependency-scanning alert
// counts/ages as facts — never a judgment beyond the single documented
// threshold (criticalTriageThresholdDays) and the not-checkable/
// verified-fail gates below.
//
// A confirmed AdvSecNotEnabledException (see isAdvSecNotEnabledErr) maps to
// verified-fail, not not-checkable (issue #190, graduating the deliberate
// conservatism below once S9 supplied the missing evidence): the GitHub
// twin treats its own confirmed-disabled signal identically
// (alertsDisabledMessageSubstring -> verified-fail, "Dependabot alerts are
// not enabled for this repository") — a repo with GHAzDO dependency
// scanning alerts confirmed off is a real, meaningful compliance gap, not
// an unresolved unknown, the same reasoning that check's own doc comment
// gives. The stronger argument, found in review of #225: this codebase had
// already decided the opposite for the identical org state before this
// change. fixtures-ado.yaml recorded C04.deps.dependabot-alerts,
// C04.secrets.*, and C05.sast.default-setup as verified-fail for the same
// unlicensed seciq org (codeSecurityEnabled/etc. reading false is a real,
// verifiable "off" — see checkOrgSecurityDefaults) while this check alone
// read not-checkable for "triage the alerts that dependency scanning would
// produce" against the identical org — a real absence upstream and an
// unresolved unknown downstream of it. That mismatch, not merely the S9
// citation on its own, is what settles this: it was the anomaly, and this
// change removes it rather than creates one.
//
// A confirmed 404, by contrast, stays not-checkable (found in review,
// correcting this check's original design): "GHAzDO isn't licensed for
// this org/project" was only ever a LIKELY reading of 404 here, and S9's
// empirical pass, now complete, settled the confirmed-not-enabled signal as
// HTTP 400 + this typeKey — NOT 404 at all, so licensing is no longer a
// plausible explanation for a 404 reaching this check. What actually
// produces one remains genuinely unconfirmed [fixture-verify: no S9
// recorded response covers a 404 from this endpoint]. The GitHub twin's own
// doc comment for its analogous check records this exact style of
// assumption failing once already: an earlier version of that check copied
// a 404-means-disabled pattern from an unrelated endpoint without verifying
// it held for GitHub's real Dependabot-alerts response, and it didn't
// (GitHub's actual disabled-repo response is a 403 with a specific message,
// not a 404 at all) — the same caution that kept this check's own 404 case
// honest rather than guessing again now that the real signal turned out to
// be something else entirely. A 403 stays ambiguous/not-checkable
// regardless, same as every other advsec-backed check in this epic — S9
// recorded no response for a 403 from this specific endpoint. The Reason
// strings below stay citation-free on purpose (issue #225 review): they
// land in a specific customer's own evidence.json/report.md, and naming a
// third party's org/date there would be confusing at best, leaking at
// worst — the citation belongs here and in the generated rubric, not in a
// customer's signed pack.
func checkAlertsTriaged(org, repo string, criticalCount int, oldestAgeDays float64, oldestAgeKnown bool, err error, prov []model.Provenance) model.CheckResult {
	const id = idAlertsTriaged

	if err != nil {
		if isAdvSecNotEnabledErr(err) {
			return model.CheckResult{
				CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
				Reason: "GHAzDO dependency-scanning alerts are not enabled for this repository",
				Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			}
		}
		if isAdvSecNotFoundErr(err) {
			return model.CheckResult{
				CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
				Reason: fmt.Sprintf("GHAzDO dependency-scanning alerts query returned 404 for %s/%s — the cause is unconfirmed; a confirmed-not-enabled state for this endpoint reads HTTP 400 with typeKey AdvSecNotEnabledException instead, so licensing/not-enabled is not a likely explanation for a 404 here [fixture-verify: no recorded response covers what actually produces one]", org, repo),
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
