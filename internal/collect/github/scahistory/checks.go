package scahistory

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/collect/github/runhistory"
	"github.com/sioakim/ssdf/internal/mapping"
	"github.com/sioakim/ssdf/internal/model"
)

// dependencyReviewSignatureID is the scanner-signatures.yaml entry
// checkDependencyReview looks for among a repo's matched SCA workflows.
const dependencyReviewSignatureID = "dependency-review-action"

// criticalTriageThresholdDays is the "documented default" the issue calls
// for: alert severity/age are always facts, never a judgment, EXCEPT this
// one threshold — a critical alert open longer than this caps
// alerts-triaged at partial. Configurable later (the issue's own words);
// v0.1 hardcodes it rather than adding a Scope field for a single check's
// single knob.
const criticalTriageThresholdDays = 30.0

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

// matchConfidence reports whether matched contains any SCA match at all
// (hasAny) and whether any of those matches are at least medium
// confidence (hasHighOrMedium) — mirrors sasthistory's identical helper;
// not shared across packages since each collector's matched-workflow
// stream is independently fetched and there's no shared caller to justify
// hoisting this into runhistory.
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

// checkToolConfigured implements the same confidence-capping rule as
// C05's identically-named check: a low-confidence-only match (workflow
// name heuristic alone) can never alone justify verified-pass — it caps
// at partial. A configured Dependabot (dependabotConfigured, derived from
// .github/dependabot.yml existing with at least one update entry) counts
// as a high-confidence signal on its own, the same way CodeQL default
// setup does for C05.
func checkToolConfigured(org, repo string, matched []runhistory.MatchedWorkflow, dependabotConfigured bool, prov []model.Provenance) model.CheckResult {
	const id = "C06.sca.tool-configured"

	hasAny, hasHighOrMedium := matchConfidence(matched)
	names := map[string]bool{}
	for _, mw := range matched {
		for _, m := range mw.Matches {
			names[m.Name] = true
		}
	}
	if dependabotConfigured {
		names["Dependabot"] = true
	}

	status, reason := model.StatusVerifiedFail, "no SCA tool detected in any workflow, and no Dependabot config found"
	switch {
	case hasHighOrMedium || dependabotConfigured:
		status = model.StatusVerifiedPass
		reason = "an SCA tool is configured"
	case hasAny:
		status = model.StatusPartial
		reason = "only a low-confidence (workflow-name-only) match was found — not enough signal alone to confirm an SCA tool is genuinely configured"
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
			"dependabot_configured":     dependabotConfigured,
			"low_confidence_match_only": hasAny && !hasHighOrMedium && !dependabotConfigured,
		},
	}
}

// checkRanPerRelease mirrors C05's three-tier per-release semantics
// exactly (verified-fail on any missing coverage, verified-pass only when
// every release ran cleanly and no tag was dropped, partial otherwise) —
// see runhistory.LinkRunsToReleases and sasthistory's checkRanPerRelease
// for the shared reasoning.
//
// dependabotOnly is true when a Dependabot config is the sole source of
// C06.sca.tool-configured's pass (no workflow-based SCA tool matched at
// all). Dependabot itself has no discrete per-release run history —
// unlike a GitHub Actions workflow, it isn't invoked per commit/release
// and has no run list ListWorkflowRunsByID could return — so fabricating
// a pass/fail verdict from Dependabot's mere presence would overstate what
// this check can actually verify. In that case the check is honestly
// not-checkable, pointing at C06.sca.alerts-triaged as the check that DOES
// have real Dependabot-sourced evidence (open alert counts/ages).
func checkRanPerRelease(org, repo string, filteredReleases []runhistory.ReleaseInfo, coverage []runhistory.ReleaseCoverage, droppedTags int, dependabotOnly bool, relResp *ghgithub.Response, relErr error, prov []model.Provenance) model.CheckResult {
	const id = "C06.sca.ran-per-release"

	if dependabotOnly {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "Dependabot has no discrete per-release run history to evaluate — see C06.sca.alerts-triaged for ongoing SCA activity instead",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	if relErr != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not list releases: %s", notCheckableReason(relResp, relErr, org, repo)),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
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

	status, reason := model.StatusPartial, "a matched SCA tool ran for every release, but not always successfully"
	switch {
	case anyMissing:
		status, reason = model.StatusVerifiedFail, "at least one release in the lookback window has no matched SCA run at all"
	case allRan && droppedTags == 0:
		status, reason = model.StatusVerifiedPass, fmt.Sprintf("an SCA tool ran successfully for all %d release(s) in the lookback window", len(coverage))
	case allRan:
		status, reason = model.StatusPartial, fmt.Sprintf("an SCA tool ran successfully for all %d evaluated release(s), but %d release tag(s) could not be resolved and were excluded from evaluation", len(coverage), droppedTags)
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"per_release": table, "dropped_tags": droppedTags},
	}
}

// checkDependabotConfig compares the ecosystems .github/dependabot.yml (or
// .yml's .yaml twin) configures against the ecosystems detectEcosystems
// found manifests for. A detected ecosystem with no matching
// package-ecosystem entry is a coverage gap (Facts: uncovered_ecosystems)
// — per the issue's own wording, this caps at partial, it never fails a
// repo that has SOME config just because it's incomplete.
//
// rootErr must be checked FIRST, before configExists: a failed
// root-directory listing (rootErr != nil) means detectedEcosystems is
// empty for an unknown reason, not because the repo genuinely has no
// manifests — treating that as "nothing to cover" would silently produce
// a false verified-pass (config exists, zero known ecosystems, so
// "covers everything") or a false "no manifests" not-checkable, neither
// of which reflects what was actually verified.
func checkDependabotConfig(org, repo string, cfg *dependabotConfig, configExists bool, detectedEcosystems []string, rootResp *ghgithub.Response, rootErr error, prov []model.Provenance) model.CheckResult {
	const id = "C06.sca.dependabot-config"

	if rootErr != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not list the repository's root directory to detect dependency manifests: %s", notCheckableReason(rootResp, rootErr, org, repo)),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	if !configExists {
		if len(detectedEcosystems) == 0 {
			return model.CheckResult{
				CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
				Reason: "no dependency manifest files detected; nothing for Dependabot to cover",
				Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			}
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: fmt.Sprintf("no Dependabot config found; %d detected ecosystem(s) are uncovered", len(detectedEcosystems)),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"detected_ecosystems": detectedEcosystems, "uncovered_ecosystems": detectedEcosystems},
		}
	}

	configured := cfg.ecosystems()
	var uncovered []string
	for _, e := range detectedEcosystems {
		if !configured[e] {
			uncovered = append(uncovered, e)
		}
	}
	sort.Strings(uncovered)

	status, reason := model.StatusVerifiedPass, "Dependabot config covers every detected ecosystem"
	if len(uncovered) > 0 {
		status = model.StatusPartial
		reason = fmt.Sprintf("Dependabot config exists, but %d detected ecosystem(s) are not covered", len(uncovered))
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"detected_ecosystems": detectedEcosystems, "uncovered_ecosystems": uncovered},
	}
}

// triggersOnPullRequest inspects a parsed workflow's `on:` value, which
// GitHub Actions allows as a bare string, a list of strings, or a map
// keyed by event name — mapping.WorkflowFile.On is left untyped for
// exactly this reason (see its doc comment).
func triggersOnPullRequest(on any) bool {
	switch v := on.(type) {
	case string:
		return v == "pull_request" || v == "pull_request_target"
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && (s == "pull_request" || s == "pull_request_target") {
				return true
			}
		}
	case map[string]any:
		if _, ok := v["pull_request"]; ok {
			return true
		}
		if _, ok := v["pull_request_target"]; ok {
			return true
		}
	}
	return false
}

// matchRequiredCheck reports how confidently workflowName is covered by
// the required status check context names: exact is true only for a
// case-insensitive EQUAL match (safe to treat as confirmed — GitHub uses
// the workflow name directly as the context for a simple single-job
// workflow); loose is true for a weaker substring match in either
// direction (e.g. a workflow named "PR Checks" against a required context
// "PR Checks / lint") — but a loose match can be dangerously wrong: that
// exact example is a DIFFERENT job's context within the same workflow,
// not proof the dependency-review job itself is required, since
// mapping.WorkflowFile doesn't carry per-job display names to check that
// precisely. Callers must never treat a loose-only match as equivalent to
// exact — see checkDependencyReview, which caps loose matches at partial.
func matchRequiredCheck(workflowName string, requiredNames []string) (exact, loose bool) {
	if workflowName == "" {
		return false, false
	}
	lower := strings.ToLower(workflowName)
	for _, n := range requiredNames {
		nl := strings.ToLower(n)
		if nl == lower {
			return true, true
		}
		if strings.Contains(nl, lower) || strings.Contains(lower, nl) {
			loose = true
		}
	}
	return false, loose
}

// checkDependencyReview looks for a matched dependency-review-action (or
// equivalent SCA-category) workflow, confirms it triggers on pull_request
// (dependency review's whole value proposition is gating PRs — a workflow
// that never runs on a PR trigger isn't actually gating anything), and
// cross-references whether it's a required status check via
// matchRequiredCheck. All I/O (finding the matched workflow, its
// content, and the required-status-check names) happens in the caller
// (collectRepo) — this function is pure given already-fetched data,
// matching this codebase's established check-function shape.
func checkDependencyReview(org, repo string, found bool, workflow *mapping.WorkflowFile, fetchErr error, statusCheckNames []string, statusCheckErr error, prov []model.Provenance) model.CheckResult {
	const id = "C06.sca.dependency-review"

	if !found {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: "no dependency-review-action (or equivalent) workflow detected",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	if fetchErr != nil || workflow == nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("dependency-review workflow was detected but could not be re-fetched to inspect its triggers: %v", fetchErr),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	if !triggersOnPullRequest(workflow.On) {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusPartial,
			Reason: "dependency review is configured but its workflow does not trigger on pull_request events",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"workflow_name": workflow.Name},
		}
	}

	if statusCheckErr != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusPartial,
			Reason: fmt.Sprintf("dependency review runs on pull requests, but required-status-check state could not be determined: %v", statusCheckErr),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"workflow_name": workflow.Name},
		}
	}

	exact, loose := matchRequiredCheck(workflow.Name, statusCheckNames)
	status, reason := model.StatusPartial, "dependency review runs on pull requests but is not confirmed as a required status check — a merge could still bypass it"
	switch {
	case exact:
		status, reason = model.StatusVerifiedPass, "dependency review runs on pull requests and is a required status check"
	case loose:
		reason = "dependency review runs on pull requests and a required status check name appears related, but an exact match could not be confirmed — GitHub's real check-run naming can't be derived precisely from the workflow name alone, so this is not asserted as verified"
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"workflow_name": workflow.Name, "required_status_check_names": statusCheckNames},
	}
}

// alertsDisabledMessageSubstring is the substring GitHub's own error
// message contains when Dependabot alerts are disabled for a repo (empirically
// confirmed: GET /repos/{owner}/{repo}/dependabot/alerts on a repo with the
// feature off returns 403 "Dependabot alerts are disabled for this
// repository.", not 404 — a genuinely-unauthorized request also returns
// 403, but with a different message, e.g. "You are not authorized to
// perform this operation."). This is GitHub's actual observed behavior for
// this endpoint, not the 404-means-disabled pattern C04 uses for the
// unrelated GetVulnerabilityAlerts boolean endpoint — an earlier version of
// this check copied that pattern without verifying it held here, and it
// didn't.
const alertsDisabledMessageSubstring = "disabled"

// checkAlertsTriaged reports Dependabot alert counts/ages as facts — never
// a judgment beyond the single documented threshold (see
// criticalTriageThresholdDays). A 403 whose message indicates the feature
// is disabled is treated as a real "off" state (verified-fail, a
// meaningful gap) rather than not-checkable; any other error (a genuine
// permission denial, a 404, a transient failure) is not-checkable — this
// collector can't distinguish "disabled" from "not found" from "no
// access" for those without GitHub confirming it via the message text.
func checkAlertsTriaged(org, repo string, resp *ghgithub.Response, err error, summary alertSummary, prov []model.Provenance) model.CheckResult {
	const id = "C06.sca.alerts-triaged"

	if err != nil {
		var ghErr *ghgithub.ErrorResponse
		if resp != nil && resp.StatusCode == http.StatusForbidden && errors.As(err, &ghErr) &&
			strings.Contains(strings.ToLower(ghErr.Message), alertsDisabledMessageSubstring) {
			return model.CheckResult{
				CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
				Reason: "Dependabot alerts are not enabled for this repository",
				Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			}
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: notCheckableReason(resp, err, org, repo),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	status, reason := model.StatusVerifiedPass, fmt.Sprintf("%d open alert(s), no critical alert open beyond the %.0f-day triage window", summary.OpenTotalCount, criticalTriageThresholdDays)
	if summary.OpenCriticalCount > 0 && summary.OldestCriticalAgeDays > criticalTriageThresholdDays {
		status = model.StatusPartial
		reason = fmt.Sprintf("%d critical alert(s) open, oldest %.0f day(s) — beyond the %.0f-day triage window", summary.OpenCriticalCount, summary.OldestCriticalAgeDays, criticalTriageThresholdDays)
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"open_critical_count":   summary.OpenCriticalCount,
			"open_high_count":       summary.OpenHighCount,
			"open_medium_count":     summary.OpenMediumCount,
			"open_low_count":        summary.OpenLowCount,
			"open_total_count":      summary.OpenTotalCount,
			"oldest_open_age_days":  summary.OldestOpenAgeDays,
			"triage_threshold_days": criticalTriageThresholdDays,
		},
	}
}
