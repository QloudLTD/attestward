package scahistory

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/collect/github/runhistory"
	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/internal/model"
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
//
// skipped is this repo's runhistory.MatchWorkflows skip list (issue #178):
// surfaced in Facts unconditionally (path + reason per entry), and — only
// when every other signal here would otherwise produce verified-fail —
// capping that at not-checkable instead, since a workflow this collector
// couldn't fully inspect means "no SCA tool configured" rests on
// incomplete evidence, not a confirmed absence. Mirrors the identical
// treatment already shipped for azuredevops/scahistory's checkToolConfigured.
func checkToolConfigured(org, repo string, matched []runhistory.MatchedWorkflow, skipped []runhistory.SkippedWorkflow, dependabotConfigured bool, dependabotResp *ghgithub.Response, dependabotErr error, prov []model.Provenance) model.CheckResult {
	const id = "C06.sca.tool-configured"

	hasAny, hasHighOrMedium := matchConfidence(matched)

	skipDetails := make([]map[string]any, 0, len(skipped))
	for _, sw := range skipped {
		skipDetails = append(skipDetails, map[string]any{"path": sw.Path, "reason": sw.Reason})
	}
	hasSkips := len(skipped) > 0

	// If there's no workflow-based evidence at all AND the Dependabot
	// config fetch itself failed, dependabotConfigured reading false is
	// not a genuine "no config" observation — fetchDependabotConfig
	// already normalizes a legitimate "absent at both paths" outcome to
	// (err=nil, exists=false); any non-nil error here is a real failure
	// (permission denied, malformed YAML, ...), not a confirmed absence.
	// Silently treating it as "confirmed not configured" would assert a
	// fact this collector doesn't actually have evidence for.
	if !hasAny && dependabotErr != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("no SCA tool detected in any workflow, and the Dependabot config fetch itself failed: %s", notCheckableReason(dependabotResp, dependabotErr, org, repo)),
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
	// Gated on dependabotErr == nil, matching the two Facts keys below that
	// derive from this identical dependabotConfigured value (issue #287,
	// secondary finding). fetchDependabotConfig already normalizes every
	// real fetch failure to exists=false (so dependabotConfigured is false
	// whenever dependabotErr != nil regardless of this gate today) — but
	// leaving it implicit meant tool_names' own inclusion/exclusion of
	// "Dependabot" silently depended on that other function's contract
	// rather than this function's own explicit not-confirmed handling, the
	// same kind of implicit coupling that produced #287's main defect.
	// Explicit here so a future change to fetchDependabotConfig's contract
	// can't silently reintroduce it.
	if dependabotConfigured && dependabotErr == nil {
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
	case hasSkips:
		status = model.StatusNotCheckable
		reason = fmt.Sprintf("no matched SCA workflow evidence and no Dependabot config found, but %d workflow(s) in this repo could not be fully inspected — a confirmed absence can't be asserted over incomplete evidence", len(skipped))
	}

	toolNames := make([]string, 0, len(names))
	for n := range names {
		toolNames = append(toolNames, n)
	}
	sort.Strings(toolNames)

	// dependabot_configured and low_confidence_match_only both derive from
	// dependabotConfigured, which silently collapses to false whenever
	// dependabotErr != nil (fetchDependabotConfig returns exists=false
	// alongside any real error) — a query failure reads identically to a
	// genuine, confirmed "no config at either path" response. Asserting
	// either as a confirmed fact from an unconfirmed fetch is the same
	// inference C05 sasthistory's identical fix removes (issue #258): a
	// Facts consumer reading evidence.json directly has no adjacent
	// not-checkable status to reconcile it against, unlike a report.md
	// reader. Included only when the fetch actually succeeded, so an
	// unconfirmed state is honestly absent from the pack rather than
	// misreported as a confirmed false.
	facts := map[string]any{
		"tool_names":        toolNames,
		"skipped_workflows": skipDetails,
	}
	if dependabotErr == nil {
		facts["dependabot_configured"] = dependabotConfigured
		facts["low_confidence_match_only"] = hasAny && !hasHighOrMedium && !dependabotConfigured
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: facts,
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
func checkRanPerRelease(org, repo string, filteredReleases []runhistory.ReleaseInfo, coverage []runhistory.ReleaseCoverage, droppedTags int, dependabotOnly, dependabotUnknown, hasMatchedWorkflows bool, skipped []runhistory.SkippedWorkflow, relResp *ghgithub.Response, relErr error, runsErr error, prov []model.Provenance) model.CheckResult {
	const id = "C06.sca.ran-per-release"

	// dependabotUnknown (no workflow-based SCA evidence, and the
	// Dependabot config fetch itself failed) is checked before
	// dependabotOnly: with zero workflow matches, evaluating release
	// coverage would find no runs at all and confidently fail every
	// release, when the truth is "unknown whether Dependabot — which
	// would itself make this not-checkable, same as dependabotOnly below
	// — is this repo's sole SCA tool or genuinely absent."
	if dependabotUnknown {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "no workflow-based SCA tool was detected, and the Dependabot config fetch itself failed — it's unknown whether Dependabot is this repo's sole SCA tool (which would have no per-release run history to evaluate here) or absent entirely (see C06.sca.tool-configured)",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	if dependabotOnly {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "Dependabot has no discrete per-release run history to evaluate — see C06.sca.alerts-triaged for ongoing SCA activity instead",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	// A skip-caused false verified-fail (issue #202's review finding):
	// reaching this point with zero matched workflows means (per
	// dependabotOnly's own guard above) Dependabot isn't configured either
	// — genuinely zero SCA evidence from either source, except whatever a
	// same-repo skip couldn't confirm one way or the other. With zero
	// matched workflows, every release's coverage reads CoverageMissing
	// regardless of WHY matched is empty, so asserting verified-fail here
	// would contradict C06.sca.tool-configured's own not-checkable for the
	// identical evidence (two panels of one pack, opposite claims).
	if !hasMatchedWorkflows && len(skipped) > 0 {
		skipDetails := make([]map[string]any, 0, len(skipped))
		for _, sw := range skipped {
			skipDetails = append(skipDetails, map[string]any{"path": sw.Path, "reason": sw.Reason})
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("no matched SCA workflow evidence and no Dependabot config found, but %d workflow(s) in this repo could not be fully inspected — a confirmed absence can't be asserted over incomplete evidence", len(skipped)),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"skipped_workflows": skipDetails},
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

	// The coverage table is built unconditionally, runsErr or not — see
	// sasthistory's identical checkRanPerRelease for the full monotonicity
	// reasoning (issue #291): coverage status is monotone non-decreasing in
	// the runs pool, so a table that already reads "ran" (or "failed" —
	// attempted, just not successfully) for every release can't be
	// invalidated by whatever the failed fetch would have added; only a
	// table with a CoverageMissing entry actually depends on the missing
	// data.
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

	// runsErr (issue #287, narrowed by #291): mirrors sasthistory's
	// identical guard — see that package's checkRanPerRelease for the full
	// reasoning. Only taints the result when the table above actually
	// asserts an absence (anyMissing); a table with no missing release is
	// kept rather than discarded into not-checkable. Placed after the
	// coverage table is built (rather than before, as the pre-#291 total
	// taint was), keeping the same unconditional dropped_tags inclusion the
	// "nothing to evaluate" early return above already uses.
	if runsErr != nil && anyMissing {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not fetch workflow run history to evaluate release coverage: %v", runsErr),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"dropped_tags": droppedTags},
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
func checkDependabotConfig(org, repo string, cfg *dependabotConfig, configExists bool, detectedEcosystems []string, rootResp *ghgithub.Response, rootErr error, dependabotResp *ghgithub.Response, dependabotErr error, prov []model.Provenance) model.CheckResult {
	const id = "C06.sca.dependabot-config"

	if rootErr != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not list the repository's root directory to detect dependency manifests: %s", notCheckableReason(rootResp, rootErr, org, repo)),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	// fetchDependabotConfig already normalizes a legitimate "not present
	// at either .yml/.yaml path" outcome to (err=nil, exists=false); any
	// non-nil error here is a real failure (permission denied, malformed
	// YAML, ...), not a confirmed absence — distinct from the !configExists
	// branch below, which only runs once that's ruled out.
	if dependabotErr != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not fetch the repository's Dependabot config: %s", notCheckableReason(dependabotResp, dependabotErr, org, repo)),
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
//
// skipped is this repo's runhistory.MatchWorkflows skip list (issue #290):
// !found alone can't distinguish "no dependency-review workflow exists"
// from "one might exist among the workflows this collector couldn't fully
// inspect" — a same-repo skip caps that verified-fail at not-checkable
// instead, the same treatment checkToolConfigured and checkRanPerRelease
// already apply to identical evidence.
func checkDependencyReview(org, repo string, found bool, skipped []runhistory.SkippedWorkflow, workflow *mapping.WorkflowFile, fetchErr error, statusCheckNames []string, statusCheckErr error, prov []model.Provenance) model.CheckResult {
	const id = "C06.sca.dependency-review"

	if !found {
		if len(skipped) > 0 {
			skipDetails := make([]map[string]any, 0, len(skipped))
			for _, sw := range skipped {
				skipDetails = append(skipDetails, map[string]any{"path": sw.Path, "reason": sw.Reason})
			}
			return model.CheckResult{
				CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
				Reason: fmt.Sprintf("no matched dependency-review-action (or equivalent) workflow, but %d workflow(s) in this repo could not be fully inspected — a confirmed absence can't be asserted over incomplete evidence", len(skipped)),
				Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
				Facts: map[string]any{"skipped_workflows": skipDetails},
			}
		}
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
	switch {
	case summary.OpenCriticalCount > 0 && summary.OldestCriticalAgeDays > criticalTriageThresholdDays:
		// A definite finding outranks an incomplete one: we know something is
		// wrong, so say that rather than that we could not tell.
		status = model.StatusPartial
		reason = fmt.Sprintf("%d critical alert(s) open, oldest %.0f day(s) — beyond the %.0f-day triage window", summary.OpenCriticalCount, summary.OldestCriticalAgeDays, criticalTriageThresholdDays)
		if summary.OpenUnclassifiedCount > 0 {
			// Both problems are real, and the definite one leading must not
			// bury the other. Without this the Reason names only the critical
			// alert while the incompleteness sits in Facts, so a reader who
			// remediates the critical and re-scans meets the second finding as
			// a surprise rather than having been told about it the first time.
			reason += fmt.Sprintf("; a further %d open alert(s) could not be classified by severity, so there may be more",
				summary.OpenUnclassifiedCount)
		}
	case summary.OpenUnclassifiedCount > 0:
		// The pass says "no critical alert open beyond the window". That claim
		// cannot be made over an alert whose severity was never interpreted —
		// it may be the critical one. Passing here would tell a producer their
		// triage is clean, in a signed attestation, on the strength of a field
		// the build could not read.
		status = model.StatusPartial
		reason = fmt.Sprintf("%d of %d open alert(s) could not be classified by severity (oldest %.0f day(s)), "+
			"so a critical alert beyond the %.0f-day triage window cannot be ruled out",
			summary.OpenUnclassifiedCount, summary.OpenTotalCount, summary.OldestUnclassifiedAgeDays, criticalTriageThresholdDays)
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"open_critical_count": summary.OpenCriticalCount,
			"open_high_count":     summary.OpenHighCount,
			"open_medium_count":   summary.OpenMediumCount,
			"open_low_count":      summary.OpenLowCount,
			"open_total_count":    summary.OpenTotalCount,
			// Surfaced so the evidence and the conclusion agree. Without it the
			// severity buckets silently fail to sum to the total, and only a
			// reader who noticed the arithmetic would know why.
			"open_unclassified_count":      summary.OpenUnclassifiedCount,
			"oldest_unclassified_age_days": summary.OldestUnclassifiedAgeDays,
			"oldest_open_age_days":         summary.OldestOpenAgeDays,
			"triage_threshold_days":        criticalTriageThresholdDays,
		},
	}
}
