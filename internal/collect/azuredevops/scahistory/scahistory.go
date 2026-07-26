// Package scahistory implements C06 sca-history for Azure DevOps — the ADO
// counterpart to internal/collect/github/scahistory — under the same five
// check IDs (issue #34's check-identity model): tool-configured,
// ran-per-release, dependabot-config, dependency-review, alerts-triaged.
// Built on internal/collect/azuredevops/pipelinehistory (issue #152's
// shared release-resolution/pipeline-discovery/run-lookback machinery) the
// same way C05 sast-history is, and sharing that exact same collector
// architecture: one project-scoped Client, pipeline discovery
// (ListPipelines + MatchPipelines, category mapping.CategorySCA) and
// repository listing happen exactly ONCE per Collect, filtered client-side
// per repo via MatchedPipeline.RepositoryID/SkippedPipeline.RepositoryID —
// see sasthistory's own package doc comment for the full architecture
// rationale, which applies here unchanged (project-scoped, sequential
// per-repo processing, no ForEachRepo-style concurrent fan-out).
//
// Eight judgment calls this package makes, beyond what issue #152's C06
// section states directly:
//
//  1. ran-per-release reuses C05's unconditional-dropped-tags rule as-is
//     (ResolveReleases' dropped []string is unconditional; any drop caps
//     this check at partial the same way it caps C05's) — see
//     sasthistory's own package doc comment for the full
//     platform-asymmetry rationale; this package does not re-derive that
//     judgment call, only applies it.
//
//  2. tool-configured's GHAzDO-enablement signal is
//     codeSecurityFeatures.dependencyScanningInjectionEnabled ALONE, not
//     "dependencyScanningInjectionEnabled OR codeSecurityEnabled" as issue
//     #152's literal text reads. Microsoft's own docs state plainly:
//     "Dependency scanning requires running a pipeline configured with the
//     AdvancedSecurity-Dependency-Scanning@1 task or running a pipeline in
//     a repository with dependency scanning default setup enabled.
//     Enabling Advanced Security or Code Security doesn't execute
//     dependency scanning automatically." (Set up dependency scanning for
//     GHAzDO, learn.microsoft.com). codeSecurityEnabled is the umbrella
//     Code Security license/plan toggle — true even for a repo where
//     dependency scanning never runs at all — while
//     dependencyScanningInjectionEnabled is the actual default-setup
//     auto-injection mechanism, the direct GHAzDO analog of C05's
//     codeQLEnabled. Treating codeSecurityEnabled alone as sufficient
//     evidence that "an SCA tool is configured" would assert a fact this
//     collector doesn't have: a repo can have Code Security fully licensed
//     and enabled with zero dependency scanning ever having run.
//     codeSecurityEnabled is still surfaced as an informational Fact
//     (code_security_enabled) so a report reader can see the broader
//     license state, but it never independently drives this check's
//     verdict.
//
//  3. dependabot-config and dependency-review are not-checkable
//     unconditionally, per issue #152's own explicit instruction — Azure
//     DevOps has no per-repo config-file convention analogous to
//     .github/dependabot.yml (GHAzDO dependency scanning is
//     enablement-driven, see judgment call 2 above), and no pull-request
//     gate analogous to GitHub's dependency-review-action. Both checks'
//     Endpoints are deliberately empty (see collect.CheckMeta.Endpoints's
//     own doc comment: "may legitimately be empty... e.g.
//     C09.audit.log-streaming") — there is no ADO evidence source for
//     either, on any repo, ever.
//
//  4. alerts-triaged fetches ONLY active, critical-severity,
//     dependency-type alerts — issue #152's own literal query
//     (criteria.alertType=dependency&criteria.states=active&
//     criteria.severities=critical) — rather than fetching every open
//     alert of every severity and categorizing client-side the way the
//     GitHub twin's checkAlertsTriaged does. Facts here carry only
//     open_critical_count/oldest_critical_age_days, not the GitHub twin's
//     full high/medium/low/total breakdown — a deliberate, narrower scope
//     following the story's specified query, not an oversight. This
//     check's own 404-vs-403 message split (isAdvSecNotFoundErr picks a
//     more specific not-checkable Reason for a 404 than the
//     advSecNotCheckableReason fallback; both already return
//     not-checkable regardless) no longer mirrors anything in C05 — issue
//     #226 (PR #233) removed C05's own checkToolConfigured guard that used
//     to have a comparable split, since that guard's version let a 404
//     change the STATUS it returned, which this check's version never did.
//     advSecNotCheckableReason itself (not isAdvSecNotFoundErr) remains
//     duplicated from C05's own copy rather than shared — see judgment
//     call 6 below. A confirmed 404
//     stays NOT-CHECKABLE (found in review, correcting this check's
//     original design: "GHAzDO isn't licensed" was only ever a likely
//     reading of 404, and the GitHub twin's own doc comment for its
//     analogous check records this exact style of assumption failing once
//     already for a different endpoint) — deliberately conservative rather
//     than a guess. S9's live run (2026-07-23, dev.azure.com/seciq)
//     resolved which guess was right: the confirmed-not-enabled signal
//     turned out to be neither 404 nor 403 at all, but HTTP 400 with
//     typeKey AdvSecNotEnabledException — issue #190 added
//     isAdvSecNotEnabledErr to match it and graduated THAT case to
//     verified-fail (mirroring the GitHub twin's own confirmed-disabled ->
//     verified-fail treatment), while 404 stays not-checkable since S9
//     recorded no response for it specifically — see checkAlertsTriaged's
//     own doc comment. A 403 stays ambiguous/not-checkable regardless,
//     same as every other advsec-backed check in this epic.
//
//     Also found in review: a repo whose active criticals ALL have an
//     unparseable firstSeenDate must not read as verified-pass over
//     unknown ages (summarizeAlerts' oldestAgeKnown return distinguishes
//     this from the empty-alerts case); and fetchActiveCriticalDependencyAlerts'
//     own doc comment now names a related [fixture-verify] risk for S9:
//     without pagination or an explicit orderBy=firstSeen, the alert that
//     actually determines this check's verdict could be sitting on a page
//     this collector never fetches.
//
//     Also found in review (issue #154/#155's live audit-streams bug):
//     this function used to decode the alerts response as a bare JSON
//     array on the strength of Microsoft's own REST reference alone,
//     citing auditlogging's checkLogStreaming as an identical precedent —
//     a live scan proved checkLogStreaming's own identically-sourced
//     bare-array assumption (asserted with no hedge at all, not a tagged
//     guess) false: the real response was the ordinary {count,value}
//     envelope. Since this endpoint's real response has never been
//     observed at all (the live demo org 400s here, unlicensed for
//     GHAzDO), documentation alone is no longer trusted for it either:
//     fetchActiveCriticalDependencyAlerts now decodes tolerantly (bare
//     array first, {count,value} envelope as a fallback, with the same
//     count>0-but-empty-value wrong-envelope sanity guard
//     azuredevops.GetJSON itself applies) via its own alertsEnvelope
//     type, rather than assuming either shape and risking the same
//     silent decode-error-as-not-checkable failure mode on every real
//     org — or, worse, a garbage response silently decoding to zero
//     alerts and a false verified-pass.
//
//  5. Consuming pipelinehistory.MatchPipelines' skipped list (originally
//     issue #178, filed as a cross-platform completion item after C05
//     shipped without ever reading it; extended to this package's own
//     ran-per-release by issue #207 once #178 closed): tool-configured
//     and ran-per-release both filter skippedAll down to this repo's own
//     entries (by RepositoryID, the same field MatchedPipeline carries)
//     and surface them in Facts (skipped_pipelines: name + reason, per
//     entry) unconditionally. When a check's OTHER evidence would
//     otherwise produce verified-fail (no matched pipeline, no GHAzDO
//     signal for tool-configured; zero matched builds for ran-per-release
//     with zero matched pipelines overall), a same-repo skip caps that at
//     not-checkable instead: a pipeline this collector couldn't fully
//     inspect (a build-definition fetch failure, an unresolved YAML path,
//     a YAML fetch/parse failure, or an unresolved template reference)
//     means the "no SCA tool configured"/"no matched build" conclusion
//     rests on incomplete evidence, not a confirmed absence.
//
//  6. The shared-vs-local upstream-failure boundary follows the GitHub
//     twin's OWN explicit precedent, not C05's: GitHub's scahistory
//     package doc comment states plainly that, "unlike C05, only the repo
//     fetch and the workflow listing early-return allNotCheckable for
//     every check... a release-listing... failure is handled locally by
//     the one or two checks that actually consume that data." This ADO
//     package makes the identical choice: a project repositories/
//     pipelines-listing failure (or the named repo not being found)
//     blankets all five checks via allNotCheckable, exactly like C05 — but
//     a release-tag-resolution failure is LOCAL to ran-per-release only,
//     unlike C05 (where it blankets all four checks). tool-configured,
//     dependabot-config, dependency-review, and alerts-triaged never
//     consume release data at all, so failing them alongside a
//     release-resolution error the way C05 does would be strictly less
//     honest here, with no compensating benefit.
//
//  7. checkRanPerRelease's own injectionOnly guard (found in review, a
//     genuine bug in this package's original design): with GHAzDO
//     dependency scanning injection as this repo's ONLY SCA evidence (no
//     signature-matched pipeline at all), tool-configured legitimately
//     reports verified-pass (judgment call 2), but injected scanning runs
//     invisibly to this collector's own build-matching — there is no
//     matched pipeline whose builds ran-per-release could link any
//     release to, so every release read CoverageMissing and this check
//     independently concluded verified-fail ("zero matched SCA builds"),
//     a self-contradictory pair with tool-configured's own verified-pass
//     for the identical evidence. ran-per-release now reports
//     not-checkable instead, with a reason mirroring C05's own
//     cadence-style wording for its own analogous
//     codeQL-default-setup-only gap. injectionOnly and a same-repo skip
//     (judgment call 5) can both be true at once — injectionOnly wins
//     unconditionally (see checkRanPerRelease's own doc comment for why
//     the skip's wording would otherwise contradict tool-configured's
//     verified-pass for the identical evidence), with the skip's Facts
//     still attached so the pack doesn't lose the record of an
//     uninspectable pipeline. C05's identical gap (its own cadence check
//     has no such guard against its OWN codeQL-default-setup-only
//     composition) is being filed as its own issue, not fixed here — out
//     of scope for this package's own review round.
//
//  8. summarizeAlerts' oldestAgeKnown return distinguishes "zero critical
//     alerts" from "one or more critical alerts, but none of their dates
//     parsed" (found in review: an earlier version conflated the two,
//     since both left the zero-value oldestAgeDays at 0 — reading as
//     "well within the triage window" for a genuinely unknown age, a
//     false verified-pass). See checkAlertsTriaged's own doc comment.
//
// advSecNotCheckableReason is duplicated from C05's sasthistory package
// (not exported/shared) rather than hoisted into pipelinehistory or the
// azuredevops package — mirrors this epic's own established precedent for
// near-identical per-package logic with no single obvious shared caller
// yet (see e.g. sasthistory's own matchConfidence doc comment: "not
// shared across packages since... no shared caller to justify hoisting").
// isAdvSecNotFoundErr is NOT a C05 duplicate anymore (issue #236): C05's
// own copy was deleted in issue #226, since its only use there — a
// checkToolConfigured guard letting a 404 change that check's STATUS —
// was the unsound inference #226 fixed. This package's own copy survives
// for a narrower, still-sound purpose: checkAlertsTriaged's own
// isAdvSecNotFoundErr call (see its doc comment) only picks which
// not-checkable Reason text to write, never the status itself. A future
// third advsec-backed collector needing the identical split would be the
// point to reconsider
// this.
package scahistory

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/collect/azuredevops/pipelinehistory"
	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/model"
	"github.com/sioakim/attestward/mappings"
)

// collectorID must equal the GitHub twin's Collector string exactly — the
// registry (internal/collect/registry.go's Register) panics if two
// platforms register the same check ID under different Collector strings.
const collectorID = "C06.sca-history"

const (
	idToolConfigured   = "C06.sca.tool-configured"
	idRanPerRelease    = "C06.sca.ran-per-release"
	idDependabotConfig = "C06.sca.dependabot-config"
	idDependencyReview = "C06.sca.dependency-review"
	idAlertsTriaged    = "C06.sca.alerts-triaged"
)

var checkIDs = []string{idToolConfigured, idRanPerRelease, idDependabotConfig, idDependencyReview, idAlertsTriaged}

// checkTitles reuses the GitHub twin's wording where it's platform-neutral
// (tool-configured, ran-per-release, dependency-review), and departs from
// it where the GitHub twin's own title names a GitHub-specific product
// ("Dependabot") that has no meaning on Azure DevOps — mirroring C05's own
// idDefaultSetup precedent (epic #34 open decision 4 permits Title to
// differ per platform). dependabot-config's title drops the "Dependabot"
// name entirely (there is no ADO analog to name); alerts-triaged's title
// names the real ADO product surface (GHAzDO) instead.
var checkTitles = map[string]string{
	idToolConfigured:   "An SCA tool is configured",
	idRanPerRelease:    "An SCA tool ran for each release in the lookback window",
	idDependabotConfig: "Dependency-scan config covers the repo's detected ecosystems",
	idDependencyReview: "Dependency review is enforced as a required check on pull requests",
	idAlertsTriaged:    "Open GHAzDO dependency-scanning alerts are triaged within the default window",
}

var checkRemediations = map[string]string{
	idToolConfigured: "Add a pipeline task using a recognized SCA action/CLI (see " +
		"mappings/scanner-signatures.yaml), or enable GHAzDO dependency scanning (Project Settings -> " +
		"Repositories -> [repo] -> Security -> GitHub Advanced Security -> enable Code Security, which " +
		"includes dependency scanning injection) — a pipeline whose name merely suggests SCA isn't enough " +
		"on its own; it needs a matched task/CLI invocation to count as more than a low-confidence signal.",
	idRanPerRelease: "Make sure the SCA pipeline's trigger actually fires on (or before) the commit each " +
		"release tag points at — e.g. trigger on push to the release branch — and that any build that did " +
		"fire completed with result==\"succeeded\" rather than failing or being canceled.",
	idDependabotConfig: "Not applicable to Azure DevOps — GHAzDO dependency scanning is enablement-driven " +
		"(Project Settings -> Repositories -> [repo] -> Security -> GitHub Advanced Security), not configured " +
		"via a checked-in file; see C06.sca.tool-configured instead.",
	idDependencyReview: "Not applicable to Azure DevOps — there is no pull-request dependency-review gate " +
		"equivalent to GitHub's dependency-review-action; GHAzDO surfaces dependency-scanning alerts (see " +
		"C06.sca.alerts-triaged) but does not block a PR merge on them.",
	idAlertsTriaged: "If GHAzDO dependency scanning is disabled entirely, enable it first (see " +
		"C06.sca.tool-configured). Once enabled, triage: repo -> Advanced Security -> filter by Critical " +
		"severity -> fix or dismiss (with a documented reason) any critical alert open longer than 30 days.",
}

// sharedUpstreamFetchFailureRubric is shared by all five checks: a project
// repositories/pipelines-listing failure, or the named repo not being found
// in the project, blankets every check via allNotCheckable — see the
// package doc comment's judgment call 6 for exactly why a release-tag-
// resolution failure is deliberately NOT included here (unlike C05), only
// in idRanPerRelease's own rubric below.
const sharedUpstreamFetchFailureRubric = "the project's repositories or pipelines couldn't be read " +
	"(403/other API error), or the named repository wasn't found in the project — collectRepo returns " +
	"not-checkable for every check on the first such failure; or the embedded scanner-signature registry " +
	"itself failed to load (a binary-level failure, independent of the scanned repo)"

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce — see checks.go for the pass/fail/partial logic each
// rubric below summarizes.
var checkRubrics = map[string]map[model.Status]string{
	idToolConfigured: {
		model.StatusVerifiedPass: "at least one matched pipeline reaches medium-or-high confidence (an " +
			"ado_task or run-pattern match, not just a suggestive pipeline/step name), or GHAzDO dependency " +
			"scanning injection (codeSecurityFeatures.dependencyScanningInjectionEnabled) reads true",
		model.StatusPartial: "only a low-confidence (pipeline/step-name-only) match was found in any " +
			"pipeline, and dependency scanning injection is not confirmed enabled — not enough signal alone " +
			"to confirm an SCA tool is genuinely configured",
		model.StatusVerifiedFail: "no pipeline match of any confidence was found, the GHAzDO repo-enablement " +
			"query itself succeeded (HTTP 200 — issue #236: an enablement-query failure routes to " +
			"not-checkable instead, see below) and its response reads dependencyScanningInjectionEnabled " +
			"false — whether the field explicitly reads false, reads null, or codeSecurityFeatures is " +
			"absent from the response body entirely, all three decode identically via Go's zero-value " +
			"fallback for a plain bool (see pipelinehistory.repoEnablementRaw's own doc comment) — and " +
			"every pipeline MatchPipelines inspected for this repo resolved cleanly (no same-repo skip) — " +
			"a real absence, not an evidence gap",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or there is no pipeline-based " +
			"evidence at all and the GHAzDO repo-enablement query itself failed, for any reason — a 404 " +
			"(issue #236: what actually produces one remains genuinely unconfirmed [fixture-verify]; no " +
			"longer treated as equivalent to confirmed-off, unlike an earlier version of this check) or a " +
			"403 (most likely the token lacks the vso.advsec scope; licensing is ruled " +
			"out as the cause — observed 2026-07-23 against dev.azure.com/seciq: an unlicensed org/project's " +
			"enablement endpoint reads HTTP 200, not 403 — but other permission causes can't be excluded " +
			"from the response alone) or any other API error " +
			"— an unresolved unknown, not a confirmed absence; or one or more " +
			"of this repo's own pipelines could not be fully inspected (a build-definition fetch failure, an " +
			"unresolved YAML path, a YAML fetch/parse failure, or an unresolved template reference — see " +
			"Facts.skipped_pipelines) and the evidence gathered would otherwise have produced verified-fail " +
			"— this check applies the honest not-checkable fix rather than asserting a confident absence over " +
			"incomplete evidence",
	},
	idRanPerRelease: {
		model.StatusVerifiedPass: "an SCA pipeline ran successfully (at least one matched build whose " +
			"result is \"succeeded\", case-insensitive) for every release in the lookback window, and every " +
			"matching release tag was successfully dated",
		model.StatusPartial: "one or more release tags matching the configured pattern could not be dated " +
			"(their commit is always already known straight from the refs listing itself — it's only the " +
			"date lookup that failed; this collector's own deliberate choice, inherited from C05, applies " +
			"that unconditionally, not only to tags provably inside the lookback window); if that leaves " +
			"nothing evaluable, the reason names the drop count directly, otherwise every evaluated release " +
			"still succeeded but the exclusion caps the result at partial; or a matched SCA pipeline ran for " +
			"every evaluated release, but not every build succeeded",
		model.StatusVerifiedFail: "at least one release in the lookback window has zero matched SCA builds " +
			"at all (not even a failed one), and — when there are zero matched pipelines overall — the " +
			"GHAzDO repo-enablement query itself succeeded (issue #244: an enablement-query failure routes " +
			"to not-checkable instead, see below) and every pipeline MatchPipelines inspected for this " +
			"repo resolved cleanly (no same-repo skip)",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or resolving this repo's release " +
			"tags failed (403/other API error) — unlike the four other checks in this package, this failure " +
			"is local to this check alone (see the package doc comment's judgment call 6); or GHAzDO " +
			"dependency scanning injection is this repo's ONLY SCA evidence (no signature-matched pipeline " +
			"at all) — injected scanning runs invisibly to this collector's own build-matching, so this check " +
			"has no verified way to observe it per release (see the package doc comment's judgment call 7); " +
			"or there are zero matched pipelines and either the GHAzDO repo-enablement query itself failed " +
			"(issue #244: whether dependency scanning injection covers this repo instead can't be confirmed " +
			"either, the same evidence gap C06.sca.tool-configured itself goes not-checkable for since issue " +
			"#236) or one or more of this repo's own pipelines could not be fully inspected (see " +
			"Facts.skipped_pipelines) — this check goes not-checkable rather than asserting a confident " +
			"absence over either gap — when dependency scanning injection is ALSO the sole evidence, that " +
			"cause wins and is what this Reason names (a same-repo skip is still recorded in Facts, just not " +
			"the stated cause when injection explains the status), since the skip/enablement-failure wording " +
			"would otherwise contradict tool-configured's verified-pass for the identical evidence (see the " +
			"package doc comment's judgment call 7); or no release tag matches the configured pattern within " +
			"the lookback window, and none of the tags that did match were dropped as unresolvable either " +
			"— genuinely nothing to evaluate; or the project's build history itself could not be fetched",
	},
	idDependabotConfig: {
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or (the common case) Azure DevOps " +
			"has no per-repo Dependabot-config-file convention at all — GHAzDO dependency scanning is " +
			"enablement-driven (see C06.sca.tool-configured), not configured via a checked-in file the way " +
			".github/dependabot.yml is on GitHub — this check has no ADO evidence source and reports " +
			"not-checkable unconditionally, on every repo, regardless of any other evidence gathered",
	},
	idDependencyReview: {
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or (the common case) Azure DevOps " +
			"has no pull-request dependency-review gate equivalent to GitHub's dependency-review-action — " +
			"this check has no ADO evidence source and reports not-checkable unconditionally, on every repo, " +
			"regardless of any other evidence gathered",
	},
	idAlertsTriaged: {
		model.StatusVerifiedPass: fmt.Sprintf("the active-critical-alerts query succeeded, and no alert has "+
			"been open longer than the %.0f-day triage window", criticalTriageThresholdDays),
		model.StatusPartial: fmt.Sprintf("one or more active critical dependency-scanning alerts are open, "+
			"and the oldest has been open longer than the %.0f-day triage window; or one or more active "+
			"critical alerts were found but none of their firstSeenDate values could be parsed, so their "+
			"age relative to the %.0f-day window is genuinely unknown", criticalTriageThresholdDays, criticalTriageThresholdDays),
		model.StatusVerifiedFail: "the alerts query failed with HTTP 400 and typeKey AdvSecNotEnabledException " +
			"— a confirmed signal GHAzDO dependency-scanning alerts are not enabled for this repository " +
			"(observed 2026-07-23 against dev.azure.com/seciq), a real compliance gap rather than an " +
			"unresolved unknown; matches the GitHub twin's identical treatment of its own confirmed-disabled " +
			"signal",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or the alerts query returned 404 — " +
			"the cause is unconfirmed: S9's 2026-07-23 live run against dev.azure.com/seciq settled the " +
			"confirmed-not-enabled signal as HTTP 400 with typeKey AdvSecNotEnabledException (see the " +
			"verified-fail row above), not 404, so licensing/not-enabled is no longer a plausible " +
			"explanation for a 404 here [fixture-verify: no recorded response covers what actually produces " +
			"one]; or the alerts query failed with a 403 (ambiguous: either a missing vso.advsec scope or " +
			"some other cause this collector can't distinguish from the response alone [fixture-verify: no " +
			"recorded response covers a 403 from this endpoint]) or another API error",
	},
}

// pipelineEvidenceEndpoints backs tool-configured and ran-per-release —
// project-scoped calls that happen once per Collect, shared across every
// repo in scope (mirrors sasthistory's identical pipelineEvidenceEndpoints).
var pipelineEvidenceEndpoints = []string{
	"GET dev.azure.com/{org}/{project}/_apis/git/repositories",
	"GET dev.azure.com/{org}/{project}/_apis/pipelines",
	"GET dev.azure.com/{org}/{project}/_apis/build/definitions/{definitionId}",
	"GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/items",
}

const enablementEndpoint = "GET advsec.dev.azure.com/{org}/{project}/_apis/management/repositories/{repository}/enablement"

var releaseEvidenceEndpoints = []string{
	"GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/refs",
	"GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/annotatedtags/{objectId}",
	"GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/commits/{commitId}",
}

const buildsEndpoint = "GET dev.azure.com/{org}/{project}/_apis/build/builds"

// alertsEndpoint documents the query parameters inline (per
// collect.CheckMeta.Endpoints' own doc comment: "when a query parameter
// changes what the endpoint actually returns... include it") — this exact
// filter (issue #152's own literal query) is what makes Facts here narrower
// than the GitHub twin's; see the package doc comment's judgment call 4.
const alertsEndpoint = "GET advsec.dev.azure.com/{org}/{project}/_apis/alert/repositories/{repository}/alerts" +
	"?criteria.alertType=dependency&criteria.states=active&criteria.severities=critical"

var checkEndpoints = map[string][]string{
	idToolConfigured:   append(append([]string{}, pipelineEvidenceEndpoints...), enablementEndpoint),
	idRanPerRelease:    append(append(append([]string{}, pipelineEvidenceEndpoints...), releaseEvidenceEndpoints...), buildsEndpoint),
	idDependabotConfig: nil,
	idDependencyReview: nil,
	idAlertsTriaged:    {alertsEndpoint},
}

// checkTokenScopes' dependabot-config/dependency-review entries read "n/a"
// rather than a scope name — there is no ADO API call backing either
// check, so no scope applies (see checkEndpoints' identical nil Endpoints
// for these two, and collect.CheckMeta.Endpoints' own doc comment for the
// established precedent this mirrors).
var checkTokenScopes = map[string]string{
	idToolConfigured:   "vso.build, vso.code (pipeline discovery and YAML fetch), vso.advsec (GHAzDO repo enablement)",
	idRanPerRelease:    "vso.build, vso.code",
	idDependabotConfig: "n/a — no ADO evidence source exists for this check; see its Rubric",
	idDependencyReview: "n/a — no ADO evidence source exists for this check; see its Rubric",
	idAlertsTriaged:    "vso.advsec (Alerts - List)",
}

const fixtureRef = "internal/collect/azuredevops/scahistory/scahistory_test.go"

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:          id,
			Platform:    "azuredevops",
			Title:       checkTitles[id],
			Collector:   collectorID,
			TokenScope:  checkTokenScopes[id],
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			FixtureRef:  fixtureRef,
		})
	}
}

// Collector implements C06 sca-history for Azure DevOps.
type Collector struct {
	client *azuredevops.Client
}

// New returns a C06 collector using client for all API calls — mirrors
// sasthistory.New's identical single-shared-Client architecture (see the
// package doc comment).
func New(client *azuredevops.Client) *Collector {
	return &Collector{client: client}
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. It never returns a non-nil
// top-level error for a per-repo API failure — see C01 org-security's
// Collect doc comment for why that matters for the rollup.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	registry, err := mapping.LoadScannerSignaturesFS(mappings.FS, "scanner-signatures.yaml")
	if err != nil {
		// The registry is this binary's own embedded data — a load
		// failure here means the binary itself is broken, not that this
		// scan's target has a problem. Every check for every repo becomes
		// not-checkable with the same underlying cause.
		var all []model.CheckResult
		for _, repo := range scope.Repos {
			all = append(all, allNotCheckable(scope.Org, repo, fmt.Sprintf("could not load the embedded scanner-signature registry: %v", err), nil)...)
		}
		return all, nil
	}

	repos, reposErr := pipelinehistory.FetchRepositories(ctx, c.client, scope.Project)

	var pipelines []pipelinehistory.PipelineRef
	var pipelinesErr error
	if reposErr == nil {
		pipelines, pipelinesErr = pipelinehistory.ListPipelines(ctx, c.client, scope.Project)
	}

	var matchedAll []pipelinehistory.MatchedPipeline
	var skippedAll []pipelinehistory.SkippedPipeline
	if reposErr == nil && pipelinesErr == nil {
		matchedAll, skippedAll = pipelinehistory.MatchPipelines(ctx, c.client, registry, scope.Project, pipelines, mapping.CategorySCA)
	}

	projectProv := c.client.Provenance()

	var all []model.CheckResult
	for _, repoName := range scope.Repos {
		all = append(all, c.collectRepo(ctx, scope, repoName, repos, reposErr, pipelinesErr, matchedAll, skippedAll, projectProv)...)
	}
	if all == nil {
		all = []model.CheckResult{}
	}
	return all, nil
}

// collectRepo resolves one repo's pipeline-match, release/build, GHAzDO
// enablement, and alert evidence, then emits all five CheckResults for it.
//
// Call order within a repo matters for provenance, mirroring sasthistory's
// identical choice: release resolution and build fetching run first (their
// combined provenance, plus the project-wide prefix, is shared by
// tool-configured/ran-per-release via plain prefix slicing), the GHAzDO
// repo-enablement call runs next (isolated as its own suffix, folded into
// tool-configured's own provenance since tool-configured is the only check
// here that reads it), and the dependency-alerts call runs last (isolated
// as alerts-triaged's own dedicated provenance — the only check that reads
// it). dependabot-config and dependency-review consume zero evidence (see
// the package doc comment's judgment call 3) and so carry no provenance at
// all.
func (c *Collector) collectRepo(ctx context.Context, scope collect.Scope, repoName string, repos []pipelinehistory.RepositoryInfo, reposErr, pipelinesErr error, matchedAll []pipelinehistory.MatchedPipeline, skippedAll []pipelinehistory.SkippedPipeline, projectProv []model.Provenance) []model.CheckResult {
	if reposErr != nil {
		return allNotCheckable(scope.Org, repoName, apiErrorReason(reposErr, "project repositories"), projectProv)
	}
	repo, found := pipelinehistory.FindRepository(repos, repoName)
	if !found {
		return allNotCheckable(scope.Org, repoName, fmt.Sprintf("repository %q not found in project %q", repoName, scope.Project), projectProv)
	}
	if pipelinesErr != nil {
		return allNotCheckable(scope.Org, repoName, apiErrorReason(pipelinesErr, "project pipelines"), projectProv)
	}

	var matched []pipelinehistory.MatchedPipeline
	var defIDs []int
	for _, mp := range matchedAll {
		if mp.RepositoryID == repo.ID {
			matched = append(matched, mp)
			defIDs = append(defIDs, mp.DefinitionID)
		}
	}
	var sameRepoSkips []pipelinehistory.SkippedPipeline
	for _, sp := range skippedAll {
		if sp.RepositoryID == repo.ID {
			sameRepoSkips = append(sameRepoSkips, sp)
		}
	}

	now := time.Now().UTC()
	windowStart := now.AddDate(0, -scope.LookbackMonths, 0)

	repoStart := len(c.client.Provenance())

	// Release resolution is LOCAL to ran-per-release only (unlike C05,
	// where a release-resolution failure blankets all four checks) — see
	// the package doc comment's judgment call 6.
	releases, dropped, relErr := pipelinehistory.ResolveReleases(ctx, c.client, scope.Project, repo.ID, scope.ReleaseTagPattern)
	var filteredReleases []pipelinehistory.ReleaseInfo
	if relErr == nil {
		filteredReleases = pipelinehistory.FilterReleasesInLookback(releases, scope.ReleaseTagPattern, scope.LookbackReleases, scope.LookbackMonths, now)
	}

	// definitionIDs must never be an empty-but-non-nil slice when there are
	// zero matched pipelines — FetchBuilds' own contract treats that as
	// "unfiltered, fetch everything," not "fetch nothing" (see
	// sasthistory's identical guard for the full correctness rationale).
	var runs []pipelinehistory.RunInfo
	var buildsErr error
	if relErr == nil && len(defIDs) > 0 {
		runs, buildsErr = pipelinehistory.FetchBuilds(ctx, c.client, scope.Project, repo.ID, defIDs, windowStart)
	}
	coverage := pipelinehistory.LinkRunsToReleases(filteredReleases, runs, repo.DefaultBranch)

	sharedProv := append(append([]model.Provenance{}, projectProv...), tailProvenance(c.client.Provenance(), repoStart)...)

	enablementStart := len(c.client.Provenance())
	enablement, enablementErr := pipelinehistory.FetchRepoEnablement(ctx, c.client, scope.Project, repo.ID)
	enablementProv := tailProvenance(c.client.Provenance(), enablementStart)
	toolConfiguredProv := append(append([]model.Provenance{}, sharedProv...), enablementProv...)

	// injectionOnly feeds checkRanPerRelease's own guard against the
	// self-contradictory pair found in review: GHAzDO dependency scanning
	// injection alone is enough for tool-configured's own verified-pass,
	// but it runs invisibly to this collector's own build-matching, so
	// ran-per-release must not independently conclude verified-fail from
	// the resulting zero matched builds — see checkRanPerRelease's own doc
	// comment.
	//
	// hasMatchedPipelines is deliberately derived from the same hasAny
	// matchConfidence already computed, not a second len(matched) > 0
	// check (mirrors sasthistory's identical choice) — the two are
	// equivalent only because pipelinehistory.MatchPipelines appends a
	// MatchedPipeline solely when len(categoryMatches) > 0, an invariant
	// that lives in another package; two independently-written predicates
	// for the same concept would silently disagree if that invariant ever
	// broke.
	hasAny, _ := matchConfidence(matched)
	injectionOnly := !hasAny && enablementErr == nil && enablement.DependencyScanningInjectionEnabled
	hasMatchedPipelines := hasAny

	alertsStart := len(c.client.Provenance())
	criticalAlerts, alertsErr := fetchActiveCriticalDependencyAlerts(ctx, c.client, scope.Project, repo.ID)
	alertsProv := tailProvenance(c.client.Provenance(), alertsStart)
	criticalCount, oldestAgeDays, oldestAgeKnown := summarizeAlerts(criticalAlerts, now)

	return []model.CheckResult{
		checkToolConfigured(scope.Org, repoName, matched, sameRepoSkips, enablement, enablementErr, toolConfiguredProv),
		checkRanPerRelease(scope.Org, repoName, filteredReleases, coverage, dropped, relErr, buildsErr, enablementErr, injectionOnly, hasMatchedPipelines, sameRepoSkips, sharedProv),
		checkDependabotConfig(scope.Org, repoName),
		checkDependencyReview(scope.Org, repoName),
		checkAlertsTriaged(scope.Org, repoName, criticalCount, oldestAgeDays, oldestAgeKnown, alertsErr, alertsProv),
	}
}

func allNotCheckable(org, repo, reason string, prov []model.Provenance) []model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	out := make([]model.CheckResult, 0, len(checkIDs))
	for _, id := range checkIDs {
		out = append(out, model.CheckResult{
			CheckID:    id,
			Title:      checkTitles[id],
			Status:     model.StatusNotCheckable,
			Reason:     reason,
			Scope:      model.ScopeRef{Org: org, Repo: repo},
			Provenance: prov,
		})
	}
	return out
}

func tailProvenance(prov []model.Provenance, skip int) []model.Provenance {
	if skip >= len(prov) {
		return []model.Provenance{}
	}
	return prov[skip:]
}

// apiErrorReason names a 403 explicitly and falls back to a generic message
// otherwise — mirrors sasthistory's identical helper for the same
// dev.azure.com-hosted calls (repositories, pipelines/definitions/items).
func apiErrorReason(err error, what string) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) && se.StatusCode == http.StatusForbidden {
		return fmt.Sprintf("token lacks permission to read %s", what)
	}
	return fmt.Sprintf("could not read %s: %v", what, err)
}
