// Package scahistory implements C06 sca-history: whether an SCA
// (software-composition-analysis / dependency-scanning) tool is
// configured — via #16's scanner-signature matcher, or a Dependabot
// config — whether it actually ran for each recent release, whether
// Dependabot's ecosystem coverage matches the repo's real dependency
// manifests, whether dependency review gates pull requests, and whether
// open Dependabot alerts are being triaged in a timely manner (SSDF
// PW.4.4, RV.1.2, RV.2.1).
package scahistory

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	ghgithub "github.com/google/go-github/v75/github"

	"gitlab.com/sioakeim/attestward/internal/collect"
	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/collect/github/repoprotection"
	"gitlab.com/sioakeim/attestward/internal/collect/github/runhistory"
	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/internal/model"
	"gitlab.com/sioakeim/attestward/mappings"
)

const collectorID = "C06.sca-history"

var checkTitles = map[string]string{
	"C06.sca.tool-configured":   "An SCA tool is configured",
	"C06.sca.ran-per-release":   "An SCA tool ran for each release in the lookback window",
	"C06.sca.dependabot-config": "Dependabot config covers the repo's detected dependency ecosystems",
	"C06.sca.dependency-review": "Dependency review is enforced as a required check on pull requests",
	"C06.sca.alerts-triaged":    "Open Dependabot alerts are triaged within the default window",
}

var checkIDs = []string{
	"C06.sca.tool-configured",
	"C06.sca.ran-per-release",
	"C06.sca.dependabot-config",
	"C06.sca.dependency-review",
	"C06.sca.alerts-triaged",
}

var checkRemediations = map[string]string{
	"C06.sca.tool-configured": "Add a `.github/dependabot.yml` with at least one `updates:` entry, or add " +
		"a workflow using a recognized SCA action/CLI (see mappings/scanner-signatures.yaml) — a workflow " +
		"whose name merely suggests SCA isn't enough on its own; it needs a matched action/CLI invocation.",
	"C06.sca.ran-per-release": "Applies to a workflow-based SCA tool specifically (Dependabot has no " +
		"per-release run history to check). Make sure the SCA workflow's trigger fires on the commit each " +
		"release is cut from, and that any run that fired completed successfully.",
	"C06.sca.dependabot-config": "Extend `.github/dependabot.yml` with an `updates:` entry for each " +
		"detected-but-uncovered ecosystem (see this finding's `uncovered_ecosystems` fact for exactly " +
		"which ones).",
	"C06.sca.dependency-review": "Add a workflow using `actions/dependency-review-action` (or " +
		"equivalent), make sure it triggers on `pull_request` (not just push), and add it as a required " +
		"status check: repo Settings -> Rules -> Rulesets -> the branch's rule -> Require status checks " +
		"to pass -> select the dependency-review workflow's check.",
	"C06.sca.alerts-triaged": "If Dependabot alerts are disabled entirely, enable them first: repo " +
		"Settings -> Code security -> enable \"Dependabot alerts\" (see C04.deps.dependabot-alerts). Once " +
		"enabled, triage: Security -> Dependabot alerts -> filter by Critical severity -> fix or dismiss " +
		"(with a documented reason) any critical alert open longer than 30 days.",
}

// sharedUpstreamFetchFailureRubric is shared by all five checks: unlike
// C05, only the repo fetch and the workflow listing early-return
// allNotCheckable for every check in collectRepo — a release-listing,
// root-listing, Dependabot-config, alerts, or required-status-check
// failure is handled locally by the one or two checks that actually
// consume that data (see each check's own not-checkable entry below),
// NOT propagated to every check the way C05's release-listing failure
// is. Collect's own embedded-registry-load failure is a distinct,
// binary-level cause that also reaches every check for every repo in
// scope, independent of the target repo's own state.
const sharedUpstreamFetchFailureRubric = "the repo fetch or the workflow listing failed (403/plan-gated/" +
	"other API error) — collectRepo returns not-checkable for every check on either failure, since none of " +
	"them can be computed without this shared evidence; or the embedded scanner-signature registry itself " +
	"failed to load (a binary-level failure, independent of the scanned repo — since issue #255, this " +
	"fallback is no longer reachable via `attestward scan`: the orchestrator's own load of the same " +
	"embedded file now aborts the whole scan first if it fails; kept as defense in depth for any caller " +
	"that doesn't go through scan.go's own pre-load)"

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce — see checks.go for the pass/fail/partial logic
// each rubric below summarizes.
var checkRubrics = map[string]map[model.Status]string{
	"C06.sca.tool-configured": {
		model.StatusVerifiedPass: "at least one matched workflow reaches medium-or-high confidence (an " +
			"action slug or CLI pattern, not just a suggestive workflow name), or a Dependabot config " +
			"exists with at least one `updates:` entry that sets a non-empty `package-ecosystem`",
		model.StatusPartial: "only a low-confidence (workflow-name-only) match was found in any workflow, " +
			"and Dependabot is not confirmed configured (no config at either accepted path, a config with " +
			"no usable `updates:` entries, or the config fetch itself failed) — not enough signal alone to " +
			"confirm an SCA tool is genuinely configured",
		model.StatusVerifiedFail: "no workflow match of any confidence was found, the Dependabot " +
			"config fetch succeeded but found either no config at either accepted path " +
			"(`.github/dependabot.yml` or `.yaml`) or a config with no `updates:` entry setting a " +
			"non-empty `package-ecosystem`, and every workflow this collector inspected for this repo " +
			"resolved cleanly (no same-repo skip) — a real absence, not an evidence gap",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or there is no workflow-based " +
			"evidence at all and the Dependabot config fetch itself failed (permission denied, malformed " +
			"YAML, or another API error) — an unresolved unknown, not a confirmed absence; or one or more " +
			"of this repo's own workflows could not be fully inspected (a content fetch, decode, or parse " +
			"failure — see Facts.skipped_workflows) and no Dependabot config was found, and the evidence " +
			"gathered would otherwise have produced verified-fail — this check applies the honest " +
			"not-checkable fix rather than asserting a confident absence over incomplete evidence",
	},
	"C06.sca.ran-per-release": {
		model.StatusVerifiedPass: "an SCA tool ran successfully (at least one matched run whose conclusion " +
			"is \"success\") for every release in the lookback window, and every matching release tag " +
			"published in the lookback window resolved to a commit; reachable even when a matched " +
			"workflow's own run-history fetch failed (issue #291), as long as every release's coverage " +
			"already reads \"ran\" from the workflow(s) that DID resolve — e.g. dependency-review-action is " +
			"itself SCA-category, so its own `/runs` failing doesn't taint a repo whose release coverage is " +
			"otherwise fully evidenced by another matched SCA workflow — coverage status only ever improves " +
			"as more runs are added, never regresses, so an already-\"ran\" release can't be undone by data " +
			"this collector couldn't fetch",
		model.StatusPartial: "release tags published in the lookback window matched but couldn't be " +
			"resolved to a commit, so no release could be evaluated; or a matched SCA tool ran for every " +
			"evaluated release, but not every run succeeded; or every evaluated release succeeded, but one " +
			"or more matching release tags couldn't be resolved to a commit and were excluded from " +
			"evaluation — either of the latter two reachable despite a matched workflow's run-history fetch " +
			"failing (issue #291), by the same monotonicity reasoning as verified-pass above, as long as no " +
			"release's coverage reads \"missing\"",
		model.StatusVerifiedFail: "at least one release in the lookback window has zero matched SCA runs " +
			"at all (not even a failed one), and — when there are zero matched workflows and no Dependabot " +
			"config — every workflow this collector inspected for this repo resolved cleanly (no same-repo " +
			"skip)",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or no workflow-based SCA tool was " +
			"detected and the Dependabot config fetch itself failed — unknown whether Dependabot is this " +
			"repo's sole SCA tool or absent entirely; or Dependabot is this repo's sole detected SCA tool, " +
			"which has no per-release run history to evaluate here (see C06.sca.alerts-triaged instead); " +
			"or there are zero matched workflows, no Dependabot config, and one or more of this repo's own " +
			"workflows could not be fully inspected (see Facts.skipped_workflows) — the same evidence gap " +
			"C06.sca.tool-configured itself goes not-checkable for, so this check does too rather than " +
			"asserting a confident absence over it; or the release listing itself failed (403/plan-gated/" +
			"other API error); or no release tag matches the configured pattern within the lookback window, " +
			"and none of the tags that did match were dropped as unresolvable either — genuinely nothing to " +
			"evaluate; or the workflow run-history fetch itself failed for one or more matched workflows AND " +
			"the resulting coverage table (built from whatever run history DID resolve) shows at least one " +
			"release with no matched run at all (issue #287, narrowed by #291) — an incomplete run-history " +
			"pool can't be trusted to certify that specific per-release absence; a partial pool whose table " +
			"already reads \"ran\"/\"failed\" for every release is NOT tainted by this (see verified-pass/" +
			"partial above)",
	},
	"C06.sca.dependabot-config": {
		model.StatusVerifiedPass: "a Dependabot config exists and covers every ecosystem detected from the " +
			"repo's root-level manifests and/or its GitHub Actions workflows",
		model.StatusPartial: "a Dependabot config exists, but one or more detected ecosystems are not " +
			"covered by it",
		model.StatusVerifiedFail: "no Dependabot config exists at either accepted path, and one or more " +
			"dependency ecosystems were detected",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or the repo's root directory " +
			"listing failed (403/plan-gated/other API error), so which ecosystems are in use couldn't be " +
			"detected; or the Dependabot config fetch itself failed (permission denied, malformed YAML, or " +
			"another API error); or no Dependabot config exists and no dependency manifests were detected " +
			"either — nothing for Dependabot to cover",
	},
	"C06.sca.dependency-review": {
		model.StatusVerifiedPass: "a matched dependency-review-action (or equivalent SCA-category) " +
			"workflow triggers on `pull_request`/`pull_request_target`, and its workflow name exactly " +
			"(case-insensitively) matches one of the branch's required status check names",
		model.StatusPartial: "a matched dependency-review workflow doesn't trigger on `pull_request`/" +
			"`pull_request_target` events; or the required-status-check state couldn't be determined; or " +
			"the workflow triggers on pull requests but no required status check name exactly matches its " +
			"own name (a substring-only \"loose\" match, or no match at all, is never asserted as confirmed " +
			"— GitHub's real check-run naming can't be derived precisely from the workflow name alone)",
		model.StatusVerifiedFail: "no workflow matching the dependency-review-action signature (or " +
			"equivalent) was detected in any workflow",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or a dependency-review workflow " +
			"was detected, but re-fetching it to inspect its triggers failed; or no matched " +
			"dependency-review-action (or equivalent) workflow was found, but one or more of this " +
			"repo's own workflows could not be fully inspected (see Facts.skipped_workflows) — the " +
			"same evidence gap C06.sca.tool-configured itself goes not-checkable for, so this check " +
			"does too rather than asserting a confident absence over it",
	},
	"C06.sca.alerts-triaged": {
		model.StatusVerifiedPass: fmt.Sprintf("the open-alerts fetch succeeded, EVERY open alert's severity "+
			"was interpreted, and no critical alert has been open longer than the %.0f-day triage window",
			criticalTriageThresholdDays),
		model.StatusPartial: fmt.Sprintf("either one or more critical alerts are open with the oldest beyond "+
			"the %.0f-day triage window, or one or more open alerts carried a severity this build could not "+
			"interpret (a missing security advisory, or a value outside GitHub's enum) so a stale critical "+
			"alert cannot be ruled out. Facts carry open_unclassified_count for the second case.",
			criticalTriageThresholdDays),
		model.StatusVerifiedFail: "Dependabot alerts are not enabled for this repository (the alerts " +
			"endpoint returned 403 with a message confirming the feature itself is disabled, not a generic " +
			"permission or not-found error)",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or the open-alerts fetch failed " +
			"with something other than a confirmed \"alerts disabled\" 403 (a genuine permission denial, a " +
			"404, or another API error) — this collector can't distinguish those causes from GitHub's " +
			"response alone",
	},
}

// sharedEvidenceEndpoints are the calls that determine matchedWorkflows,
// defaultBranch, and hasWorkflows — shared by every check that consumes
// any of that evidence.
var sharedEvidenceEndpoints = []string{
	"GET /repos/{owner}/{repo}",
	"GET /repos/{owner}/{repo}/actions/workflows",
	"GET /repos/{owner}/{repo}/contents/{path}",
}

const releasesAPIEndpoint = "GET /repos/{owner}/{repo}/releases"
const gitRefAPIEndpoint = "GET /repos/{owner}/{repo}/git/ref/{ref}"
const gitTagAPIEndpoint = "GET /repos/{owner}/{repo}/git/tags/{tag_sha}"
const workflowRunsAPIEndpoint = "GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs"
const branchProtectionAPIEndpoint = "GET /repos/{owner}/{repo}/branches/{branch}/protection"
const rulesForBranchAPIEndpoint = "GET /repos/{owner}/{repo}/rules/branches/{branch}"
const dependabotAlertsAPIEndpoint = "GET /repos/{owner}/{repo}/dependabot/alerts"

// checkEndpoints lists which REST endpoint(s) actually back each check's
// status.
var checkEndpoints = map[string][]string{
	"C06.sca.tool-configured":   append([]string{}, sharedEvidenceEndpoints...),
	"C06.sca.dependabot-config": append([]string{}, sharedEvidenceEndpoints...),
	"C06.sca.ran-per-release": append(append([]string{}, sharedEvidenceEndpoints...),
		releasesAPIEndpoint, gitRefAPIEndpoint, gitTagAPIEndpoint, workflowRunsAPIEndpoint),
	"C06.sca.dependency-review": append(append([]string{}, sharedEvidenceEndpoints...),
		branchProtectionAPIEndpoint, rulesForBranchAPIEndpoint),
	"C06.sca.alerts-triaged": {dependabotAlertsAPIEndpoint},
}

const fixtureRef = "internal/collect/github/scahistory/scahistory_test.go"

// checkGHESNotes is issue #13's per-check GHES divergence audit. The other
// four checks only ever call sharedEvidenceEndpoints plus other basic
// repo/branch/release reads, none of them GHAS/Enterprise-license-gated.
// alerts-triaged is the one exception, and deliberately GHESNoteUnverified
// rather than guessed at: checkAlertsTriaged's own 403-message-substring
// gating (see alertsDisabledMessageSubstring's doc comment) was
// empirically confirmed against github.com specifically, and Dependabot
// alerts on GHES additionally depend on GitHub Connect syncing github.com's
// advisory database (or an airgapped alternative) — neither of which this
// tool's authors have independently confirmed produces the same
// status-code/message shape this collector reads.
var checkGHESNotes = map[string]string{
	"C06.sca.tool-configured":   ghcollect.GHESNoteSupported,
	"C06.sca.dependabot-config": ghcollect.GHESNoteSupported,
	"C06.sca.ran-per-release":   ghcollect.GHESNoteSupported,
	"C06.sca.dependency-review": ghcollect.GHESNoteSupported,
	"C06.sca.alerts-triaged":    ghcollect.GHESNoteUnverified,
}

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:          id,
			Platform:    "github",
			Title:       checkTitles[id],
			Collector:   collectorID,
			TokenScope:  "repo (classic) or Actions: read-only + Contents: read-only (fine-grained), plus Administration: read-only (shared with C02, for the dependency-review required-status-check cross-check) and whatever fine-grained category gates Dependabot alerts specifically — not independently verified against GitHub's docs, same kind of hedge as C05's TokenScope",
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			GHESNote:    checkGHESNotes[id],
			FixtureRef:  fixtureRef,
		})
	}
}

// Collector implements C06 sca-history.
type Collector struct {
	token string

	// hostConfig carries the resolved GHES base URL/CA (or the zero value,
	// for github.com) into every per-repo Client this collector builds —
	// see ghcollect.ResolveHostConfig (issue #11).
	hostConfig ghcollect.ClientConfig

	// newClientForTest overrides how each repo's Client is constructed —
	// see sasthistory.Collector's identical field for why.
	newClientForTest func(token string) *ghcollect.Client
}

// New returns a C06 collector authenticated with token, targeting cfg's
// host — github.com for the zero value, or a GitHub Enterprise Server
// install (issue #11). Per-repo checks fan out via ForEachRepo's concurrent
// worker pool, so each repo constructs its own Client — see
// sasthistory.New's doc comment for why a shared client across concurrent
// repos would corrupt provenance attribution.
func New(token string, cfg ghcollect.ClientConfig) *Collector {
	return &Collector{token: token, hostConfig: cfg}
}

func (c *Collector) newClient() *ghcollect.Client {
	if c.newClientForTest != nil {
		return c.newClientForTest(c.token)
	}
	return ghcollect.NewClient(c.token, c.hostConfig)
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. It never returns a non-nil
// top-level error for a per-repo API failure — see org-security's Collect
// doc comment for why that matters for the rollup.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	registry, err := mapping.LoadScannerSignaturesFS(mappings.FS, "scanner-signatures.yaml")
	if err != nil {
		var all []model.CheckResult
		for _, repo := range scope.Repos {
			all = append(all, allNotCheckable(scope.Org, repo, fmt.Sprintf("could not load the embedded scanner-signature registry: %v", err), nil)...)
		}
		return all, nil
	}

	repoResults := ghcollect.ForEachRepo(ctx, scope.Repos, ghcollect.DefaultConcurrency, func(ctx context.Context, repo string) ([]model.CheckResult, error) {
		client := c.newClient()
		return collectRepo(ctx, client, registry, scope.Org, repo, scope), nil
	})

	var all []model.CheckResult
	for _, r := range repoResults {
		if r.Err != nil {
			all = append(all, allNotCheckable(scope.Org, r.Repo, fmt.Sprintf("scan canceled before this repo's checks ran: %v", r.Err), nil)...)
			continue
		}
		all = append(all, r.Value...)
	}
	if all == nil {
		all = []model.CheckResult{}
	}
	return all, nil
}

// collectRepo resolves SCA tool-configuration, run-history, ecosystem
// coverage, dependency-review enforcement, and alert-triage evidence for
// one repo and emits all five CheckResults. It never returns an error;
// every failure becomes a not-checkable result for the affected check(s).
//
// Provenance is attributed per API-call phase via a running-offset
// snapshot closure, then recombined per check — e.g. tool-configured
// draws on both the workflow-match phase and the dependabot-config-fetch
// phase (a Dependabot match is one of its two possible signals), while
// ran-per-release only draws on the workflow-match and release/run-history
// phases (Dependabot has no per-release run history — see
// checkRanPerRelease's doc comment).
func collectRepo(ctx context.Context, client *ghcollect.Client, registry *mapping.ScannerSignatureRegistry, org, repo string, scope collect.Scope) []model.CheckResult {
	// prevLen starts at 0, not len(client.Provenance()) after the Get call
	// below: client is freshly constructed per repo (see New's doc
	// comment), so Provenance() is empty at this point anyway — starting
	// here means the very first snapshot() call includes this initial
	// Get's own provenance entry, the same way sasthistory's sharedProv
	// includes its own leading repo-fetch call.
	prevLen := 0
	snapshot := func() []model.Provenance {
		all := client.Provenance()
		seg := append([]model.Provenance{}, all[prevLen:]...)
		prevLen = len(all)
		return seg
	}

	repository, resp, err := client.REST.Repositories.Get(ctx, org, repo)
	if err != nil {
		return allNotCheckable(org, repo, notCheckableReason(resp, err, org, repo, scope), client.Provenance())
	}
	defaultBranch := repository.GetDefaultBranch()

	allWorkflows, wfResp, err := runhistory.ListWorkflows(ctx, client, org, repo)
	if err != nil {
		return allNotCheckable(org, repo, notCheckableReason(wfResp, err, org, repo, scope), client.Provenance())
	}
	workflowMatches, skippedWorkflows := runhistory.MatchWorkflows(ctx, client, registry, org, repo, defaultBranch, allWorkflows, mapping.CategorySCA)
	workflowMatchProv := snapshot()

	now := time.Now().UTC()
	windowStart := now.AddDate(0, -scope.LookbackMonths, 0)
	tagPattern := scope.ReleaseTagPattern

	var filteredReleases []runhistory.ReleaseInfo
	var coverage []runhistory.ReleaseCoverage
	droppedTags := 0
	// runsErr (issue #287): mirrors sasthistory's identical loop — see that
	// package's collectRepo doc comment on the equivalent loop for the
	// full reasoning on why a partial per-workflow fetch failure is
	// tracked as a single error rather than attributed to just the failing
	// workflow. checkRanPerRelease below only taints its own result from
	// this when the merged runs pool it DID get already shows a release
	// with no matched run at all (issue #291, narrowing #287's original
	// unconditional taint) — coverage status is monotone in the runs pool
	// (more runs can only turn CoverageMissing into CoverageFailed/
	// CoverageRan, never the reverse), so a pool that already fully covers
	// every release can't be invalidated by whatever the failed workflow's
	// runs would have added. See checkRanPerRelease's own doc comment for
	// the full reasoning; C06 has no cadence check, so there's no
	// sasthistory-style asymmetry to track here — this package's runsErr
	// feeds exactly one check.
	var runsErr error
	rawReleases, relResp, relErr := runhistory.FetchReleases(ctx, client, org, repo)
	if relErr == nil {
		var releases []runhistory.ReleaseInfo
		for _, r := range rawReleases {
			tagName := r.GetTagName()
			if ok, mErr := filepath.Match(tagPattern, tagName); mErr != nil || !ok {
				continue // out of scope regardless of resolution outcome — not a drop
			}
			publishedAt := r.GetPublishedAt().Time
			sha, rErr := runhistory.ResolveReleaseCommit(ctx, client, org, repo, tagName)
			if rErr != nil {
				if !publishedAt.Before(windowStart) {
					droppedTags++
				}
				continue
			}
			releases = append(releases, runhistory.ReleaseInfo{TagName: tagName, CommitSHA: sha, PublishedAt: publishedAt})
		}
		filteredReleases = runhistory.FilterReleasesInLookback(releases, tagPattern, scope.LookbackReleases, scope.LookbackMonths, now)

		var runs []runhistory.RunInfo
		for _, mw := range workflowMatches {
			wfRuns, rErr := runhistory.FetchWorkflowRuns(ctx, client, org, repo, mw.WorkflowID, windowStart)
			if rErr != nil {
				if runsErr == nil {
					runsErr = fmt.Errorf("workflow %d (%s): %w", mw.WorkflowID, mw.Path, rErr)
				}
				continue
			}
			for _, r := range wfRuns {
				runs = append(runs, runhistory.RunInfo{
					HeadSHA:    r.GetHeadSHA(),
					HeadBranch: r.GetHeadBranch(),
					Conclusion: r.GetConclusion(),
					CreatedAt:  r.GetCreatedAt().Time,
				})
			}
		}
		coverage = runhistory.LinkRunsToReleases(filteredReleases, runs, defaultBranch)
	}
	releaseRunProv := snapshot()

	rootFilenames, rootResp, rootErr := fetchRootFilenames(ctx, client, org, repo, defaultBranch)
	hasWorkflows := len(allWorkflows) > 0
	var detectedEcosystems []string
	if rootErr == nil {
		detectedEcosystems = detectEcosystems(rootFilenames, hasWorkflows)
	}
	ecosystemProv := snapshot()

	cfg, configExists, dependabotResp, dependabotErr := fetchDependabotConfig(ctx, client, org, repo, defaultBranch)
	dependabotProv := snapshot()
	dependabotConfigured := configExists && cfg != nil && len(cfg.ecosystems()) > 0

	alerts, alertsResp, alertsErr := fetchOpenAlerts(ctx, client, org, repo)
	alertsProv := snapshot()

	statusCheckNames, _, _, statusErr := repoprotection.RequiredStatusCheckNames(ctx, client, org, repo, defaultBranch)
	statusCheckProv := snapshot()

	depReviewPath, depReviewFound := findMatchedSignature(workflowMatches, dependencyReviewSignatureID)
	var depReviewWorkflow *mapping.WorkflowFile
	var depReviewFetchErr error
	if depReviewFound {
		depReviewWorkflow, depReviewFetchErr = refetchWorkflow(ctx, client, org, repo, defaultBranch, depReviewPath)
	}
	depReviewProv := snapshot()

	toolConfiguredProv := concatProv(workflowMatchProv, dependabotProv)
	ranPerReleaseProv := concatProv(workflowMatchProv, releaseRunProv)
	dependabotConfigProv := concatProv(ecosystemProv, dependabotProv)
	dependencyReviewProv := concatProv(workflowMatchProv, statusCheckProv, depReviewProv)

	// runhistory.MatchWorkflows only ever appends an entry when it has at
	// least one match, so len(workflowMatches) == 0 is exactly "no
	// workflow-based SCA tool detected at all."
	dependabotOnly := dependabotConfigured && len(workflowMatches) == 0
	// dependabotUnknown is dependabotOnly's "we don't actually know"
	// counterpart: same zero-workflow-evidence precondition, but the
	// Dependabot config fetch itself failed rather than confirming
	// absence — see checkRanPerRelease's own doc comment.
	dependabotUnknown := dependabotErr != nil && len(workflowMatches) == 0
	hasMatchedWorkflows := len(workflowMatches) > 0

	summary := summarizeAlerts(alerts, now)

	return []model.CheckResult{
		checkToolConfigured(org, repo, workflowMatches, skippedWorkflows, dependabotConfigured, dependabotResp, dependabotErr, scope, toolConfiguredProv),
		checkRanPerRelease(org, repo, filteredReleases, coverage, droppedTags, dependabotOnly, dependabotUnknown, hasMatchedWorkflows, skippedWorkflows, relResp, relErr, runsErr, scope, ranPerReleaseProv),
		checkDependabotConfig(org, repo, cfg, configExists, detectedEcosystems, rootResp, rootErr, dependabotResp, dependabotErr, scope, dependabotConfigProv),
		checkDependencyReview(org, repo, depReviewFound, skippedWorkflows, depReviewWorkflow, depReviewFetchErr, statusCheckNames, statusErr, dependencyReviewProv),
		checkAlertsTriaged(org, repo, alertsResp, alertsErr, summary, scope, alertsProv),
	}
}

// findMatchedSignature returns the Path of the first matched workflow
// carrying a match with the given signature ID, if any.
func findMatchedSignature(matched []runhistory.MatchedWorkflow, signatureID string) (path string, found bool) {
	for _, mw := range matched {
		for _, m := range mw.Matches {
			if m.SignatureID == signatureID {
				return mw.Path, true
			}
		}
	}
	return "", false
}

// refetchWorkflow re-fetches and re-parses one already-matched workflow's
// content, purely to read its `on:` trigger list — MatchedWorkflow doesn't
// carry the parsed mapping.WorkflowFile (runhistory.MatchWorkflows only
// returns which signatures matched, not the whole parsed file), and
// extending the shared package's return type for one collector's narrow
// need isn't worth it for a single extra GetContents call.
func refetchWorkflow(ctx context.Context, client *ghcollect.Client, org, repo, defaultBranch, path string) (*mapping.WorkflowFile, error) {
	content, _, _, err := client.REST.Repositories.GetContents(ctx, org, repo, path, &ghgithub.RepositoryContentGetOptions{Ref: defaultBranch})
	if err != nil {
		return nil, err
	}
	if content == nil {
		return nil, fmt.Errorf("no content returned for %s", path)
	}
	raw, err := content.GetContent()
	if err != nil {
		return nil, err
	}
	parsed, err := mapping.ParseWorkflowFile([]byte(raw))
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func concatProv(segments ...[]model.Provenance) []model.Provenance {
	var out []model.Provenance
	for _, s := range segments {
		out = append(out, s...)
	}
	if out == nil {
		out = []model.Provenance{}
	}
	return out
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
