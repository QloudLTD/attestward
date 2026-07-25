// Package sasthistory implements C05 sast-history for Azure DevOps — the
// ADO counterpart to internal/collect/github/sasthistory — under the same
// four check IDs (issue #34's check-identity model). It is built on
// internal/collect/azuredevops/pipelinehistory (issue #152's shared
// release-resolution/pipeline-discovery/run-lookback/cadence machinery,
// its first real consumer) exactly the way the GitHub twin is built on
// internal/collect/github/runhistory.
//
// Architecture mirrors C02 repo-protection, not the GitHub twin's
// per-repo-Client fan-out: pipeline discovery (ListPipelines +
// MatchPipelines) and repository listing are project-scoped calls that
// happen exactly ONCE per Collect, shared across every repo in scope, then
// filtered client-side per repo via MatchedPipeline.RepositoryID (added to
// pipelinehistory alongside this collector, since pipeline discovery
// itself has no per-repo filter at all — every consumer of
// pipelinehistory needs this same resolution). Only release resolution,
// build-history fetching, and the GHAzDO repo-enablement query are
// genuinely per-repo, matching pipelinehistory's own API scoping.
// Processing repos sequentially (not fanned out concurrently the way the
// GitHub twin's ForEachRepo does) is fine here for the same reason it was
// for C10 vdp: nothing needs concurrent-goroutine provenance isolation,
// since the one shared Client's calls all happen on a single goroutine in
// a known order.
//
// Two deliberate platform-specific judgment calls, both explained where
// they're applied and restated in this PR's own description:
//
//   - ResolveReleases' dropped []string return is UNCONDITIONAL (every
//     tagPattern-matching tag whose date resolution failed, regardless of
//     whether it would fall inside the lookback window) — see that
//     function's own doc comment for exactly why Azure DevOps structurally
//     cannot provide the window-gating the GitHub twin's droppedTags
//     applies before counting a drop (it needs a release's date to judge
//     window membership, and a resolution failure is precisely the
//     absence of that date). This collector applies the GitHub twin's
//     "any dropped tag caps ran-per-release at partial" rule to that
//     unconditional list as-is: the honest choice is to never silently
//     assume an unresolvable tag was irrelevant, even though this reads
//     stricter/noisier on Azure DevOps than the equivalent GitHub scenario
//     for the same underlying repository history — a real platform
//     information asymmetry (GitHub's Releases API hands over a
//     PublishedAt before any resolution is attempted; Azure DevOps's tag
//     API does not), not evidence ADO pipelines are actually less
//     reliable. Facts records the dropped tag NAMES (not just a count,
//     unlike the GitHub twin) precisely because that asymmetry exists —
//     a report reader can judge each one for themselves rather than trust
//     an opaque number.
//   - checkCadence's own not-checkable-vs-normal gate is keyed on
//     matched-pipeline evidence (hasAny) alone, deliberately excluding
//     GHAzDO CodeQL default setup (codeQLEnabled) even though
//     checkToolConfigured's OR condition includes it: GitHub's own CodeQL
//     default setup produces a real, queryable virtual-workflow run
//     history (ListWorkflows exposes it at a synthetic path, with genuine
//     run objects the normal per-workflow-runs endpoint returns), so
//     GitHub's cadence can legitimately read real numbers off it. GHAzDO's
//     default setup scans DO run somewhere real — Microsoft's own current
//     docs describe them running on configurable agent pools with visible
//     job logs, not some invisible server-side-only process (an earlier
//     draft of this comment overstated the platform fact as "no
//     discoverable build/run equivalent at all," which review caught as
//     wrong) — but this collector has no VERIFIED way to observe that run
//     history via the Pipelines/Builds APIs it actually uses: default
//     setup isn't a normal build-definition-backed pipeline this tool's
//     own pipeline discovery (ListPipelines/MatchPipelines) would ever
//     enumerate, so there is no definitionID this collector could hand to
//     FetchBuilds for it [fixture-verify — issue #34/#155's S9
//     recorded-response pass should confirm empirically whether
//     default-setup runs surface anywhere in GET .../_apis/build/builds
//     at all]. Reporting verified-fail ("configured, but zero runs
//     observed") on the strength of a gap in this collector's own
//     endpoints, not a confirmed platform absence, would assert a fact it
//     doesn't actually have evidence for; this collector reports
//     not-checkable instead, with a reason distinguishing "no tool
//     configured at all" from "a tool is configured, but this collector
//     has no verified way to observe its run history."
//     checkCadence's own low-confidence-only cap (see checks.go) reflects
//     the same asymmetry: the GitHub twin's identical-shaped formula lets
//     a genuinely-configured default setup "rescue" a low-confidence
//     pipeline match out of the partial cap, since GitHub's default setup
//     really does contribute additional observable run history there —
//     co-existing evidence, not a stand-in for it. This collector's own
//     formula does NOT grant codeQLEnabled that same rescue: since GHAzDO
//     default setup contributes zero observable builds here, letting it
//     upgrade a result whose entire observed RunCount came from a
//     low-confidence-only pipeline match would be asserting confidence in
//     evidence this collector never actually gathered. See checkCadence's
//     own doc comment for the code-level statement of this divergence.
package sasthistory

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
const collectorID = "C05.sast-history"

const (
	idToolConfigured = "C05.sast.tool-configured"
	idRanPerRelease  = "C05.sast.ran-per-release"
	idCadence        = "C05.sast.cadence"
	idDefaultSetup   = "C05.sast.default-setup"
)

var checkIDs = []string{idToolConfigured, idRanPerRelease, idCadence, idDefaultSetup}

// checkTitles is allowed to differ from the GitHub twin's wording (epic
// #34 open decision 4) — idDefaultSetup's Title is issue #152's own
// explicit ADO phrasing ("GHAzDO CodeQL default setup"), naming the
// GHAzDO product surface directly rather than reusing GitHub's generic
// "CodeQL default setup" wording.
var checkTitles = map[string]string{
	idToolConfigured: "A SAST tool is configured",
	idRanPerRelease:  "A SAST tool ran for each release in the lookback window",
	idCadence:        "SAST run cadence over the lookback window",
	idDefaultSetup:   "GHAzDO CodeQL default setup",
}

var checkRemediations = map[string]string{
	idToolConfigured: "Enable GHAzDO CodeQL default setup (repo -> Advanced Security -> Code scanning -> " +
		"CodeQL -> Enable default setup), or add a pipeline task using a recognized SAST task/CLI (see " +
		"mappings/scanner-signatures.yaml for what this tool recognizes) — a pipeline whose name merely " +
		"suggests SAST isn't enough on its own; it needs a matched task/CLI invocation to count as more " +
		"than a low-confidence signal.",
	idRanPerRelease: "Make sure the SAST pipeline's trigger actually fires on (or before) the commit each " +
		"release tag points at — e.g. trigger on push to the release branch — and that any build that did " +
		"fire completed with result==\"succeeded\" rather than failing or being canceled.",
	idCadence: "If zero SAST builds were observed in the lookback window, same fix as " +
		"C05.sast.ran-per-release: confirm the pipeline runs on a schedule or on every push/PR to the " +
		"default branch, not only on rare manual triggers. If builds WERE observed but this still reads " +
		"partial, the match itself is low-confidence (pipeline/step-name-only) — same fix as " +
		"C05.sast.tool-configured: use a recognized task/CLI, not just a pipeline name that sounds like " +
		"SAST.",
	idDefaultSetup: "Repo -> Advanced Security -> Code scanning -> CodeQL -> Enable default setup.",
}

// sharedUpstreamFetchFailureRubric is shared by all four checks: collectRepo
// returns not-checkable for every one of them on the first failure among
// the project's repositories/pipelines listing or this repo's own release
// resolution, since none of the four checks below can be computed without
// that shared evidence — the same reasoning as the GitHub twin's identical
// sharedUpstreamFetchFailureRubric (see collectRepo's own doc comment for
// exactly which calls this covers).
const sharedUpstreamFetchFailureRubric = "the project's repositories or pipelines couldn't be read " +
	"(403/other API error), the named repository wasn't found in the project, or resolving this repo's " +
	"release tags failed (403/other API error) — collectRepo returns not-checkable for every check on the " +
	"first such failure; or the embedded scanner-signature registry itself failed to load (a binary-level " +
	"failure, independent of the scanned repo)"

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce — see checks.go for the pass/fail/partial logic
// each rubric below summarizes.
var checkRubrics = map[string]map[model.Status]string{
	idToolConfigured: {
		model.StatusVerifiedPass: "at least one matched pipeline reaches medium-or-high confidence (an " +
			"ado_task or run-pattern match, not just a suggestive pipeline/step name), or GHAzDO's CodeQL " +
			"default setup (codeSecurityFeatures.codeQLEnabled) reads true",
		model.StatusPartial: "only a low-confidence (pipeline/step-name-only) match was found in any " +
			"pipeline, and CodeQL default setup is not confirmed enabled — not enough signal alone to " +
			"confirm a SAST tool is genuinely configured",
		model.StatusVerifiedFail: "no pipeline match of any confidence was found, the GHAzDO " +
			"repo-enablement query confirms codeQLEnabled reads false — including a 404 response (GHAzDO " +
			"isn't licensed for this org/project, a real \"not available\" fact [fixture-verify]) but " +
			"deliberately NOT a 403 (ambiguous between a missing vso.advsec scope and an unlicensed " +
			"org/project — that response alone routes to not-checkable instead, see the next clause; found " +
			"in review: an earlier version of this check treated any gated response, 403 included, as a " +
			"confirmed fail, which could false-negative a licensed org whose token merely lacked the scope) " +
			"— and every pipeline MatchPipelines inspected for this repo resolved cleanly (no same-repo " +
			"skip) — a real absence, not an evidence gap",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or there is no pipeline-based " +
			"evidence at all and the GHAzDO repo-enablement query itself failed with anything other than a " +
			"404 — including a 403, ambiguous between a missing vso.advsec scope and an unlicensed " +
			"org/project [fixture-verify] — an unresolved unknown, not a confirmed absence; or one or more " +
			"of this repo's own pipelines could not be fully inspected (a build-definition fetch failure, " +
			"an unresolved YAML path, a YAML fetch/parse failure, or an unresolved template reference — see " +
			"Facts.skipped_pipelines) and the evidence gathered would otherwise have produced verified-fail " +
			"— this check applies the honest not-checkable fix now rather than asserting a confident " +
			"absence over incomplete evidence",
	},
	idRanPerRelease: {
		model.StatusVerifiedPass: "a SAST pipeline ran successfully (at least one matched build whose " +
			"result is \"succeeded\", case-insensitive) for every release in the lookback window, and every " +
			"matching release tag was successfully dated",
		model.StatusPartial: "one or more release tags matching the configured pattern could not be dated " +
			"(their commit is always already known straight from the refs listing itself — it's only the " +
			"date lookup that failed; this collector's own deliberate choice applies that unconditionally, " +
			"not only to tags provably inside the lookback window — see the package doc comment); if that " +
			"leaves nothing evaluable, the reason names the drop count directly, otherwise every evaluated " +
			"release still succeeded but the exclusion caps the result at partial; or a matched SAST " +
			"pipeline ran for every evaluated release, but not every build succeeded",
		model.StatusVerifiedFail: "at least one release in the lookback window has zero matched SAST " +
			"builds at all (not even a failed one), and — when there are zero matched pipelines overall — " +
			"every pipeline MatchPipelines inspected for this repo resolved cleanly (no same-repo skip)",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or GHAzDO CodeQL default setup is " +
			"this repo's ONLY SAST evidence (no signature-matched pipeline at all) — default-setup scans " +
			"run invisibly to this collector's own build-matching, so this check has no verified way to " +
			"observe them per release (issue #184, mirroring C06's identical injectionOnly guard); or " +
			"there are zero matched pipelines and one or more of this repo's own pipelines could not be " +
			"fully inspected (see Facts.skipped_pipelines) — the same evidence gap " +
			"C05.sast.tool-configured itself goes not-checkable for, so this check does too rather than " +
			"asserting a confident absence over it — when default setup is ALSO the sole evidence, that " +
			"cause wins and is what this Reason names (the skip is still recorded in Facts, just not the " +
			"stated cause), since the skip wording would otherwise contradict tool-configured's " +
			"verified-pass for the identical evidence; or no release tag matches the configured pattern " +
			"within the lookback window, and none of the tags that did match were dropped as unresolvable " +
			"either — genuinely nothing to evaluate; or the project's build history itself could not be " +
			"fetched",
	},
	idCadence: {
		model.StatusVerifiedPass: "one or more SAST builds were observed in the lookback window, backed by " +
			"at least a medium-confidence pipeline match or GHAzDO CodeQL default setup (not a " +
			"low-confidence-only match)",
		model.StatusPartial: "one or more builds were observed, but only a low-confidence " +
			"(pipeline/step-name-only) match identified the tool — not enough signal to confirm this " +
			"cadence reflects genuine SAST activity",
		model.StatusVerifiedFail: "a SAST tool is configured via a matched pipeline, but zero SAST builds " +
			"were observed in the lookback window",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or no SAST tool is configured at " +
			"all (no matched pipeline of any confidence, and GHAzDO CodeQL default setup does not read " +
			"enabled) — nothing to compute cadence for; or a SAST tool is configured ONLY via GHAzDO CodeQL " +
			"default setup, and this collector has no verified way to observe scan history for that " +
			"mechanism via the Pipelines/Builds APIs it uses [fixture-verify, issue #34/#155's S9 pass] — " +
			"see the package doc comment for why this collector doesn't assert a run count it can't verify; " +
			"or the project's build history itself could not be fetched",
	},
	idDefaultSetup: {
		model.StatusVerifiedPass: "the GHAzDO repo-enablement query succeeded and codeSecurityFeatures.codeQLEnabled reads true",
		model.StatusVerifiedFail: "the GHAzDO repo-enablement query succeeded, but codeSecurityFeatures.codeQLEnabled reads false",
		// This check never reads release/pipeline data itself, but still
		// goes not-checkable on the shared upstream failures (found in
		// review: an earlier version of this rubric omitted them,
		// describing only the enablement-query-specific failure below,
		// even though allNotCheckable actually routes this exact check
		// through the shared reason too — collectRepo returns early via
		// allNotCheckable before ever reaching the enablement call, the
		// same "default-setup doesn't need this evidence but still goes
		// not-checkable if it fails" shape the GitHub twin's own
		// sharedUpstreamFetchFailureRubric documents).
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or the GHAzDO repo-enablement query " +
			"itself failed — a 404 (org/project not licensed for GHAzDO [fixture-verify]), a 403 (ambiguous " +
			"between a missing vso.advsec scope and an unlicensed org/project [fixture-verify], see " +
			"azuredevops.IsAdvSecGated's own doc comment), or another API error",
	},
}

// pipelineEvidenceEndpoints backs every check whose evidence includes
// matched-pipeline data (all four, directly or indirectly) — project-scoped
// calls that happen once per Collect, shared across every repo in scope
// (mirrors repoprotection's identical sharedEndpoints reasoning).
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

var checkEndpoints = map[string][]string{
	idToolConfigured: append(append([]string{}, pipelineEvidenceEndpoints...), enablementEndpoint),
	idRanPerRelease: append(append(append([]string{}, pipelineEvidenceEndpoints...), releaseEvidenceEndpoints...),
		buildsEndpoint),
	idCadence:      append(append(append([]string{}, pipelineEvidenceEndpoints...), enablementEndpoint), buildsEndpoint),
	idDefaultSetup: {enablementEndpoint},
}

var checkTokenScopes = map[string]string{
	idToolConfigured: "vso.build, vso.code (pipeline discovery and YAML fetch), vso.advsec (GHAzDO repo enablement)",
	idRanPerRelease:  "vso.build, vso.code",
	idCadence:        "vso.build, vso.code, vso.advsec",
	idDefaultSetup:   "vso.advsec",
}

const fixtureRef = "internal/collect/azuredevops/sasthistory/sasthistory_test.go"

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

// Collector implements C05 sast-history for Azure DevOps.
type Collector struct {
	client *azuredevops.Client
}

// New returns a C05 collector using client for all API calls. Like C02
// repo-protection, one shared Client covers every repo in scope: pipeline
// discovery and repository listing are project-scoped (exactly once,
// regardless of repo count), and per-repo calls run sequentially on this
// same Client — see the package doc comment for why that needs no
// per-repo Client the way the GitHub twin's genuinely concurrent fan-out
// does.
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
		matchedAll, skippedAll = pipelinehistory.MatchPipelines(ctx, c.client, registry, scope.Project, pipelines, mapping.CategorySAST)
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

// collectRepo resolves one repo's release/build history and GHAzDO
// enablement state, then emits all four CheckResults for it.
//
// Call order within a repo matters for provenance, the same way it does in
// the GitHub twin: release resolution and build fetching run FIRST, so
// their combined provenance (plus the project-wide prefix) can be shared
// by tool-configured/ran-per-release/cadence via plain prefix slicing;
// the GHAzDO repo-enablement call runs LAST, so its own provenance can be
// isolated as a suffix for default-setup's own dedicated result — mirroring
// the GitHub twin's identical choice to run its default-setup call last for
// the identical reason (see that package's collectRepo doc comment).
// tool-configured and cadence's own results are attributed the shared
// prefix, not the enablement suffix, even though their logic reads
// enablement data too — the GitHub twin makes the exact same asymmetric
// choice for its own tool-configured/cadence versus defaultSetup, and this
// collector mirrors it rather than second-guessing an already-reviewed
// design.
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

	releases, dropped, relErr := pipelinehistory.ResolveReleases(ctx, c.client, scope.Project, repo.ID, scope.ReleaseTagPattern)
	if relErr != nil {
		prov := append(append([]model.Provenance{}, projectProv...), tailProvenance(c.client.Provenance(), repoStart)...)
		return allNotCheckable(scope.Org, repoName, apiErrorReason(relErr, "release tags"), prov)
	}
	filteredReleases := pipelinehistory.FilterReleasesInLookback(releases, scope.ReleaseTagPattern, scope.LookbackReleases, scope.LookbackMonths, now)

	// definitionIDs must never be passed as an empty-but-non-nil slice
	// when there are zero matched pipelines: FetchBuilds' own contract
	// treats an empty/nil list as "unfiltered — fetch every build in the
	// repo", not "fetch nothing" — passing one here by mistake would
	// silently attribute completely unrelated builds (any pipeline in the
	// repo, matched or not) as SAST evidence. Skipping the call entirely
	// when there is nothing to filter by is the only correct way to get
	// "no matched builds."
	var runs []pipelinehistory.RunInfo
	var buildsErr error
	if len(defIDs) > 0 {
		runs, buildsErr = pipelinehistory.FetchBuilds(ctx, c.client, scope.Project, repo.ID, defIDs, windowStart)
	}

	coverage := pipelinehistory.LinkRunsToReleases(filteredReleases, runs, repo.DefaultBranch)
	cadenceStats := pipelinehistory.ComputeCadence(runs, windowStart, now)

	sharedProv := append(append([]model.Provenance{}, projectProv...), tailProvenance(c.client.Provenance(), repoStart)...)
	enablementStart := len(c.client.Provenance())

	enablement, enablementErr := pipelinehistory.FetchRepoEnablement(ctx, c.client, scope.Project, repo.ID)
	enablementProv := tailProvenance(c.client.Provenance(), enablementStart)

	// defaultSetupOnly feeds checkRanPerRelease's own guard against the
	// self-contradictory pair fixed in issue #184 (twin of #183's C06
	// injectionOnly guard): GHAzDO CodeQL default setup alone is enough
	// for tool-configured's own verified-pass, but it runs invisibly to
	// this collector's own build-matching, so ran-per-release must not
	// independently conclude verified-fail from the resulting zero
	// matched builds — see checkRanPerRelease's own doc comment.
	//
	// hasMatchedPipelines is deliberately derived from the same hasAny
	// matchConfidence already computed, not a second len(matched) > 0
	// check (found in review: the two are equivalent only because
	// pipelinehistory.MatchPipelines appends a MatchedPipeline solely when
	// len(categoryMatches) > 0 — an invariant that lives in another
	// package; two independently-written predicates for the same concept
	// would silently disagree if that invariant ever broke).
	hasAny, _ := matchConfidence(matched)
	defaultSetupOnly := !hasAny && enablementErr == nil && enablement.CodeQLEnabled
	hasMatchedPipelines := hasAny

	return []model.CheckResult{
		checkToolConfigured(scope.Org, repoName, matched, sameRepoSkips, enablement, enablementErr, sharedProv),
		checkRanPerRelease(scope.Org, repoName, filteredReleases, coverage, dropped, buildsErr, defaultSetupOnly, hasMatchedPipelines, sameRepoSkips, sharedProv),
		checkCadence(scope.Org, repoName, matched, enablement, enablementErr, cadenceStats, buildsErr, sharedProv),
		checkDefaultSetup(scope.Org, repoName, enablement, enablementErr, enablementProv),
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
// otherwise — mirrors repoprotection's identical helper for the same two
// dev.azure.com-hosted calls (repositories, pipelines/definitions/items,
// refs/tags).
func apiErrorReason(err error, what string) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) && se.StatusCode == http.StatusForbidden {
		return fmt.Sprintf("token lacks permission to read %s", what)
	}
	return fmt.Sprintf("could not read %s: %v", what, err)
}
