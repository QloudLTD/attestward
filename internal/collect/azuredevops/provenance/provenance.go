// Package provenance implements C07 provenance for Azure DevOps — the ADO
// counterpart to internal/collect/github/provenance — under the same five
// check IDs (issue #34's check-identity model). It is built on
// internal/collect/azuredevops/pipelinehistory exactly the way C05
// sasthistory is: pipeline discovery (ListPipelines + MatchPipelines,
// category mapping.CategoryProvenance) is a project-scoped call that
// happens exactly once per Collect, shared across every repo in scope, and
// filtered client-side per repo via MatchedPipeline.RepositoryID — see
// sasthistory's own package doc comment for the full rationale, which
// applies here unchanged.
//
// Issue #153's own C07 spec splits this collector's five checks into two
// very different shapes:
//
//   - C07.release.tags-signed, C07.release.checksums, and
//     C07.release.signatures are not-checkable ALWAYS, unconditionally, with
//     no API call of their own — the same shape as
//     internal/collect/azuredevops/vdp's C10.vdp.private-reporting/
//     C10.vdp.security-policy-org. tags-signed: verified head-on against
//     the GitAnnotatedTag reference (Git Annotated Tags - Get) —
//     message/taggedBy/taggedObject and nothing else; Azure DevOps exposes
//     no signature or verification field of any kind and does not verify
//     tag signatures the way GitHub does. checksums/signatures: Azure
//     DevOps has no release-asset concept at all the way GitHub Releases
//     does — Azure Artifacts is a package registry, not a release-asset
//     store, and is out of scope for this collector (issue #153's own C07
//     spec, which scopes this collector to Azure Repos-hosted YAML
//     pipelines and their release tags, not Azure Artifacts). All three
//     follow vdp's exact convention: Reason states the platform fact
//     directly rather than echoing the Rubric's "always —" framing
//     verbatim, Provenance is always []model.Provenance{}, and Collect
//     calls them unconditionally, immune to any upstream failure or ctx
//     cancellation, since they never depended on any evidence to begin
//     with.
//   - C07.provenance.workflow and C07.provenance.commit-linkage are real,
//     evidence-based checks, and share collectRepo's early-return gate
//     (project repositories/pipelines listing, then this repo's own
//     release-tag resolution) the same way sasthistory's four checks all
//     do — even commit-linkage, which never reads pipeline-match data,
//     still goes not-checkable if pipeline discovery itself failed,
//     mirroring sasthistory's idDefaultSetup's identical (deliberate)
//     asymmetry. Both consume pipelinehistory.MatchPipelines' skipped-
//     pipeline list from the start (issue #178), the same fix C06
//     sca-history's own tool-configured applies: provenance.workflow
//     filters skippedAll down to this repo's own entries and surfaces them
//     in Facts unconditionally, capping a would-be verified-fail at
//     not-checkable when a same-repo skip exists — see
//     checkProvenanceWorkflow's own doc comment.
//
// One deliberate divergence from sasthistory worth stating explicitly:
// commit-linkage's build fetch passes a nil definitionIDs list to
// pipelinehistory.FetchBuilds, fetching every build in the repo
// unfiltered by pipeline — NOT restricted to the provenance-category
// matched pipelines checkProvenanceWorkflow itself uses. This mirrors the
// GitHub twin's own checkCommitLinkage exactly: "is this release's commit
// traceable to ANY workflow run, any conclusion" — not specifically a
// provenance-tool run (that's provenance.workflow's job, via a completely
// different mechanism: category-matched-pipeline evidence rather than
// direct commit matching). Matching a build to a commit is therefore a
// small local pure function (linkBuildsToCommits, checks.go), not
// pipelinehistory.LinkRunsToReleases: that function's branch+time-window
// fallback exists for continuous tool-coverage questions (C05/C06's own
// ran-per-release, "did a scheduled scan run around this release"), and
// applying it here would let an unrelated build on the default branch
// "cover" a release whose actual commit was never built at all — exactly
// the gap this check exists to catch. linkBuildsToCommits itself does
// exact SourceVersion equality only, with no window/branch fallback and no
// Result filtering (matches the GitHub twin's ListWorkflowRunsOptions{
// HeadSHA: ...} call, which is deliberately blind to run conclusion too) —
// but unlike the GitHub twin's genuinely unbounded HeadSHA lookup, the
// runs slice this function is handed IS still time-bounded, by
// FetchBuilds' own minTime (see commitLinkageBuildGraceWindow in
// checks.go and collectRepo below): "no window" describes the matching
// function alone, not the overall check. This same unfiltered-by-pipeline
// design is exactly why issue #207's same-repo-skip guard (added to
// checkProvenanceWorkflow above, and to the ran-per-release-style checks
// elsewhere in this epic) does NOT extend to commit-linkage: a pipeline
// pipelinehistory.MatchPipelines couldn't fully inspect for CATEGORY
// matching has no bearing here, since commit-linkage never consults
// matched/skipped pipeline evidence at all — a same-repo-skip guard here
// would be structurally pointless, not merely redundant, since this
// check's own logic never reads that evidence in the first place.
//
// dropped-tag semantics (pipelinehistory.ResolveReleases' unconditional
// dropped list) are applied to commit-linkage exactly the way sasthistory's
// checkRanPerRelease applies them to its own ran-per-release check: any
// dropped tag caps the result at partial rather than a clean verified-pass
// — see ResolveReleases' own doc comment and sasthistory's package doc
// comment for why this reads stricter/noisier on Azure DevOps than the
// equivalent GitHub scenario (a real platform information asymmetry, not
// evidence ADO pipelines are less reliable).
package provenance

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
const collectorID = "C07.provenance"

const (
	idTagsSigned    = "C07.release.tags-signed"
	idChecksums     = "C07.release.checksums"
	idSignatures    = "C07.release.signatures"
	idWorkflow      = "C07.provenance.workflow"
	idCommitLinkage = "C07.provenance.commit-linkage"
)

// alwaysNotCheckableIDs are the three checks with no API call of their own
// — see the package doc comment.
var alwaysNotCheckableIDs = []string{idTagsSigned, idChecksums, idSignatures}

// evidenceCheckIDs are the two checks backed by real, evidence-based
// collectRepo logic.
var evidenceCheckIDs = []string{idWorkflow, idCommitLinkage}

var checkIDs = append(append([]string{}, alwaysNotCheckableIDs...), evidenceCheckIDs...)

// checkTitles is allowed to differ from the GitHub twin's wording (epic #34
// open decision 4: same ID, per-platform Title). commit-linkage's own Title
// swaps "workflow run" for "build" — Azure DevOps's own nomenclature for
// what a pipeline produces — mirroring sasthistory's identical wording
// choice throughout.
var checkTitles = map[string]string{
	idTagsSigned:    "Release tags are signed and their signature is verified",
	idChecksums:     "Releases ship checksum assets",
	idSignatures:    "Releases ship signature or attestation assets",
	idWorkflow:      "A provenance-generating tool is configured",
	idCommitLinkage: "Release artifacts are traceable to a build on the release commit",
}

var checkRemediations = map[string]string{
	idTagsSigned: "No remediation applicable via this tool: Azure DevOps's GitAnnotatedTag (Git Annotated " +
		"Tags - Get) exposes message/taggedBy/taggedObject and no signature or verification field of any " +
		"kind, and Azure DevOps does not verify tag signatures the way GitHub does — there is nothing this " +
		"tool could ever confirm here, regardless of whether tags are genuinely signed with git's own " +
		"mechanisms. Document any real tag-signing practice in the self-attestation questionnaire instead.",
	idChecksums: "No remediation applicable via this tool: Azure DevOps has no release-asset concept the way " +
		"GitHub Releases does. Azure Artifacts is a package registry, not a release-asset store, and is out " +
		"of scope for this collector (issue #153's own C07 spec). Document any real checksum-publishing " +
		"practice (e.g. via Azure Artifacts or an external release process) in the self-attestation " +
		"questionnaire instead.",
	idSignatures: "No remediation applicable via this tool: the same platform gap as C07.release.checksums " +
		"applies — Azure DevOps has no release-asset concept for this collector to inspect signature/" +
		"attestation assets against. Document any real signing practice in the self-attestation " +
		"questionnaire instead.",
	idWorkflow: "Add a provenance-generating step to the pipeline: Sigstore/cosign (a `cosign sign`/" +
		"`sign-blob`/`attest` invocation), or a SLSA provenance generator — see mappings/scanner-signatures.yaml " +
		"for what this tool recognizes. No ADO-native attestation task exists, so a pipeline whose name " +
		"merely suggests provenance (e.g. \"SLSA\") isn't enough on its own; it needs a matched run-pattern " +
		"invocation to count as more than a low-confidence signal.",
	idCommitLinkage: "Make sure the pipeline that produces release assets is triggered by (or runs on) the " +
		"same commit being tagged — e.g. a tag-created trigger, or the same branch build release automation " +
		"consumes — rather than run manually against an unrelated commit.",
}

// alwaysNotCheckableReasons is each always-not-checkable check's fixed
// Reason, stated as a direct platform fact rather than echoing the
// Rubric's "always —" framing verbatim — mirrors vdp's checkPrivateReporting/
// checkSecurityPolicyOrg convention exactly (that hedge belongs in registry
// metadata, not a runtime Reason written into a signed evidence pack).
var alwaysNotCheckableReasons = map[string]string{
	idTagsSigned: "Azure DevOps's GitAnnotatedTag exposes message/taggedBy/taggedObject and no signature or " +
		"verification field of any kind, and Azure DevOps does not verify tag signatures the way GitHub does " +
		"— there is nothing this tool could ever call to confirm it",
	idChecksums: "Azure DevOps has no release-asset concept the way GitHub Releases does; Azure Artifacts is " +
		"a package registry, not a release-asset store, and is out of scope for this collector",
	idSignatures: "Azure DevOps has no release-asset concept the way GitHub Releases does; Azure Artifacts is " +
		"a package registry, not a release-asset store, and is out of scope for this collector",
}

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce.
var checkRubrics = map[string]map[model.Status]string{
	idTagsSigned: {
		model.StatusNotCheckable: "always — Azure DevOps's GitAnnotatedTag exposes message/taggedBy/" +
			"taggedObject and no signature or verification field of any kind; Azure DevOps does not verify " +
			"tag signatures the way GitHub does — there is nothing this tool could ever call to confirm it, " +
			"verified head-on against the GitAnnotatedTag reference",
	},
	idChecksums: {
		model.StatusNotCheckable: "always — Azure DevOps has no release-asset concept the way GitHub " +
			"Releases does; Azure Artifacts is a package registry, not a release-asset store, and is out of " +
			"scope for this collector (issue #153's own C07 spec)",
	},
	idSignatures: {
		model.StatusNotCheckable: "always — Azure DevOps has no release-asset concept the way GitHub " +
			"Releases does; Azure Artifacts is a package registry, not a release-asset store, and is out of " +
			"scope for this collector (issue #153's own C07 spec)",
	},
	idWorkflow: {
		model.StatusVerifiedPass: "at least one matched pipeline reaches medium-or-high confidence (an " +
			"ado_task or run-pattern match — e.g. a cosign sign/sign-blob/attest invocation — not just a " +
			"suggestive pipeline/step name)",
		model.StatusPartial: "only a low-confidence (pipeline/step-name-only) match was found — not enough " +
			"signal alone to confirm a provenance tool is genuinely configured",
		model.StatusVerifiedFail: "no provenance-generating tool of any confidence was detected in any " +
			"pipeline, and every pipeline MatchPipelines inspected for this repo resolved cleanly (no " +
			"same-repo skip) — a real absence, not an evidence gap",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or one or more of this repo's own " +
			"pipelines could not be fully inspected (a build-definition fetch failure, an unresolved YAML " +
			"path, a YAML fetch/parse failure, or an unresolved template reference — see " +
			"Facts.skipped_pipelines) and the evidence gathered would otherwise have produced verified-fail " +
			"— this check applies the honest not-checkable fix rather than asserting a confident absence over " +
			"incomplete evidence",
	},
	idCommitLinkage: {
		model.StatusVerifiedPass: "every release in the lookback window has at least one build whose " +
			"sourceVersion equals the release's own resolved commit SHA, within the bounded build search " +
			"window (see Facts.builds_search_start)",
		model.StatusVerifiedFail: "at least one release in the lookback window has zero builds on its commit " +
			"within the bounded search window — builds are fetched from the oldest evaluated release's own " +
			"date minus a fixed 90-day grace window, not an unbounded history (see Facts.builds_search_start " +
			"for the exact bound this run applied), so an unusually large gap between a release tag and the " +
			"build/commit it names could in principle still be missed",
		model.StatusPartial: "one or more release tags matching the configured pattern could not be dated " +
			"(their commit is always already known straight from the refs listing itself — it's only the " +
			"date lookup that failed; see the package doc comment for why this collector applies C05/C06's " +
			"unconditional-dropped-tag rule here too); if that leaves nothing evaluable, the reason names the " +
			"drop count directly and no release's build coverage was evaluated at all; otherwise every " +
			"evaluated release is still traceable to a build on its commit, but the exclusion caps the " +
			"result at partial",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or no release tag matches the " +
			"configured pattern within the lookback window, and none of the tags that did match were dropped " +
			"as unresolvable either — genuinely nothing to evaluate; or the project's build history itself " +
			"could not be fetched",
	},
}

// sharedUpstreamFetchFailureRubric is shared by both evidence checks:
// collectRepo returns not-checkable for both on the first failure among
// the project's repositories/pipelines listing or this repo's own release
// resolution — mirrors sasthistory's identical sharedUpstreamFetchFailureRubric,
// including its same asymmetry (commit-linkage doesn't itself read
// pipeline-match data, but still goes not-checkable if pipeline discovery
// failed, the same way sasthistory's idDefaultSetup does for its own
// unrelated evidence).
const sharedUpstreamFetchFailureRubric = "the project's repositories or pipelines couldn't be read " +
	"(403/other API error), the named repository wasn't found in the project, or resolving this repo's " +
	"release tags failed (403/other API error) — collectRepo returns not-checkable for both evidence checks " +
	"on the first such failure; or the embedded scanner-signature registry itself failed to load (a " +
	"binary-level failure, independent of the scanned repo)"

// pipelineEvidenceEndpoints backs C07.provenance.workflow — project-scoped
// calls that happen once per Collect, shared across every repo in scope,
// identical to sasthistory's own pipelineEvidenceEndpoints.
var pipelineEvidenceEndpoints = []string{
	"GET dev.azure.com/{org}/{project}/_apis/git/repositories",
	"GET dev.azure.com/{org}/{project}/_apis/pipelines",
	"GET dev.azure.com/{org}/{project}/_apis/build/definitions/{definitionId}",
	"GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/items",
}

// releaseAndBuildEvidenceEndpoints backs C07.provenance.commit-linkage —
// release-tag resolution plus the unfiltered build-history fetch.
var releaseAndBuildEvidenceEndpoints = []string{
	"GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/refs",
	"GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/annotatedtags/{objectId}",
	"GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/commits/{commitId}",
	"GET dev.azure.com/{org}/{project}/_apis/build/builds",
}

// checkEndpoints documents only the calls each check's OWN business logic
// reads — not every call in collectRepo's shared early-return chain, the
// same convention sasthistory's idDefaultSetup Endpoints establishes (its
// Rubric's NotCheckable prose, not Endpoints, is what documents a shared
// upstream failure also routing here). idTagsSigned/idChecksums/idSignatures
// are nil: all three make no API call at all — see the package doc comment.
var checkEndpoints = map[string][]string{
	idTagsSigned:    nil,
	idChecksums:     nil,
	idSignatures:    nil,
	idWorkflow:      append([]string{}, pipelineEvidenceEndpoints...),
	idCommitLinkage: append([]string{}, releaseAndBuildEvidenceEndpoints...),
}

var checkTokenScopes = map[string]string{
	idTagsSigned: "none — this check makes no API call of its own; Azure DevOps has no tag-signature-" +
		"verification feature to query (see its own doc comment)",
	idChecksums: "none — this check makes no API call of its own; Azure DevOps has no release-asset concept " +
		"to query (see its own doc comment)",
	idSignatures: "none — this check makes no API call of its own; Azure DevOps has no release-asset concept " +
		"to query (see its own doc comment)",
	idWorkflow:      "vso.build, vso.code (pipeline discovery and YAML fetch)",
	idCommitLinkage: "vso.build, vso.code",
}

const fixtureRef = "internal/collect/azuredevops/provenance/provenance_test.go"

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

// Collector implements C07 provenance for Azure DevOps.
type Collector struct {
	client *azuredevops.Client
}

// New returns a C07 collector using client for all API calls. Like C05
// sasthistory, one shared Client covers every repo in scope: pipeline
// discovery and repository listing are project-scoped (exactly once,
// regardless of repo count), and per-repo calls run sequentially on this
// same Client.
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
		var all []model.CheckResult
		for _, repo := range scope.Repos {
			all = append(all, alwaysNotCheckableResults(scope.Org, repo)...)
			all = append(all, allEvidenceNotCheckable(scope.Org, repo, fmt.Sprintf("could not load the embedded scanner-signature registry: %v", err), nil)...)
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
		matchedAll, skippedAll = pipelinehistory.MatchPipelines(ctx, c.client, registry, scope.Project, pipelines, mapping.CategoryProvenance)
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

// collectRepo emits every check for one repo: the three always-not-
// checkable results first (unconditional, no dependency on anything below),
// then the two evidence checks via the shared early-return gate described
// in the package doc comment.
func (c *Collector) collectRepo(ctx context.Context, scope collect.Scope, repoName string, repos []pipelinehistory.RepositoryInfo, reposErr, pipelinesErr error, matchedAll []pipelinehistory.MatchedPipeline, skippedAll []pipelinehistory.SkippedPipeline, projectProv []model.Provenance) []model.CheckResult {
	always := alwaysNotCheckableResults(scope.Org, repoName)

	if reposErr != nil {
		return append(always, allEvidenceNotCheckable(scope.Org, repoName, apiErrorReason(reposErr, "project repositories"), projectProv)...)
	}
	repo, found := pipelinehistory.FindRepository(repos, repoName)
	if !found {
		return append(always, allEvidenceNotCheckable(scope.Org, repoName, fmt.Sprintf("repository %q not found in project %q", repoName, scope.Project), projectProv)...)
	}
	if pipelinesErr != nil {
		return append(always, allEvidenceNotCheckable(scope.Org, repoName, apiErrorReason(pipelinesErr, "project pipelines"), projectProv)...)
	}

	var matched []pipelinehistory.MatchedPipeline
	for _, mp := range matchedAll {
		if mp.RepositoryID == repo.ID {
			matched = append(matched, mp)
		}
	}
	var sameRepoSkips []pipelinehistory.SkippedPipeline
	for _, sp := range skippedAll {
		if sp.RepositoryID == repo.ID {
			sameRepoSkips = append(sameRepoSkips, sp)
		}
	}

	now := time.Now().UTC()

	repoStart := len(c.client.Provenance())

	releases, dropped, relErr := pipelinehistory.ResolveReleases(ctx, c.client, scope.Project, repo.ID, scope.ReleaseTagPattern)
	if relErr != nil {
		prov := append(append([]model.Provenance{}, projectProv...), tailProvenance(c.client.Provenance(), repoStart)...)
		return append(always, allEvidenceNotCheckable(scope.Org, repoName, apiErrorReason(relErr, "release tags"), prov)...)
	}
	filteredReleases := pipelinehistory.FilterReleasesInLookback(releases, scope.ReleaseTagPattern, scope.LookbackReleases, scope.LookbackMonths, now)

	// definitionIDs is deliberately nil, not matched's own definition IDs:
	// commit-linkage cares whether ANY build ran on a release's commit, not
	// specifically a provenance-tool build — see the package doc comment.
	//
	// buildsSearchStart is anchored to the oldest EVALUATED release's own
	// date (not the raw now-LookbackMonths cutoff releases are admitted
	// at-or-after) minus commitLinkageBuildGraceWindow — found in review:
	// the previous minTime (the same cutoff FilterReleasesInLookback
	// admits releases at-or-after) could sit AFTER a genuinely-in-window
	// release's own commit/build, false-failing it. See
	// commitLinkageBuildGraceWindow's own doc comment (checks.go) for why
	// this bound, not an unbounded fetch. Skipped entirely when there are
	// no releases to link against, both to avoid a wasted call and because
	// checkCommitLinkage never reads runs/buildsErr in that case anyway.
	var runs []pipelinehistory.RunInfo
	var buildsErr error
	var buildsSearchStart time.Time
	if len(filteredReleases) > 0 {
		oldest := filteredReleases[len(filteredReleases)-1].PublishedAt // sorted newest-first
		buildsSearchStart = oldest.Add(-commitLinkageBuildGraceWindow)
		runs, buildsErr = pipelinehistory.FetchBuilds(ctx, c.client, scope.Project, repo.ID, nil, buildsSearchStart)
	}

	sharedProv := append(append([]model.Provenance{}, projectProv...), tailProvenance(c.client.Provenance(), repoStart)...)

	linked := linkBuildsToCommits(filteredReleases, runs)

	return append(always,
		checkProvenanceWorkflow(scope.Org, repoName, matched, sameRepoSkips, sharedProv),
		checkCommitLinkage(scope.Org, repoName, filteredReleases, linked, dropped, buildsErr, buildsSearchStart, sharedProv),
	)
}

// alwaysNotCheckableResults emits the three always-not-checkable checks —
// no API call, no dependency on ctx or anything else in collectRepo. See
// the package doc comment.
func alwaysNotCheckableResults(org, repo string) []model.CheckResult {
	out := make([]model.CheckResult, 0, len(alwaysNotCheckableIDs))
	for _, id := range alwaysNotCheckableIDs {
		out = append(out, model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: alwaysNotCheckableReasons[id],
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: []model.Provenance{},
		})
	}
	return out
}

// allEvidenceNotCheckable emits not-checkable for just the two evidence
// checks (idWorkflow, idCommitLinkage) — the always-not-checkable three are
// never included here, since alwaysNotCheckableResults already covers them
// unconditionally in every collectRepo path.
func allEvidenceNotCheckable(org, repo, reason string, prov []model.Provenance) []model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	out := make([]model.CheckResult, 0, len(evidenceCheckIDs))
	for _, id := range evidenceCheckIDs {
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
// dev.azure.com-hosted calls.
func apiErrorReason(err error, what string) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) && se.StatusCode == http.StatusForbidden {
		return fmt.Sprintf("token lacks permission to read %s", what)
	}
	return fmt.Sprintf("could not read %s: %v", what, err)
}
