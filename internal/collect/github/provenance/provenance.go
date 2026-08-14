// Package provenance implements C07 provenance: whether release tags are
// signed and GitHub-verified, whether releases ship checksum and
// signature/attestation assets, whether a provenance-generating tool
// (Sigstore/cosign, SLSA generator, or GitHub Attestations) is configured,
// and whether release artifacts are traceable to a workflow run on the
// release commit (SSDF PS.2.1, PS.3.2).
package provenance

import (
	"context"
	"fmt"
	"time"

	ghgithub "github.com/google/go-github/v75/github"

	"gitlab.com/sioakeim/attestward/internal/collect"
	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/collect/github/runhistory"
	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/internal/model"
	"gitlab.com/sioakeim/attestward/mappings"
)

const collectorID = "C07.provenance"

var checkTitles = map[string]string{
	"C07.release.tags-signed":       "Release tags are signed and GitHub reports the signature verified",
	"C07.release.checksums":         "Releases ship checksum assets",
	"C07.release.signatures":        "Releases ship signature or attestation assets",
	"C07.provenance.workflow":       "A provenance-generating tool is configured",
	"C07.provenance.commit-linkage": "Release artifacts are traceable to a workflow run on the release commit",
}

var checkIDs = []string{
	"C07.release.tags-signed",
	"C07.release.checksums",
	"C07.release.signatures",
	"C07.provenance.workflow",
	"C07.provenance.commit-linkage",
}

var checkRemediations = map[string]string{
	"C07.release.tags-signed": "Sign release tags with a GPG or SSH key (`git tag -s` or `git tag -u " +
		"<key> vX.Y.Z`), and register the matching public key under the tagging user's own account " +
		"Settings -> SSH and GPG keys — add it specifically as a \"Signing Key\" (a key added only for " +
		"authentication won't verify signatures). Signature verification is always tied to the " +
		"individual tagger's personal account; there is no equivalent org-level key registration.",
	"C07.release.checksums": "Publish a checksum file (e.g. `checksums.txt`/`SHA256SUMS`) as a release " +
		"asset — most release-automation tools (e.g. goreleaser) generate this automatically as part of " +
		"the release job.",
	"C07.release.signatures": "Attach a signature/attestation asset to each release (e.g. a cosign " +
		"`.sig`/`.pem` bundle), or generate a GitHub Artifact Attestation for the release assets during " +
		"the build workflow via `actions/attest-build-provenance`.",
	"C07.provenance.workflow": "Add a provenance-generating step to the release workflow: Sigstore/" +
		"cosign, a SLSA provenance generator (slsa-framework/slsa-github-generator), or GitHub's native " +
		"`actions/attest-build-provenance` action.",
	"C07.provenance.commit-linkage": "Make sure the workflow that produces release assets is triggered " +
		"by the same commit being tagged/released — e.g. `on: release: types: [published]` or a tag-push " +
		"trigger — rather than run manually (workflow_dispatch) against an unrelated commit.",
}

// sharedUpstreamFetchFailureRubric is shared by all five checks: like
// C05 (and unlike C06), the repo fetch, the workflow listing, AND the
// release listing all early-return allNotCheckable in collectRepo — none
// of the five checks below can be computed without this shared evidence,
// regardless of whether a given check actually reads workflow or release
// data. Collect's own embedded-registry-load failure is a distinct,
// binary-level cause that also reaches every check for every repo in
// scope, independent of the target repo's own state.
const sharedUpstreamFetchFailureRubric = "the repo fetch, the workflow listing, or the release listing " +
	"failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on the " +
	"first such failure, since none of them can be computed without this shared evidence; or the embedded " +
	"scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned " +
	"repo — since issue #255, this fallback is no longer reachable via `attestward scan`: the " +
	"orchestrator's own load of the same embedded file now aborts the whole scan first if it fails; kept " +
	"as defense in depth for any caller that doesn't go through scan.go's own pre-load)"

// sharedNoMatchingReleasesRubric is shared by the four per-release
// checks (every check except provenance.workflow, which is release-
// independent): each returns this not-checkable reason directly, before
// any per-release evaluation, when zero releases match the configured
// tag pattern within the lookback window.
const sharedNoMatchingReleasesRubric = "no releases match the configured release tag pattern within the " +
	"lookback window"

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce — see checks.go for the pass/fail/partial logic
// each rubric below summarizes. C07.release.checksums is notable: unlike
// every other check in this package, it has no partial branch at all —
// its per-release evaluation is pure computation over already-fetched
// release/asset data with no further I/O that could leave a release
// unresolved (see checkChecksums).
var checkRubrics = map[string]map[model.Status]string{
	"C07.release.tags-signed": {
		model.StatusVerifiedPass: "every release tag in the lookback window is annotated, signed, and " +
			"GitHub reports its signature verified",
		model.StatusVerifiedFail: "at least one resolved release tag in the lookback window is either a " +
			"lightweight tag (which can never be signed — git's own object model only lets an annotated " +
			"tag carry a signature) or an annotated tag that's unsigned or whose signature GitHub doesn't " +
			"report as verified",
		model.StatusPartial: "every resolvable release tag in the lookback window is signed and verified, " +
			"but at least one tag's resolution (Git.GetRef/Git.GetTag) itself failed — unresolved, not a " +
			"confirmed pass or fail",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or " + sharedNoMatchingReleasesRubric,
	},
	"C07.release.checksums": {
		model.StatusVerifiedPass: "every release in the lookback window ships at least one asset matching " +
			"a known checksum-file naming convention (checksums.txt, SHA256SUMS, or a per-file " +
			"`.sha256`/`.sha256sum` sidecar)",
		model.StatusVerifiedFail: "at least one release in the lookback window has no asset matching a " +
			"known checksum-file naming convention",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or " + sharedNoMatchingReleasesRubric,
	},
	"C07.release.signatures": {
		model.StatusVerifiedPass: "every release in the lookback window ships an asset matching a known " +
			"signature/attestation naming convention (`.sig`, `.pem`, `.intoto.jsonl`, `.sigstore`, " +
			"`.bundle`), or has at least one GitHub Artifact Attestation found for one of its asset digests",
		model.StatusVerifiedFail: "at least one release in the lookback window has neither a matching " +
			"signature/attestation asset nor a GitHub Artifact Attestation for any of its asset digests — " +
			"every attestation lookup attempted for it completed cleanly with zero results",
		model.StatusPartial: "every release with confirmed evidence ships a matching asset or has a " +
			"GitHub Artifact Attestation, but at least one release has no matching asset and its " +
			"attestation lookup itself failed before confirming an absence — unresolved, not a confirmed " +
			"absence (the digest that errored might well have an attestation)",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or " + sharedNoMatchingReleasesRubric,
	},
	"C07.provenance.workflow": {
		model.StatusVerifiedPass: "at least one matched workflow reaches medium-or-high confidence (an " +
			"action slug or CLI pattern recognized as Sigstore/cosign, a SLSA generator, or GitHub " +
			"Attestations — not just a suggestive workflow name)",
		model.StatusPartial: "only a low-confidence (workflow-name-only) match was found — not enough " +
			"signal alone to confirm a provenance tool is genuinely configured",
		model.StatusVerifiedFail: "no provenance-generating tool of any confidence was detected in any " +
			"workflow, and every workflow runhistory.MatchWorkflows inspected for this repo resolved " +
			"cleanly (no same-repo skip) — a real absence, not an evidence gap",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or one or more of this repo's own " +
			"workflows could not be fully inspected (a content-fetch failure, a decode failure, or a YAML " +
			"parse failure — see Facts.skipped_workflows) and the evidence gathered would otherwise have " +
			"produced verified-fail — this check applies the honest not-checkable fix rather than asserting " +
			"a confident absence over incomplete evidence",
	},
	"C07.provenance.commit-linkage": {
		model.StatusVerifiedPass: "every release in the lookback window has at least one workflow run " +
			"(any workflow, any conclusion) whose HeadSHA equals the release's resolved commit",
		model.StatusVerifiedFail: "at least one resolved release in the lookback window has zero workflow " +
			"runs on its commit",
		model.StatusPartial: "every release with a resolved commit is traceable to a workflow run on it, " +
			"but at least one release's commit could not be resolved (tag resolution failed) or its run " +
			"listing itself failed — unresolved, not a confirmed pass or fail",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or " + sharedNoMatchingReleasesRubric,
	},
}

// sharedProvenanceEvidenceEndpoints are the calls that determine
// matchedWorkflows and defaultBranch — used only by
// C07.provenance.workflow, which is the sole check drawing on
// workflow-content-match evidence rather than release/tag/attestation
// evidence.
var sharedProvenanceEvidenceEndpoints = []string{
	"GET /repos/{owner}/{repo}",
	"GET /repos/{owner}/{repo}/actions/workflows",
	"GET /repos/{owner}/{repo}/contents/{path}",
}

const releasesAPIEndpoint = "GET /repos/{owner}/{repo}/releases"
const gitRefAPIEndpoint = "GET /repos/{owner}/{repo}/git/ref/{ref}"
const gitTagAPIEndpoint = "GET /repos/{owner}/{repo}/git/tags/{tag_sha}"
const attestationsAPIEndpoint = "GET /repos/{owner}/{repo}/attestations/{subject_digest}"
const workflowRunsByCommitAPIEndpoint = "GET /repos/{owner}/{repo}/actions/runs?head_sha={sha}"

// checkEndpoints lists which REST endpoint(s) actually back each check's
// status.
var checkEndpoints = map[string][]string{
	"C07.release.tags-signed":       {releasesAPIEndpoint, gitRefAPIEndpoint, gitTagAPIEndpoint},
	"C07.release.checksums":         {releasesAPIEndpoint},
	"C07.release.signatures":        {releasesAPIEndpoint, attestationsAPIEndpoint},
	"C07.provenance.workflow":       append([]string{}, sharedProvenanceEvidenceEndpoints...),
	"C07.provenance.commit-linkage": {releasesAPIEndpoint, gitRefAPIEndpoint, gitTagAPIEndpoint, workflowRunsByCommitAPIEndpoint},
}

const fixtureRef = "internal/collect/github/provenance/provenance_test.go"

// checkGHESNotes is issue #13's per-check GHES divergence audit.
// release.signatures is the one exception: attestationsAPIEndpoint (GitHub
// Artifact Attestations) reached general availability on github.com only
// in 2024 — recent enough that this tool's authors have no verified
// knowledge of whether or from which version it shipped to GHES, so this
// is GHESNoteUnverified rather than a guess. Every other check here only
// reads releases/git-refs/git-tags/workflow-runs, all basic REST surface.
var checkGHESNotes = map[string]string{
	"C07.release.tags-signed":       ghcollect.GHESNoteSupported,
	"C07.release.checksums":         ghcollect.GHESNoteSupported,
	"C07.release.signatures":        ghcollect.GHESNoteUnverified,
	"C07.provenance.workflow":       ghcollect.GHESNoteSupported,
	"C07.provenance.commit-linkage": ghcollect.GHESNoteSupported,
}

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:          id,
			Platform:    "github",
			Title:       checkTitles[id],
			Collector:   collectorID,
			TokenScope:  "repo (classic) or Contents: read-only (fine-grained) — plus whatever fine-grained category gates git ref/tag reads and the attestations endpoint specifically, not independently verified against GitHub's docs (see C05's TokenScope for the same kind of hedge, and why)",
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			GHESNote:    checkGHESNotes[id],
			FixtureRef:  fixtureRef,
		})
	}
}

// Collector implements C07 provenance.
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

// New returns a C07 collector authenticated with token, targeting cfg's
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

// collectRepo resolves signed-tag, checksum/signature-asset,
// provenance-workflow, and commit-linkage evidence for one repo and emits
// all five CheckResults. It never returns an error; every failure becomes
// a not-checkable result for the affected check(s).
func collectRepo(ctx context.Context, client *ghcollect.Client, registry *mapping.ScannerSignatureRegistry, org, repo string, scope collect.Scope) []model.CheckResult {
	repository, resp, err := client.REST.Repositories.Get(ctx, org, repo)
	if err != nil {
		return allNotCheckable(org, repo, notCheckableReason(resp, err, org, repo, scope), client.Provenance())
	}
	defaultBranch := repository.GetDefaultBranch()

	// prevLen starts at 0, not len(client.Provenance()) after the Get call
	// below — client is freshly constructed per repo, so Provenance() is
	// empty at this point anyway, and starting here means the first
	// snapshot() call includes this initial Get's own provenance entry.
	prevLen := 0
	snapshot := func() []model.Provenance {
		all := client.Provenance()
		seg := append([]model.Provenance{}, all[prevLen:]...)
		prevLen = len(all)
		return seg
	}

	allWorkflows, wfResp, err := runhistory.ListWorkflows(ctx, client, org, repo)
	if err != nil {
		return allNotCheckable(org, repo, notCheckableReason(wfResp, err, org, repo, scope), client.Provenance())
	}
	// The skipped return now feeds checkProvenanceWorkflow directly (issue
	// #207 — this was the one tool-configured-shaped check on either
	// platform never brought up to the pattern C05/C06 established for
	// issue #178).
	provWorkflowMatches, provSkippedWorkflows := runhistory.MatchWorkflows(ctx, client, registry, org, repo, defaultBranch, allWorkflows, mapping.CategoryProvenance)
	workflowMatchProv := snapshot()

	now := time.Now().UTC()
	tagPattern := scope.ReleaseTagPattern
	rawReleases, relResp, relErr := runhistory.FetchReleases(ctx, client, org, repo)
	if relErr != nil {
		return allNotCheckable(org, repo, notCheckableReason(relResp, relErr, org, repo, scope), client.Provenance())
	}
	rawByTag := make(map[string]*ghgithub.RepositoryRelease, len(rawReleases))
	releaseInfos := make([]runhistory.ReleaseInfo, 0, len(rawReleases))
	for _, r := range rawReleases {
		rawByTag[r.GetTagName()] = r
		releaseInfos = append(releaseInfos, runhistory.ReleaseInfo{
			TagName:     r.GetTagName(),
			PublishedAt: r.GetPublishedAt().Time,
		})
	}
	filteredReleases := runhistory.FilterReleasesInLookback(releaseInfos, tagPattern, scope.LookbackReleases, scope.LookbackMonths, now)
	releaseListProv := snapshot()

	resolved := make([]resolvedRelease, 0, len(filteredReleases))
	for _, rel := range filteredReleases {
		sig, sigErr := resolveTagSignature(ctx, client, org, repo, rel.TagName)
		resolved = append(resolved, resolvedRelease{Release: rel, Signature: sig, ResolveErr: sigErr})
	}
	tagSignatureProv := snapshot()

	sigEvidence := make(map[string]signatureEvidence, len(filteredReleases))
	for _, rel := range filteredReleases {
		raw := rawByTag[rel.TagName]
		var names, digests []string
		if raw != nil {
			for _, a := range raw.Assets {
				names = append(names, a.GetName())
				if d := a.GetDigest(); d != "" {
					digests = append(digests, d)
				}
			}
		}
		matched := matchingAssetNames(names, signatureAssetPatterns)
		ev := signatureEvidence{TagName: rel.TagName, MatchedAssetNames: matched}
		if len(matched) == 0 {
			// Only pay for attestation lookups when the naming-convention
			// path didn't already establish evidence — see
			// hasAnyAttestation's doc comment for the per-release cap too.
			ev.AttestedDigest, ev.LookupCapped, ev.AttestationErr = hasAnyAttestation(ctx, client, org, repo, digests)
		}
		sigEvidence[rel.TagName] = ev
	}
	signaturesProv := snapshot()

	linkageResults := make([]linkageResult, 0, len(resolved))
	for _, r := range resolved {
		if r.ResolveErr != nil {
			linkageResults = append(linkageResults, linkageResult{TagName: r.Release.TagName, Err: r.ResolveErr})
			continue
		}
		runs, _, runsErr := fetchWorkflowRunsForCommit(ctx, client, org, repo, r.Signature.CommitSHA)
		linkageResults = append(linkageResults, linkageResult{TagName: r.Release.TagName, RunCount: len(runs), Err: runsErr})
	}
	commitLinkageProv := snapshot()

	return []model.CheckResult{
		checkTagsSigned(org, repo, resolved, concatProv(releaseListProv, tagSignatureProv)),
		checkChecksums(org, repo, filteredReleases, rawByTag, releaseListProv),
		checkSignatures(org, repo, filteredReleases, sigEvidence, concatProv(releaseListProv, signaturesProv)),
		checkProvenanceWorkflow(org, repo, provWorkflowMatches, provSkippedWorkflows, workflowMatchProv),
		checkCommitLinkage(org, repo, linkageResults, concatProv(releaseListProv, tagSignatureProv, commitLinkageProv)),
	}
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
