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

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/collect/github/runhistory"
	"github.com/sioakim/ssdf/internal/mapping"
	"github.com/sioakim/ssdf/internal/model"
	"github.com/sioakim/ssdf/mappings"
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

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:          id,
			Title:       checkTitles[id],
			Collector:   collectorID,
			TokenScope:  "repo (classic) or Contents: read-only (fine-grained) — plus whatever fine-grained category gates git ref/tag reads and the attestations endpoint specifically, not independently verified against GitHub's docs (see C05's TokenScope for the same kind of hedge, and why)",
			Remediation: checkRemediations[id],
		})
	}
}

// Collector implements C07 provenance.
type Collector struct {
	token string

	// newClientForTest overrides how each repo's Client is constructed —
	// see sasthistory.Collector's identical field for why.
	newClientForTest func(token string) *ghcollect.Client
}

// New returns a C07 collector authenticated with token. Per-repo checks
// fan out via ForEachRepo's concurrent worker pool, so each repo
// constructs its own Client — see sasthistory.New's doc comment for why a
// shared client across concurrent repos would corrupt provenance
// attribution.
func New(token string) *Collector {
	return &Collector{token: token}
}

func (c *Collector) newClient() *ghcollect.Client {
	if c.newClientForTest != nil {
		return c.newClientForTest(c.token)
	}
	return ghcollect.NewClient(c.token)
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
		return allNotCheckable(org, repo, notCheckableReason(resp, err, org, repo), client.Provenance())
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
		return allNotCheckable(org, repo, notCheckableReason(wfResp, err, org, repo), client.Provenance())
	}
	provWorkflowMatches := runhistory.MatchWorkflows(ctx, client, registry, org, repo, defaultBranch, allWorkflows, mapping.CategoryProvenance)
	workflowMatchProv := snapshot()

	now := time.Now().UTC()
	tagPattern := scope.ReleaseTagPattern
	rawReleases, relResp, relErr := runhistory.FetchReleases(ctx, client, org, repo)
	if relErr != nil {
		return allNotCheckable(org, repo, notCheckableReason(relResp, relErr, org, repo), client.Provenance())
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
		checkProvenanceWorkflow(org, repo, provWorkflowMatches, workflowMatchProv),
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
