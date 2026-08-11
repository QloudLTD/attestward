// Package provenance implements three of C07 provenance's five checks for
// GitLab: release.checksums, release.signatures, release.tags-signed.
//
// Before this package existed, all five were registered through
// internal/collect/gitlab/unsupported with one shared reason: "GitLab
// exposes releases, tags and release assets... This build does not read
// them yet." True of these three — GET /projects/:id/releases and GET
// /projects/:id/repository/tags/:tag/signature are both real, documented,
// Free-tier endpoints, verified live (2026-08-11) against a dedicated
// scratch project (gitlab.com/sioakeim/attestward-scratch, same Free
// namespace as attestward itself): a real tag, a real release, a real
// release-asset link, and both the unsigned-tag 404 and the documented
// signed-tag response shape for GET .../signature.
//
// provenance.commit-linkage and provenance.workflow stay in
// gitlab/unsupported, unmoved, for a different reason than a wrong tier
// claim: both need matching pipeline/job run history against a
// cross-platform provenance-tool signature registry (see
// internal/collect/github/runhistory's MatchWorkflows and Azure DevOps's
// MatchPipelines) — porting that engine to GitLab CI is real, separately-
// scoped work, tracked in issue #1, not something to fold into this MR.
//
// GitLab's release-asset model is simpler than GitHub's to reason about:
// GET /projects/:id/releases always returns two disjoint asset lists —
// `assets.sources` (four auto-generated source archives, always present,
// never evidence of anything a producer configured) and `assets.links`
// (whatever the producer actually attached) — so unlike GitHub's Contents
// API, there is no directory-vs-file ambiguity to guard against here.
package provenance

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const platform = "gitlab"
const collectorID = "C07.provenance"

const (
	idCommitLinkage = "C07.provenance.commit-linkage"
	idWorkflow      = "C07.provenance.workflow"
	idChecksums     = "C07.release.checksums"
	idSignatures    = "C07.release.signatures"
	idTagsSigned    = "C07.release.tags-signed"
)

var checkTitles = map[string]string{
	idCommitLinkage: "Release artifacts are traceable to a workflow run on the release commit",
	idWorkflow:      "A provenance-generating tool is configured",
	idChecksums:     "Releases ship checksum assets",
	idSignatures:    "Releases ship signature or attestation assets",
	idTagsSigned:    "Release tags are signed and GitLab reports the signature verified",
}

// releaseEngineGapReason is shared by commit-linkage and workflow — the two
// checks staying in gitlab/unsupported. Named here, not there, so the
// package that actually knows why (this one) is where the explanation
// lives; unsupported.go's own table just points at this package's doc
// comment.
const releaseEngineGapReason = "evaluating this needs matching GitLab CI pipeline/job run history against a " +
	"provenance-tool signature registry, the same engine internal/collect/gitlab/provenance's own checks " +
	"depend on for release.checksums/signatures/tags-signed's siblings on GitHub and Azure DevOps — porting it " +
	"to GitLab CI is real, separately-scoped work (issue #1), not read by this build yet"

const noReleasesInWindowReason = "no releases match the configured release tag pattern within the lookback window"

var checkRemediations = map[string]string{
	idChecksums: "Attach a checksums.txt (or per-file .sha256 sidecar) to each release, generated from the " +
		"published assets.",
	idSignatures: "Attach a signature/attestation asset to each release (e.g. a cosign `.sig`/`.bundle` or " +
		"`.pem` bundle) — GitLab has no GitHub-Artifact-Attestation-style digest-lookup equivalent, so a " +
		"named asset is the only evidence this check can find.",
	idTagsSigned: "Sign each release tag (GPG or X.509) before pushing it, and confirm GitLab reports the " +
		"signature verified at GET /projects/:id/repository/tags/:tag/signature.",
}

const sharedNoWindowRubric = "no releases match the configured release tag pattern within the lookback window"

var checkRubrics = map[string]map[model.Status]string{
	idCommitLinkage: {model.StatusNotCheckable: releaseEngineGapReason},
	idWorkflow:      {model.StatusNotCheckable: releaseEngineGapReason},
	idChecksums: {
		model.StatusVerifiedPass: "every release in the lookback window ships at least one asset matching a " +
			"known checksum-file naming convention (checksums.txt, SHA256SUMS, or a per-file `.sha256`/" +
			"`.sha256sum` sidecar)",
		model.StatusVerifiedFail: "at least one release in the lookback window has no asset matching a " +
			"known checksum-file naming convention",
		model.StatusNotCheckable: sharedNoWindowRubric + ", or the releases list itself couldn't be read " +
			"(403/404/other API error)",
	},
	idSignatures: {
		model.StatusVerifiedPass: "every release in the lookback window ships an asset matching a known " +
			"signature/attestation naming convention (`.sig`, `.pem`, `.intoto.jsonl`, `.sigstore`, " +
			"`.bundle`) — GitLab has no digest-lookup attestation mechanism to check as a second, " +
			"independent kind of evidence the way the GitHub twin does",
		model.StatusVerifiedFail: "at least one release in the lookback window has neither a matching " +
			"signature/attestation asset",
		model.StatusNotCheckable: sharedNoWindowRubric + ", or the releases list itself couldn't be read " +
			"(403/404/other API error)",
	},
	idTagsSigned: {
		model.StatusVerifiedPass: "every release tag in the lookback window is signed and GitLab reports " +
			"its verification_status as \"verified\" (GET /projects/:id/repository/tags/:tag/signature)",
		model.StatusVerifiedFail: "at least one release tag in the lookback window is unsigned (a 404 at " +
			"the signature endpoint) or signed but GitLab reports its verification_status as \"unverified\"",
		model.StatusPartial: "every resolvable release tag in the lookback window is signed and verified, " +
			"but at least one tag's own signature lookup failed with something other than the documented " +
			"404-means-unsigned response — unresolved, not a confirmed pass or fail",
		model.StatusNotCheckable: sharedNoWindowRubric + ", or the releases list itself couldn't be read " +
			"(403/404/other API error)",
	},
}

var checkEndpoints = map[string][]string{
	idCommitLinkage: nil,
	idWorkflow:      nil,
	idChecksums:     {"GET /projects/{id}/releases"},
	idSignatures:    {"GET /projects/{id}/releases"},
	idTagsSigned:    {"GET /projects/{id}/releases", "GET /projects/{id}/repository/tags/{tag_name}/signature"},
}

const fixtureRef = "internal/collect/gitlab/provenance/provenance_test.go"

func init() {
	for _, id := range []string{idCommitLinkage, idWorkflow} {
		collect.Register(collect.CheckMeta{
			ID: id, Platform: platform, Title: checkTitles[id], Collector: collectorID,
			TokenScope: "none — this check makes no API call of its own; see the package doc comment",
			Remediation: "Not evaluable by this build on GitLab yet. Until a collector lands, answer the " +
				"corresponding self-attestation question, or evidence the control from whichever system " +
				"actually generates provenance.",
			Rubric: checkRubrics[id], Endpoints: checkEndpoints[id], FixtureRef: fixtureRef,
		})
	}
	for _, id := range []string{idChecksums, idSignatures, idTagsSigned} {
		collect.Register(collect.CheckMeta{
			ID: id, Platform: platform, Title: checkTitles[id], Collector: collectorID,
			TokenScope:  "read_api (Reporter or above on the project)",
			Remediation: checkRemediations[id], Rubric: checkRubrics[id],
			Endpoints: checkEndpoints[id], FixtureRef: fixtureRef,
		})
	}
}

// release is the subset of GitLab's Releases response this needs, verified
// 2026-08-11 against a live release on gitlab.com/sioakeim/attestward-scratch.
type release struct {
	TagName    string    `json:"tag_name"`
	ReleasedAt time.Time `json:"released_at"`
	Assets     struct {
		Links []struct {
			Name string `json:"name"`
		} `json:"links"`
	} `json:"assets"`
}

// tagSignature is GET .../repository/tags/:tag/signature's response shape
// for a signed tag, per docs.gitlab.com/api/tags/. A 404 means unsigned —
// verified live against an unsigned tag on the scratch project — so this
// type is only ever decoded on a 2xx response.
type tagSignature struct {
	VerificationStatus string `json:"verification_status"`
}

// Collector implements 3 of 5 C07 provenance checks for GitLab.
type Collector struct {
	baseURL, token string
	newClient      func() (*gitlabcollect.Client, error)
}

// New builds the collector against a live GitLab instance.
func New(baseURL, token string) *Collector {
	c := &Collector{baseURL: baseURL, token: token}
	c.newClient = func() (*gitlabcollect.Client, error) { return gitlabcollect.NewClient(baseURL, token) }
	return c
}

// NewForTest builds the collector against an arbitrary base URL and
// round-tripper, so tests exercise the same client production assembles.
func NewForTest(baseURL, token string, newClient func() (*gitlabcollect.Client, error)) *Collector {
	return &Collector{baseURL: baseURL, token: token, newClient: newClient}
}

// ID returns the collector identifier recorded on every result it emits.
func (c *Collector) ID() string { return collectorID }

// Collect reads each repo's releases once and derives all five checks from
// it — commit-linkage and workflow always not-checkable, the other three
// real. A read failure yields not-checkable results rather than an error,
// so one unreadable project cannot fail a whole scan.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	client, err := c.newClient()
	if err != nil {
		reason := fmt.Sprintf("could not build a GitLab client: %v", err)
		var out []model.CheckResult
		for _, repo := range scope.Repos {
			out = append(out, allNotCheckable(scope.Org, repo, reason, nil)...)
		}
		return out, nil
	}

	var all []model.CheckResult
	for _, repo := range scope.Repos {
		all = append(all, collectRepo(ctx, client, scope, repo)...)
	}
	return all, nil
}

func collectRepo(ctx context.Context, client *gitlabcollect.Client, scope collect.Scope, repo string) []model.CheckResult {
	org := scope.Org
	id := projectID(org, repo)

	raw, err := gitlabcollect.GetJSONPaged[release](ctx, client, "/projects/"+id+"/releases", nil)
	prov := client.Provenance()
	if err != nil {
		return allNotCheckable(org, repo, fmt.Sprintf("could not read releases: %v", err), prov)
	}

	releases := make([]releaseInfo, 0, len(raw))
	assetsByTag := map[string][]string{}
	for _, r := range raw {
		names := make([]string, 0, len(r.Assets.Links))
		for _, l := range r.Assets.Links {
			names = append(names, l.Name)
		}
		releases = append(releases, releaseInfo{TagName: r.TagName, ReleasedAt: r.ReleasedAt, AssetNames: names})
		assetsByTag[r.TagName] = names
	}

	// scope.ReleaseTagPattern is trusted as given, not re-defaulted here —
	// the orchestrator (cmd/attestward/scanconfig.go) already applies the
	// product default ("v*") before Collect is ever called, matching every
	// other collector's identical convention (see collect.Scope's own doc
	// comment: collectors treat the values given as the values to use).
	filtered := filterReleasesInLookback(releases, scope.ReleaseTagPattern, scope.LookbackReleases, scope.LookbackMonths, time.Now().UTC())

	out := []model.CheckResult{
		notCheckableAlways(idCommitLinkage, org, repo),
		notCheckableAlways(idWorkflow, org, repo),
		checkChecksums(org, repo, filtered, prov),
		checkSignatures(org, repo, filtered, prov),
		checkTagsSigned(ctx, client, org, repo, filtered),
	}
	return out
}

func notCheckableAlways(id, org, repo string) model.CheckResult {
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: releaseEngineGapReason,
		Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: []model.Provenance{},
	}
}

func allNotCheckable(org, repo, reason string, prov []model.Provenance) []model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	out := make([]model.CheckResult, 0, 5)
	out = append(out, notCheckableAlways(idCommitLinkage, org, repo), notCheckableAlways(idWorkflow, org, repo))
	for _, id := range []string{idChecksums, idSignatures, idTagsSigned} {
		out = append(out, model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: reason,
			Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		})
	}
	return out
}

func projectID(org, repo string) string {
	return escapePath(org) + "%2F" + escapePath(repo)
}

func escapePath(s string) string {
	out := make([]byte, 0, len(s)+8)
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			out = append(out, '%', '2', 'F')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}
