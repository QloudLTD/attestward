// Package sasthistory implements C05 sast-history for GitLab — the GitLab
// counterpart of internal/collect/github/sasthistory, under the same four
// check IDs (collect.Register panics on a Collector-string mismatch across
// platforms, so collectorID below matches every twin's "C05.sast-history"
// exactly).
//
// Three of the four are real. What they read, and why:
//
//   - sast.tool-configured and sast.cadence and sast.ran-per-release are
//     built on internal/collect/gitlab/cihistory, which detects a scanner by
//     the `artifacts: reports: sast:` declaration GitLab itself uses to
//     ingest a report, backed by the cross-platform scanner-signature
//     registry for tools that emit no GitLab report. See that package's doc
//     comment for the full detection model.
//   - sast.default-setup is always not-checkable, for a platform-gap reason
//     rather than a tier one. See below.
//
// # This package reads no Ultimate-tier endpoint at all, deliberately
//
// docs/gitlab-security-apis.md §1 is the reason. GitLab's REST security
// endpoints 403 on a Free project — loudly, which is safe — while GraphQL
// answers the same questions with empty collections and no error at all, a
// response structurally identical to "entitled, fully scanned, clean". A
// collector that read `securityScanners.enabled` to answer "is SAST
// configured" would report every Free project as having no scanner, and one
// that read `Pipeline.securityReportSummary` for cadence would report every
// Free project as never having scanned — both silently, both wrong.
//
// Every endpoint this package touches (GET /projects/:id/ci/lint,
// /releases, /jobs) is Free tier and answers identically on both. There is
// therefore no entitlement branch here at all, which is the strongest
// possible form of getting §1 right: the trap is not navigated, it is
// avoided. C06's alerts-triaged and manifest-coverage checks DO need
// Ultimate data, and they take the REST-403 route for exactly the reason
// stated above — see internal/collect/gitlab/scahistory.
//
// ⚠ One consequence worth stating plainly: because the evidence is the CI
// configuration and the job history rather than GitLab's vulnerability
// record, these checks report whether SAST RAN, never what it found. A
// project can pass all three with a scanner that reports critical findings
// on every commit. That is the same scope its GitHub and Azure DevOps twins
// have, and C05 is a history check by design.
//
// # Why sast.default-setup stays not-checkable
//
// Its GitHub twin names one specific product mechanism — CodeQL default
// setup, a repository toggle that makes GitHub run ITS OWN analyzer with no
// workflow file — and GitLab has no equivalent to report on. The nearest
// two mechanisms both answer a different question:
//
//   - Auto DevOps enables SAST as a side effect of adopting a whole
//     build/test/deploy pipeline, and GitLab does not present it as the
//     recommended way to configure scanning. Reporting its absence as a
//     finding would fail almost every well-configured project.
//   - Scan execution policies (Ultimate) enforce scanners from a group-level
//     security policy project. That is genuinely closer, but it is a group
//     governance control rather than a per-project setup mode, and it lives
//     in a separate policy project this build does not read.
//
// So this check keeps its ID and reports not-checkable with a reason naming
// that specific gap, rather than being mapped onto a mechanism whose absence
// means nothing — the same judgment internal/collect/gitlab/vdp made for
// private-reporting and internal/collect/gitlab/envseparation made for
// branch-policy.
//
// # Verified live
//
// Every response shape relied on here was exercised against gitlab.com on
// 2026-08-13 and recorded under internal/collect/gitlab/gitlabfixture/testdata:
//
//   - GET /projects/:id/ci/lint against a project running the stock SAST,
//     Dependency Scanning and Secret Detection templates
//     (ci-lint-security-templates.json). This is what established that the
//     template ships thirteen entries declaring a SAST report that can never
//     run, out of twenty-one that declare one at all.
//   - GET /projects/:id/jobs (jobs-security-pipelines.json): newest-first,
//     with name/status/finished_at, the pipeline's commit SHA, and the
//     artifact file_types the job published.
//   - GET /projects/:id/releases: the release payload carries a full
//     `commit` object, so a tag needs no second call to resolve to a SHA —
//     unlike GitHub, where the twin walks git/ref then git/tags.
package sasthistory

import (
	"context"
	"fmt"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/collect/gitlab/cihistory"
	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/internal/model"
	"gitlab.com/sioakeim/attestward/mappings"
)

const platform = "gitlab"

// collectorID must equal every twin's Collector string exactly.
const collectorID = "C05.sast-history"

const (
	idToolConfigured = "C05.sast.tool-configured"
	idRanPerRelease  = "C05.sast.ran-per-release"
	idCadence        = "C05.sast.cadence"
	idDefaultSetup   = "C05.sast.default-setup"
)

var checkIDs = []string{idToolConfigured, idRanPerRelease, idCadence, idDefaultSetup}

// checkTitles are GitLab's vocabulary. Only default-setup's differs
// materially from its twin's, and it has to: the twin's title is "CodeQL
// default setup is configured", which names a GitHub product feature that
// does not exist here — carrying it over would be wrong regardless of what
// the check reports, the correction internal/collect/gitlab/vdp and
// .../actionssecurity both had to make.
var checkTitles = map[string]string{
	idToolConfigured: "A SAST scanner is configured in the project's CI configuration",
	idRanPerRelease:  "A SAST scanner ran for each release in the lookback window",
	idCadence:        "SAST run cadence over the lookback window",
	idDefaultSetup:   "SAST is enabled by a project-level setting rather than CI configuration",
}

const defaultSetupGapReason = "GitLab has no equivalent of a repository-level toggle that makes the platform " +
	"run its own SAST analyzer with no CI configuration. Its two nearest mechanisms answer different " +
	"questions: Auto DevOps enables SAST only as a side effect of adopting an entire build/deploy pipeline " +
	"template, so its absence is not a finding for a project that configures SAST explicitly (the ordinary, " +
	"GitLab-recommended way); and scan execution policies, which do enforce scanners without a project's own " +
	"CI configuration, are an Ultimate group-governance control living in a separate security policy project " +
	"this build does not read. Whether SAST is configured at all is reported by C05.sast.tool-configured"

var checkTokenScopes = map[string]string{
	idToolConfigured: "read_api, and less — GET /projects/{id}/ci/lint answered 200 with no token at all " +
		"against a public project in this build's own live verification of C08. A private project needs " +
		"enough access to read it; the exact minimum role was not independently established",
	idRanPerRelease: "read_api (Reporter or above on the project) — GET /projects/{id}/releases and GET " +
		"/projects/{id}/jobs. ⚠ GitLab lets a project restrict pipeline visibility, in which case the jobs " +
		"listing needs at least the Reporter role even on a public project",
	idCadence: "read_api (Reporter or above on the project) — the same two endpoints as " +
		"C05.sast.ran-per-release, minus the releases listing",
	idDefaultSetup: "none — this check makes no API call of its own; see the package doc comment",
}

var checkRemediations = map[string]string{
	idToolConfigured: "Add GitLab's SAST template to .gitlab-ci.yml (`include: template: " +
		"Jobs/SAST.gitlab-ci.yml`), or add a job that emits a GitLab SAST report (`artifacts: reports: sast:`) " +
		"— that declaration is what this check reads, and it is what GitLab itself reads to ingest findings. " +
		"A third-party scanner invoked from a job's script is also recognized when its CLI matches a signature " +
		"in mappings/scanner-signatures.yaml, but at lower confidence: a job whose NAME merely suggests SAST " +
		"is never enough on its own. Note that a job disabled with an unconditional `rules: - when: never` " +
		"does not count — GitLab's own template ships several of those.",
	idRanPerRelease: "Make sure the SAST job's `rules:` actually fire on the commit each release is cut from " +
		"— a job gated on merge-request pipelines alone never runs on the tagged commit — and that any job " +
		"that did fire finished successfully rather than erroring out. Note the join is on the release's " +
		"COMMIT: a scan of a later commit on the same branch does not evidence that the released code was " +
		"scanned.",
	idCadence: "If zero SAST runs were observed in the lookback window, same fix as C05.sast.ran-per-release: " +
		"confirm the job's `rules:` let it run on ordinary pushes to the default branch or on a schedule, not " +
		"only on a rare manual trigger. If runs WERE observed but this still reads partial, the tool was only " +
		"identified by a job name — same fix as C05.sast.tool-configured: emit a GitLab SAST report, or " +
		"invoke a recognized scanner CLI.",
	idDefaultSetup: "Nothing to remediate: this check reports a mechanism GitLab does not have. Configure " +
		"SAST in CI instead — see C05.sast.tool-configured's remediation.",
}

// sharedCIConfigNotCheckableRubric is shared by all three real checks: they
// are all computed from the same lint response, so a configuration GitLab
// could not resolve reaches all three identically. Kept in sync with
// ciConfigUnavailableReason.
const sharedCIConfigNotCheckableRubric = "GET /projects/{id}/ci/lint failed outright, or returned a merged " +
	"configuration that was empty or did not parse as YAML — the errors GitLab reported are quoted in the " +
	"reason rather than guessed between, since the lint API answers 200 with valid=false both for a project " +
	"with no CI configuration at all and for one whose configuration exists but has an unresolvable include"

// jobWalkTruncatedRubric describes the bound on the job history read. It is
// stated per check rather than shared wholesale because the two checks treat
// it differently, and that asymmetry is the point — see checkRanPerRelease.
const jobWalkTruncatedRubric = "the job-history walk hit its page bound before reaching the far side of the " +
	"lookback window (a project with more than 2,000 finished jobs in the window), so the run pool is " +
	"incomplete"

var checkRubrics = map[string]map[model.Status]string{
	idToolConfigured: {
		model.StatusVerifiedPass: "at least one job in the merged CI configuration that GitLab can actually " +
			"run reaches medium-or-high confidence — high when the job declares `artifacts: reports: sast:` " +
			"(GitLab's own contract for ingesting a SAST report), medium when its script matches a scanner " +
			"CLI pattern from mappings/scanner-signatures.yaml. Hidden jobs (a leading `.`) and jobs disabled " +
			"with an unconditional `rules: - when: never` are excluded from the judgment entirely: neither is " +
			"ever added to a pipeline, and GitLab's own SAST template ships thirteen of them — measured, out " +
			"of twenty-one entries that declare a SAST report",
		model.StatusPartial: "the only evidence is a job NAME matching a scanner-signature name pattern — a " +
			"naming convention, not a tool invocation. Not enough on its own to confirm a SAST scanner is " +
			"genuinely configured",
		model.StatusVerifiedFail: "the merged CI configuration resolved cleanly and no runnable job in it " +
			"emits a SAST report, invokes a recognized scanner CLI, or is even named like one — a real " +
			"absence, not an evidence gap",
		model.StatusNotCheckable: sharedCIConfigNotCheckableRubric,
	},
	idRanPerRelease: {
		model.StatusVerifiedPass: "every release in the lookback window has at least one matched SAST job " +
			"that finished successfully on that release's own commit",
		model.StatusPartial: "every release in the lookback window has at least one matched SAST job on its " +
			"commit, but for one or more of them none of those jobs succeeded — the scanner ran and did not " +
			"complete, which is neither a clean pass nor the total absence a fail asserts",
		model.StatusVerifiedFail: "at least one release in the lookback window has no matched SAST job on its " +
			"commit at all, not even a failed one — including the case where no SAST scanner is configured, " +
			"which means nothing scanned any released commit",
		model.StatusNotCheckable: sharedCIConfigNotCheckableRubric + "; or the releases listing or the job " +
			"listing could not be read; or no release matches the configured tag pattern within the lookback " +
			"window, so there is nothing to evaluate; or " + jobWalkTruncatedRubric + " AND at least one " +
			"release reads as having no matched run — a truncated pool cannot certify that specific absence. " +
			"A truncated pool whose coverage already reads ran/failed for every release is NOT reported here: " +
			"coverage only ever improves as more runs are added, so it cannot have been overstated by runs " +
			"this build did not fetch (the same monotonicity narrowing the GitHub twin applies, issue #291)",
	},
	idCadence: {
		model.StatusVerifiedPass: "at least one matched SAST job finished inside the lookback window, and " +
			"the scanner was identified at medium-or-high confidence rather than by job name alone",
		model.StatusPartial: "matched jobs did run inside the window, but the only thing identifying them as " +
			"a SAST scanner was a job name matching a signature's name pattern — not enough to call the " +
			"cadence genuine SAST activity",
		model.StatusVerifiedFail: "a SAST scanner is configured and not one matched job finished inside the " +
			"lookback window",
		model.StatusNotCheckable: sharedCIConfigNotCheckableRubric + "; or the job listing could not be read; " +
			"or no SAST scanner is configured at all, so there is no cadence to compute (C05.sast.tool-" +
			"configured reports that absence); or " + jobWalkTruncatedRubric + " — unlike per-release " +
			"coverage, run counts and gap lengths are not monotone in the run pool (a missing run can " +
			"understate a count or overstate a gap), so any truncation taints this check",
	},
	idDefaultSetup: {
		model.StatusNotCheckable: defaultSetupGapReason,
	},
}

const (
	lintEndpoint     = "GET /projects/{id}/ci/lint"
	releasesEndpoint = "GET /projects/{id}/releases"
	jobsEndpoint     = "GET /projects/{id}/jobs"
)

var checkEndpoints = map[string][]string{
	idToolConfigured: {lintEndpoint},
	idRanPerRelease:  {lintEndpoint, releasesEndpoint, jobsEndpoint},
	idCadence:        {lintEndpoint, jobsEndpoint},
	// No endpoint backs this: it makes no call. collect.CheckMeta.Endpoints
	// documents what a check's own result depends on, and an entry here would
	// claim this build asked a question it never asks.
	idDefaultSetup: nil,
}

const fixtureRef = "internal/collect/gitlab/sasthistory/sasthistory_test.go"

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID: id, Platform: platform, Title: checkTitles[id], Collector: collectorID,
			TokenScope:  checkTokenScopes[id],
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			FixtureRef:  fixtureRef,
		})
	}
}

// Collector implements C05 sast-history for GitLab.
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

// Collect emits all four checks once per project in scope.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	registry, err := mapping.LoadScannerSignaturesFS(mappings.FS, "scanner-signatures.yaml")
	if err != nil {
		// The registry is this binary's own embedded data, so a load failure
		// means the binary is broken rather than the scanned project. Every
		// check for every project becomes not-checkable with that one cause.
		var all []model.CheckResult
		for _, repo := range scope.Repos {
			all = append(all, allNotCheckable(scope.Org, repo,
				fmt.Sprintf("could not load the embedded scanner-signature registry: %v", err), nil)...)
		}
		return all, nil
	}

	var out []model.CheckResult
	for _, repo := range scope.Repos {
		out = append(out, c.collectRepo(ctx, scope, repo, registry)...)
	}
	return out, nil
}

// collectRepo gathers one project's evidence and hands each check only the
// provenance of the calls its own Status depends on.
//
// A client is built fresh per repo, not once for the whole scope, avoiding
// the cross-repo Provenance() bleed a shared client produces (issue #14) —
// the same convention every other gitlab collector uses.
func (c *Collector) collectRepo(ctx context.Context, scope collect.Scope, repo string, registry *mapping.ScannerSignatureRegistry) []model.CheckResult {
	org := scope.Org

	client, err := c.newClient()
	if err != nil {
		return allNotCheckable(org, repo, fmt.Sprintf("could not build a GitLab client: %v", err), nil)
	}

	// segment returns the provenance recorded since the previous call to it,
	// so a check lists the calls behind its own Status and no others. prevLen
	// starts at 0 because the client is fresh here.
	prevLen := 0
	segment := func() []model.Provenance {
		all := client.Provenance()
		seg := append([]model.Provenance{}, all[prevLen:]...)
		prevLen = len(all)
		return seg
	}

	ev := gatherEvidence(ctx, client, projectID(org, repo), scope, registry,
		cihistory.ReportTypeSAST, mapping.CategorySAST, segment)

	return []model.CheckResult{
		checkToolConfigured(org, repo, ev),
		checkRanPerRelease(org, repo, ev),
		checkCadence(org, repo, ev),
		notCheckableAlways(idDefaultSetup, org, repo),
	}
}

func notCheckableAlways(id, org, repo string) model.CheckResult {
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: defaultSetupGapReason,
		Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: []model.Provenance{},
	}
}

func allNotCheckable(org, repo, reason string, prov []model.Provenance) []model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	out := make([]model.CheckResult, 0, len(checkIDs))
	for _, id := range checkIDs {
		if id == idDefaultSetup {
			// Its reason is a platform fact, not this scan's failure — an
			// unreadable project does not change why GitLab has no such
			// mechanism.
			out = append(out, notCheckableAlways(id, org, repo))
			continue
		}
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
