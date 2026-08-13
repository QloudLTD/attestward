// Package scahistory implements C06 sca-history for GitLab — the GitLab
// counterpart of internal/collect/github/scahistory, under the same five
// check IDs (collect.Register panics on a Collector-string mismatch across
// platforms, so collectorID below matches every twin's "C06.sca-history"
// exactly).
//
// Four of the five are real. Two of those four read Ultimate-tier data, and
// how they handle NOT being entitled is the most important thing in this
// package.
//
// # The entitlement rule, and why it is REST-only
//
// docs/gitlab-security-apis.md §1, measured at both tiers on 2026-08-13:
//
//	GET /projects/:id/dependencies    Free -> 403      Ultimate -> 200 [...]
//	GET /projects/:id/vulnerabilities Free -> 403      Ultimate -> 200 [...]
//	GraphQL securityScanners          Free -> {"enabled":[],"available":[],...}
//	                                  with NO errors key at all
//
// REST fails loudly; GraphQL fails SILENTLY, returning empty collections
// structurally identical to "entitled, fully scanned, and clean". A
// GraphQL-backed version of C06.sca.alerts-triaged would have reported every
// Free project as having zero open vulnerabilities — a verified-pass minted
// out of an entitlement the project never had, in a signed attestation.
//
// So both Ultimate-gated checks here read REST and translate its 403 into
// not-checkable, never into a pass and never into a fail — the discipline
// internal/collect/gitlab/client.go's ErrTierGated exists to enforce. This
// package makes no GraphQL call at all.
//
// ⚠ A 403 does not distinguish "this tier does not include the feature" from
// "this token lacks the role". Both are honestly not-checkable and the reason
// says so rather than picking one — the same treatment
// internal/collect/gitlab/actionssecurity gives its own Maintainer-gated
// endpoints.
//
// # What each check became
//
// sca.tool-configured and sca.ran-per-release are the direct GitLab forms of
// their twins, built on internal/collect/gitlab/cihistory, and are FREE tier:
// they read the merged CI configuration and the job history, not GitLab's
// vulnerability record. See that package's doc comment for the detection
// model. A project on any tier gets a real answer.
//
// sca.alerts-triaged keeps its twin's question — are open dependency
// vulnerabilities being triaged — asked of GitLab's own vulnerability
// record. GET /projects/:id/vulnerabilities carries a state per finding, and
// internal/collect/gitlab.IsOpenVulnerability is where this codebase already
// decided which states count as open (dismissed and resolved do not;
// confirmed does). The 30-day critical window is the twin's, unchanged, so
// the two platforms answer the same question the same way.
//
// sca.dependabot-config keeps its ID but not its mechanism, because GitLab
// has no `.github/dependabot.yml`: Dependency Scanning detects supported
// lockfiles automatically and there is no per-ecosystem declaration for a
// producer to keep in sync. What IS worth checking, and is the same
// underlying question, is whether the scanner's actual coverage matches the
// project's actual manifests — so this check compares the dependency files
// GitLab reported scanning against the manifests present in the repository.
//
// ⚠ It compares FILE PATHS, not ecosystem names. GET /projects/:id/dependencies
// returns a dependency_file_path per dependency ("package-lock.json",
// verified live), and the repository tree returns paths; matching those
// directly needs no lockfile→package-manager table, so there is no invented
// mapping to be wrong about. The manifest filenames it looks for are
// transcribed from GitLab's OWN Dependency Scanning template — see
// cihistory's dependencyManifestNames.
//
// ⚠ It has no verified-fail outcome, by design. A `pom.xml` under a
// test-fixture directory, or a lockfile in a path the analyzer was configured
// to exclude, is an uncovered manifest that is not a finding — so an
// uncovered manifest caps the result at partial and names the file, leaving
// the judgment to a reader who knows the repository. The same capping
// internal/collect/gitlab/actionssecurity applies to its two fork-exposure
// checks.
//
// sca.dependency-review is always not-checkable, for a platform-gap reason
// rather than a tier one. GitLab has no equivalent of a per-pull-request
// dependency diff enforced as a required status check: it has no required-
// status-check model at all (a merge request is gated by approval rules and
// by whether the pipeline succeeded), and its scanners do not fail a job on
// findings — they publish a report. The mechanism that DOES gate a merge
// request on scan findings is an Ultimate merge request approval policy,
// which lives in a separate security policy project this build does not
// read. That is a genuine remaining scope gap rather than a mapping, so the
// reason names it and the check reports nothing.
//
// # Verified live
//
// Every response shape relied on here was exercised against gitlab.com and
// recorded under internal/collect/gitlab/gitlabfixture/testdata:
//
//   - dependencies.json and vulnerabilities-all-states.json (2026-08-10), and
//     403-not-entitled.json — the tier-gated branch that must never become a
//     fail.
//   - ci-lint-security-templates.json and jobs-security-pipelines.json
//     (2026-08-13), shared with C05.
//   - repository-tree.json (2026-08-13), and the live cross-check behind this
//     package's central claim: that project's tree holds package-lock.json
//     and go.mod, and /dependencies reported dependencies from
//     package-lock.json only — go.mod is correctly NOT flagged, because
//     GitLab's own rule scans go.sum rather than go.mod.
package scahistory

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
const collectorID = "C06.sca-history"

const (
	idToolConfigured   = "C06.sca.tool-configured"
	idRanPerRelease    = "C06.sca.ran-per-release"
	idManifestCoverage = "C06.sca.dependabot-config"
	idDependencyReview = "C06.sca.dependency-review"
	idAlertsTriaged    = "C06.sca.alerts-triaged"
)

var checkIDs = []string{idToolConfigured, idRanPerRelease, idManifestCoverage, idDependencyReview, idAlertsTriaged}

// checkTitles are GitLab's vocabulary. Three of the five differ materially
// from their twins' because those name GitHub products — "Dependabot config
// covers the repo's detected dependency ecosystems", "Open Dependabot alerts
// are triaged within the default window", "Dependency review is enforced as
// a required check on pull requests" — and Dependabot, dependency review and
// required status checks are all mechanisms GitLab does not have.
var checkTitles = map[string]string{
	idToolConfigured:   "A dependency-scanning tool is configured in the project's CI configuration",
	idRanPerRelease:    "A dependency-scanning tool ran for each release in the lookback window",
	idManifestCoverage: "Dependency Scanning covers the project's dependency manifests",
	idDependencyReview: "Dependency findings gate merge requests",
	idAlertsTriaged:    "Open dependency vulnerabilities are triaged within the default window",
}

const dependencyReviewGapReason = "GitLab has no per-merge-request dependency diff and no required-status-" +
	"check model to enforce one with: a merge request is gated by approval rules and by whether its pipeline " +
	"succeeded, and GitLab's dependency scanner does not fail a job on findings — it publishes a report. The " +
	"one mechanism that does gate a merge request on scan findings is an Ultimate merge request approval " +
	"policy, which is defined in a separate security policy project that this build does not read; that is a " +
	"remaining scope gap rather than something GitLab lacks. Whether the scanner runs at all is reported by " +
	"C06.sca.tool-configured and C06.sca.ran-per-release"

// tierGatedNotCheckableRubric is shared by the two checks that need Ultimate
// data. It states the §1 finding in the place a reader of `checks docs`
// actually meets it.
const tierGatedNotCheckableRubric = "the endpoint answered 403. GitLab returns 403 both for a Dependency " +
	"Scanning feature a Free project is not entitled to and for a token without the role, and this build does " +
	"not claim to tell those apart — either way an empty answer would not have meant \"clean\", so nothing is " +
	"reported. ⚠ This is why the evidence is REST rather than GraphQL: measured at both tiers, GraphQL " +
	"answers the same question on an unentitled project with empty collections and no error at all, which is " +
	"indistinguishable from an entitled, fully scanned, clean project — see docs/gitlab-security-apis.md §1"

var checkTokenScopes = map[string]string{
	idToolConfigured: "read_api, and less — GET /projects/{id}/ci/lint answered 200 with no token at all " +
		"against a public project in this build's own live verification of C08",
	idRanPerRelease: "read_api (Reporter or above on the project) — GET /projects/{id}/releases and GET " +
		"/projects/{id}/jobs",
	idManifestCoverage: "read_api (Reporter or above), PLUS a GitLab Ultimate subscription: GET " +
		"/projects/{id}/dependencies answers 403 without one. The repository tree listing it is compared " +
		"against needs no paid tier",
	idDependencyReview: "none — this check makes no API call of its own; see the package doc comment",
	idAlertsTriaged: "read_api (Reporter or above), PLUS a GitLab Ultimate subscription: GET " +
		"/projects/{id}/vulnerabilities answers 403 without one",
}

var checkRemediations = map[string]string{
	idToolConfigured: "Add GitLab's Dependency Scanning template to .gitlab-ci.yml (`include: template: " +
		"Jobs/Dependency-Scanning.gitlab-ci.yml`), or add a job that emits a GitLab dependency-scanning " +
		"report (`artifacts: reports: dependency_scanning:`) — that declaration is what this check reads, and " +
		"it is what GitLab itself reads to ingest findings. A third-party scanner invoked from a job's script " +
		"is also recognized when its CLI matches a signature in mappings/scanner-signatures.yaml, but at " +
		"lower confidence.",
	idRanPerRelease: "Make sure the dependency-scanning job's `rules:` fire on the commit each release is cut " +
		"from, and that any job that did fire finished successfully. GitLab's own template additionally gates " +
		"its analyzers on a lockfile existing (`exists:`), so a project whose dependencies are declared only " +
		"in a manifest without a committed lockfile will never run one — commit the lockfile.",
	idManifestCoverage: "For each manifest named in this finding's uncovered_manifests fact, work out why " +
		"Dependency Scanning reported nothing from it: the analyzer for that ecosystem may be excluded via " +
		"DS_EXCLUDED_ANALYZERS, the path may be excluded via DS_EXCLUDED_PATHS (which defaults to spec, test, " +
		"tests, tmp and node_modules), or the manifest may need a committed lockfile before the analyzer will " +
		"run. If the manifest is a test fixture or a vendored copy, nothing needs fixing — that is why this " +
		"check never reports a failure.",
	idDependencyReview: "Nothing to remediate: this check reports a mechanism GitLab does not have. To gate " +
		"merge requests on dependency findings, define a merge request approval policy (GitLab Ultimate) " +
		"requiring approval when a scan finds vulnerabilities of the severities you care about.",
	idAlertsTriaged: "Triage the project's Vulnerability Report: fix or dismiss (with a documented reason) " +
		"any critical dependency vulnerability open longer than 30 days. A dismissed finding does not count " +
		"against this check — a recorded triage decision is exactly what it is looking for.",
}

// sharedCIConfigNotCheckableRubric is shared by the two CI-backed checks —
// both are computed from the same lint response.
const sharedCIConfigNotCheckableRubric = "GET /projects/{id}/ci/lint failed outright, or returned a merged " +
	"configuration that was empty or did not parse as YAML — the errors GitLab reported are quoted in the " +
	"reason rather than guessed between, since the lint API answers 200 with valid=false both for a project " +
	"with no CI configuration at all and for one whose configuration exists but has an unresolvable include"

var checkRubrics = map[string]map[model.Status]string{
	idToolConfigured: {
		model.StatusVerifiedPass: "at least one job in the merged CI configuration that GitLab can actually " +
			"run reaches medium-or-high confidence — high when the job declares `artifacts: reports: " +
			"dependency_scanning:` (GitLab's own contract for ingesting a dependency report), medium when its " +
			"script matches a scanner CLI pattern from mappings/scanner-signatures.yaml. Hidden jobs (a " +
			"leading `.`) and jobs disabled with an unconditional `rules: - when: never` are excluded: neither " +
			"is ever added to a pipeline, and GitLab's own template ships both kinds",
		model.StatusPartial: "the only evidence is a job NAME matching a scanner-signature name pattern — a " +
			"naming convention, not a tool invocation",
		model.StatusVerifiedFail: "the merged CI configuration resolved cleanly and no runnable job in it " +
			"emits a dependency-scanning report, invokes a recognized scanner CLI, or is even named like one " +
			"— a real absence, not an evidence gap",
		model.StatusNotCheckable: sharedCIConfigNotCheckableRubric,
	},
	idRanPerRelease: {
		model.StatusVerifiedPass: "every release in the lookback window has at least one matched " +
			"dependency-scanning job that finished successfully on that release's own commit",
		model.StatusPartial: "every release in the lookback window has at least one matched job on its " +
			"commit, but for one or more of them none of those jobs succeeded",
		model.StatusVerifiedFail: "at least one release in the lookback window has no matched " +
			"dependency-scanning job on its commit at all, not even a failed one — including the case where " +
			"no scanner is configured, which means nothing scanned any released commit",
		model.StatusNotCheckable: sharedCIConfigNotCheckableRubric + "; or the releases listing or the job " +
			"listing could not be read; or no release matches the configured tag pattern within the lookback " +
			"window; or the job-history walk hit its page bound AND at least one release reads as having no " +
			"matched run — a truncated pool cannot certify that specific absence, while one whose coverage " +
			"already reads ran/failed for every release is not reported here, since coverage only ever " +
			"improves as more runs are added",
	},
	idManifestCoverage: {
		model.StatusVerifiedPass: "GitLab reported dependencies from every dependency manifest found in the " +
			"repository — matched by file PATH, so no lockfile-to-package-manager mapping is involved. The " +
			"manifest filenames looked for are transcribed from GitLab's own Dependency Scanning template",
		model.StatusPartial: "one or more dependency manifests in the repository are not among the files " +
			"GitLab reported dependencies from. This check has NO verified-fail outcome by design: a manifest " +
			"under a test-fixture directory, a vendored copy, or a path matched by DS_EXCLUDED_PATHS is " +
			"uncovered without that being a finding, and this build cannot tell those from a real gap. The " +
			"offending paths are named in Facts.uncovered_manifests for a reader who knows the repository",
		model.StatusNotCheckable: tierGatedNotCheckableRubric + ". Also: the repository tree could not be " +
			"listed, so which manifests exist is unknown; or the repository contains no dependency manifest " +
			"this build recognizes, so there is no coverage question to answer",
	},
	idDependencyReview: {
		model.StatusNotCheckable: dependencyReviewGapReason,
	},
	idAlertsTriaged: {
		model.StatusVerifiedPass: "the vulnerability listing was read in full, every finding's state was one " +
			"this build recognizes, and no OPEN critical dependency-scanning finding has been open longer " +
			"than the 30-day triage window. Open means state detected or confirmed; a dismissed or resolved " +
			"finding is a triage decision already made and never counts against the project",
		model.StatusVerifiedFail: "at least one open critical dependency-scanning finding has been open " +
			"longer than the 30-day triage window",
		model.StatusPartial: "no critical finding is beyond the window, but at least one finding carried a " +
			"state this build does not recognize — a future GitLab state is not silently bucketed as open or " +
			"closed, so a stale critical finding cannot be ruled out. Facts carry unrecognized_states",
		model.StatusNotCheckable: tierGatedNotCheckableRubric,
	},
}

const (
	lintEndpoint            = "GET /projects/{id}/ci/lint"
	releasesEndpoint        = "GET /projects/{id}/releases"
	jobsEndpoint            = "GET /projects/{id}/jobs"
	dependenciesEndpoint    = "GET /projects/{id}/dependencies"
	treeEndpoint            = "GET /projects/{id}/repository/tree"
	vulnerabilitiesEndpoint = "GET /projects/{id}/vulnerabilities"
)

var checkEndpoints = map[string][]string{
	idToolConfigured:   {lintEndpoint},
	idRanPerRelease:    {lintEndpoint, releasesEndpoint, jobsEndpoint},
	idManifestCoverage: {dependenciesEndpoint, treeEndpoint},
	// No endpoint backs this: it makes no call.
	idDependencyReview: nil,
	idAlertsTriaged:    {vulnerabilitiesEndpoint},
}

const fixtureRef = "internal/collect/gitlab/scahistory/scahistory_test.go"

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

// Collector implements C06 sca-history for GitLab.
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

// Collect emits all five checks once per project in scope.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	registry, err := mapping.LoadScannerSignaturesFS(mappings.FS, "scanner-signatures.yaml")
	if err != nil {
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
// the cross-repo Provenance() bleed a shared client produces (issue #14).
func (c *Collector) collectRepo(ctx context.Context, scope collect.Scope, repo string, registry *mapping.ScannerSignatureRegistry) []model.CheckResult {
	org := scope.Org

	client, err := c.newClient()
	if err != nil {
		return allNotCheckable(org, repo, fmt.Sprintf("could not build a GitLab client: %v", err), nil)
	}

	prevLen := 0
	segment := func() []model.Provenance {
		all := client.Provenance()
		seg := append([]model.Provenance{}, all[prevLen:]...)
		prevLen = len(all)
		return seg
	}

	projID := projectID(org, repo)
	ev := gatherEvidence(ctx, client, projID, scope, registry,
		cihistory.ReportTypeDependencyScanning, mapping.CategorySCA, segment)

	scanned, scannedErr := fetchScannedDependencyFiles(ctx, client, projID)
	manifests, manifestsErr := cihistory.FetchDependencyManifests(ctx, client, projID)
	coverageProv := segment()

	vulns, vulnsErr := fetchVulnerabilities(ctx, client, projID)
	vulnsProv := segment()

	return []model.CheckResult{
		checkToolConfigured(org, repo, ev),
		checkRanPerRelease(org, repo, ev),
		checkManifestCoverage(org, repo, scanned, scannedErr, manifests, manifestsErr, coverageProv),
		notCheckableAlways(idDependencyReview, org, repo),
		checkAlertsTriaged(org, repo, vulns, vulnsErr, ev.Now, vulnsProv),
	}
}

func notCheckableAlways(id, org, repo string) model.CheckResult {
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: dependencyReviewGapReason,
		Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: []model.Provenance{},
	}
}

func allNotCheckable(org, repo, reason string, prov []model.Provenance) []model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	out := make([]model.CheckResult, 0, len(checkIDs))
	for _, id := range checkIDs {
		if id == idDependencyReview {
			// Its reason is a platform fact, not this scan's failure.
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
