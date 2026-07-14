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

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/collect/github/repoprotection"
	"github.com/sioakim/ssdf/internal/collect/github/runhistory"
	"github.com/sioakim/ssdf/internal/mapping"
	"github.com/sioakim/ssdf/internal/model"
	"github.com/sioakim/ssdf/mappings"
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

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:          id,
			Title:       checkTitles[id],
			Collector:   collectorID,
			TokenScope:  "repo (classic) or Actions: read-only + Contents: read-only (fine-grained), plus Administration: read-only (shared with C02, for the dependency-review required-status-check cross-check) and whatever fine-grained category gates Dependabot alerts specifically — not independently verified against GitHub's docs, same kind of hedge as C05's TokenScope",
			Remediation: checkRemediations[id],
		})
	}
}

// Collector implements C06 sca-history.
type Collector struct {
	token string

	// newClientForTest overrides how each repo's Client is constructed —
	// see sasthistory.Collector's identical field for why.
	newClientForTest func(token string) *ghcollect.Client
}

// New returns a C06 collector authenticated with token. Per-repo checks
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
		return allNotCheckable(org, repo, notCheckableReason(resp, err, org, repo), client.Provenance())
	}
	defaultBranch := repository.GetDefaultBranch()

	allWorkflows, wfResp, err := runhistory.ListWorkflows(ctx, client, org, repo)
	if err != nil {
		return allNotCheckable(org, repo, notCheckableReason(wfResp, err, org, repo), client.Provenance())
	}
	workflowMatches := runhistory.MatchWorkflows(ctx, client, registry, org, repo, defaultBranch, allWorkflows, mapping.CategorySCA)
	workflowMatchProv := snapshot()

	now := time.Now().UTC()
	windowStart := now.AddDate(0, -scope.LookbackMonths, 0)
	tagPattern := scope.ReleaseTagPattern

	var filteredReleases []runhistory.ReleaseInfo
	var coverage []runhistory.ReleaseCoverage
	droppedTags := 0
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

	cfg, configExists, _, _ := fetchDependabotConfig(ctx, client, org, repo, defaultBranch)
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

	summary := summarizeAlerts(alerts, now)

	return []model.CheckResult{
		checkToolConfigured(org, repo, workflowMatches, dependabotConfigured, toolConfiguredProv),
		checkRanPerRelease(org, repo, filteredReleases, coverage, droppedTags, dependabotOnly, relResp, relErr, ranPerReleaseProv),
		checkDependabotConfig(org, repo, cfg, configExists, detectedEcosystems, rootResp, rootErr, dependabotConfigProv),
		checkDependencyReview(org, repo, depReviewFound, depReviewWorkflow, depReviewFetchErr, statusCheckNames, statusErr, dependencyReviewProv),
		checkAlertsTriaged(org, repo, alertsResp, alertsErr, summary, alertsProv),
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
