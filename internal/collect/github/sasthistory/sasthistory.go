package sasthistory

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/mapping"
	"github.com/sioakim/ssdf/internal/model"
	"github.com/sioakim/ssdf/mappings"
)

const collectorID = "C05.sast-history"

var checkTitles = map[string]string{
	"C05.sast.tool-configured": "A SAST tool is configured",
	"C05.sast.ran-per-release": "A SAST tool ran for each release in the lookback window",
	"C05.sast.cadence":         "SAST run cadence over the lookback window",
	"C05.sast.default-setup":   "CodeQL default setup is configured",
}

var checkIDs = []string{
	"C05.sast.tool-configured",
	"C05.sast.ran-per-release",
	"C05.sast.cadence",
	"C05.sast.default-setup",
}

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:         id,
			Title:      checkTitles[id],
			Collector:  collectorID,
			TokenScope: "repo (classic) or Actions: read-only + Contents: read-only (fine-grained) — plus whatever fine-grained category gates the code-scanning default-setup endpoint specifically, not independently verified against GitHub's docs (see C04's TokenScope for the same kind of hedge, and why)",
		})
	}
}

// Collector implements C05 sast-history.
type Collector struct {
	token string

	// newClientForTest overrides how each repo's Client is constructed —
	// see repoprotection.Collector's identical field for why.
	newClientForTest func(token string) *ghcollect.Client
}

// New returns a C05 collector authenticated with token. Like
// repoprotection/envseparation/secretshygiene, per-repo checks fan out via
// ForEachRepo's concurrent worker pool, so each repo constructs its own
// Client.
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
		// The registry is this binary's own embedded data — a load
		// failure here means the binary itself is broken, not that this
		// scan's target has a problem. There is no meaningful per-repo
		// not-checkable reason for that; every check for every repo
		// becomes not-checkable with the same underlying cause.
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

// collectRepo resolves SAST tool-configuration and run-history evidence
// for one repo and emits all four CheckResults. It never returns an
// error; every failure becomes a not-checkable result for the affected
// check(s).
//
// The CodeQL default-setup call runs LAST, after every other call
// (repo fetch, workflow listing+content+matching, release listing+tag
// resolution, run-history fetching) — deliberately, so provenance splits
// into a simple prefix (everything else, shared by tool-configured/
// ran-per-release/cadence, which all draw on that combined evidence) and
// suffix (just the one default-setup call, its own dedicated check) via
// plain slicing, without needing to exclude a middle range.
func collectRepo(ctx context.Context, client *ghcollect.Client, registry *mapping.ScannerSignatureRegistry, org, repo string, scope collect.Scope) []model.CheckResult {
	repository, resp, err := client.REST.Repositories.Get(ctx, org, repo)
	if err != nil {
		return allNotCheckable(org, repo, notCheckableReason(resp, err, org, repo), client.Provenance())
	}
	defaultBranch := repository.GetDefaultBranch()

	matchedWorkflows, wfResp, err := fetchAndMatchWorkflows(ctx, client, registry, org, repo, defaultBranch)
	if err != nil {
		return allNotCheckable(org, repo, notCheckableReason(wfResp, err, org, repo), client.Provenance())
	}

	now := time.Now().UTC()
	windowStart := now.AddDate(0, -scope.LookbackMonths, 0)

	rawReleases, relResp, err := fetchReleases(ctx, client, org, repo)
	if err != nil {
		return allNotCheckable(org, repo, notCheckableReason(relResp, err, org, repo), client.Provenance())
	}
	// The tag-pattern filter runs here, before resolution, so an
	// unresolvable tag only counts as a "drop" (below) when it's plausibly
	// in scope for this check at all — an unrelated tag that doesn't even
	// match the release pattern was never going to be evaluated, resolved
	// or not. droppedTags additionally checks PublishedAt against
	// windowStart (the same months cutoff filterReleasesInLookback applies)
	// before counting a drop — that timestamp comes straight off the
	// Releases API response and is known before resolution even starts, so
	// unlike the count-based bound (which genuinely depends on sort order
	// among the releases that DID resolve, unknowable in advance) there's
	// no excuse to skip it: without this check, a years-old release whose
	// tag was later deleted, or a draft release (PublishedAt unset, so
	// always "too old" here), would cap ran-per-release at partial
	// permanently — fixable only by deleting the offending GitHub release.
	tagPattern := scope.ReleaseTagPattern
	var releases []releaseInfo
	droppedTags := 0
	for _, r := range rawReleases {
		tagName := r.GetTagName()
		if ok, err := filepath.Match(tagPattern, tagName); err != nil || !ok {
			continue // out of scope regardless of resolution outcome — not a drop
		}
		publishedAt := r.GetPublishedAt().Time
		sha, err := resolveReleaseCommit(ctx, client, org, repo, tagName)
		if err != nil {
			// An individual unresolvable tag doesn't invalidate the rest,
			// but silently vanishing it would let ran-per-release ignore a
			// release that might genuinely lack SAST coverage — so a drop
			// still within the lookback window is counted and surfaced
			// (see checkRanPerRelease) rather than treated as if the
			// release never existed.
			if !publishedAt.Before(windowStart) {
				droppedTags++
			}
			continue
		}
		releases = append(releases, releaseInfo{
			TagName:     tagName,
			CommitSHA:   sha,
			PublishedAt: publishedAt,
		})
	}
	filteredReleases := filterReleasesInLookback(releases, tagPattern, scope.LookbackReleases, scope.LookbackMonths, now)

	var runs []runInfo
	for _, mw := range matchedWorkflows {
		wfRuns, err := fetchWorkflowRuns(ctx, client, org, repo, mw.WorkflowID, windowStart)
		if err != nil {
			continue // an individual workflow's run history failing to fetch doesn't invalidate the rest
		}
		for _, r := range wfRuns {
			runs = append(runs, runInfo{
				HeadSHA:    r.GetHeadSHA(),
				HeadBranch: r.GetHeadBranch(),
				Conclusion: r.GetConclusion(),
				CreatedAt:  r.GetCreatedAt().Time,
			})
		}
	}

	coverage := linkRunsToReleases(filteredReleases, runs, defaultBranch)
	cadence := computeCadence(runs, windowStart, now)

	sharedProv := client.Provenance() // everything up to (not including) the default-setup call below
	sharedSkip := len(sharedProv)

	defaultSetup, dsResp, dsErr := client.REST.CodeScanning.GetDefaultSetupConfiguration(ctx, org, repo)
	dsProv := tailProvenance(client.Provenance(), sharedSkip)

	return []model.CheckResult{
		checkToolConfigured(org, repo, matchedWorkflows, defaultSetup, sharedProv),
		checkRanPerRelease(org, repo, filteredReleases, coverage, droppedTags, sharedProv),
		checkCadence(org, repo, matchedWorkflows, defaultSetup, cadence, sharedProv),
		checkDefaultSetup(org, repo, defaultSetup, dsResp, dsErr, dsProv),
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
