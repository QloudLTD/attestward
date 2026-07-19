// Package sasthistory implements C05 sast-history: whether a SAST tool is
// configured (via #16's scanner-signature matcher, or GitHub's separate
// CodeQL "default setup" mechanism) and whether it actually ran for each
// recent release (SSDF PW.7, PW.8, RV.1).
package sasthistory

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	ghgithub "github.com/google/go-github/v75/github"

	"github.com/sioakim/attestward/internal/collect"
	ghcollect "github.com/sioakim/attestward/internal/collect/github"
	"github.com/sioakim/attestward/internal/collect/github/runhistory"
	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/model"
	"github.com/sioakim/attestward/mappings"
)

const collectorID = "C05.sast-history"

// codeQLDefaultSetupPathPrefix is the synthetic workflow path GitHub's API
// reports for a repo's CodeQL "default setup" scanning configuration
// (Settings > Code security > Code scanning > Set up > Default), when it's
// enabled: ListWorkflows includes a virtual entry at this path even though
// no such file exists in the repo. Fetching its content 404s — it isn't a
// real file — so it must be special-cased rather than run through
// runhistory.MatchWorkflows' normal content-fetch-then-match path. This is
// SAST-specific (CodeQL has no SCA equivalent), so it's handled here, not
// in the shared runhistory package.
const codeQLDefaultSetupPathPrefix = "dynamic/github-code-scanning/"

// codeQLSignatureID is the scanner-signatures.yaml entry this collector
// attributes default-setup's synthetic match to, so its tool name in
// checkToolConfigured's Facts matches the name a real codeql-action-based
// workflow would report.
const codeQLSignatureID = "codeql"

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

var checkRemediations = map[string]string{
	"C05.sast.tool-configured": "Enable CodeQL default setup (repo Settings -> Security -> Advanced " +
		"Security -> under Code Security, \"CodeQL analysis\" -> Set up -> Default), or add a workflow " +
		"using a recognized SAST action/CLI (see mappings/scanner-signatures.yaml for what this tool " +
		"recognizes) — a workflow whose name merely suggests SAST isn't enough on its own; it needs a " +
		"matched action/CLI invocation to count as more than a low-confidence signal.",
	"C05.sast.ran-per-release": "Make sure the SAST workflow's trigger actually fires on (or before) the " +
		"commit each release is cut from — e.g. trigger on push to the release branch, or on the release " +
		"event itself — and that any run that did fire completed successfully rather than erroring out.",
	"C05.sast.cadence": "If zero SAST runs were observed in the lookback window, same fix as " +
		"C05.sast.ran-per-release: confirm the workflow runs on a schedule or on every push/PR to the " +
		"default branch, not only on rare manual dispatch. If runs WERE observed but this still reads " +
		"partial, the match itself is low-confidence (workflow-name-only) — same fix as " +
		"C05.sast.tool-configured: use a recognized action/CLI, not just a workflow name that sounds like " +
		"SAST.",
	"C05.sast.default-setup": "Repo Settings -> Security -> Advanced Security -> under Code Security, " +
		"\"CodeQL analysis\" -> Set up -> Default (choose \"Default\", not \"Advanced\", unless a custom " +
		"workflow is specifically needed).",
}

// sharedUpstreamFetchFailureRubric is shared by all four checks:
// collectRepo returns not-checkable for every one of them on the first
// failure among the repo fetch, the workflow listing, or the release
// listing — none of the four checks below can be computed without that
// shared evidence, regardless of whether a given check actually reads
// release data (e.g. default-setup doesn't, but still goes not-checkable
// if FetchReleases fails, since collectRepo never reaches its own call in
// that case). Collect's own embedded-registry-load failure is a distinct,
// binary-level cause that also reaches every check for every repo in
// scope, independent of the target repo's own state.
const sharedUpstreamFetchFailureRubric = "the repo fetch, the workflow listing, or the release listing " +
	"failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on the " +
	"first such failure, since none of them can be computed without this shared evidence; or the embedded " +
	"scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo)"

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce — see checks.go for the pass/fail/partial logic
// each rubric below summarizes.
var checkRubrics = map[string]map[model.Status]string{
	"C05.sast.tool-configured": {
		model.StatusVerifiedPass: "at least one matched workflow reaches medium-or-high confidence (an " +
			"action slug or CLI pattern, not just a suggestive workflow name), or CodeQL default setup's " +
			"state reads \"configured\"",
		model.StatusPartial: "only a low-confidence (workflow-name-only) match was found in any workflow, " +
			"and CodeQL default setup is not confirmed configured — not enough signal alone to confirm a " +
			"SAST tool is genuinely configured",
		model.StatusVerifiedFail: "no workflow match of any confidence was found, and CodeQL default " +
			"setup's state reads anything other than \"configured\" — including a legitimate plan-gated/" +
			"not-found response to the default-setup query itself (a real \"not available\" fact, not an " +
			"unknown)",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or there is no workflow-based " +
			"evidence at all and the CodeQL default-setup query itself failed with something other than a " +
			"plan-gated/not-found response — an unresolved unknown, not a confirmed absence",
	},
	"C05.sast.ran-per-release": {
		model.StatusVerifiedPass: "a SAST tool ran successfully (at least one matched run whose conclusion " +
			"is \"success\") for every release in the lookback window, and every matching release tag " +
			"published in the lookback window resolved to a commit — an unresolvable tag published " +
			"outside the window is out of scope, not a drop, so it doesn't block verified-pass",
		model.StatusPartial: "one or more matching release tags published in the lookback window couldn't " +
			"be resolved to a commit; if that leaves nothing evaluable, the reason names the drop count " +
			"directly, otherwise every evaluated release still succeeded but the exclusion caps the result " +
			"at partial; or a matched SAST tool ran for every evaluated release, but not every run succeeded",
		model.StatusVerifiedFail: "at least one release in the lookback window has zero matched SAST runs " +
			"at all (not even a failed one)",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or no release tag matches the " +
			"configured pattern within the lookback window, and none of the tags that did match were " +
			"dropped as unresolvable either — genuinely nothing to evaluate",
	},
	"C05.sast.cadence": {
		model.StatusVerifiedPass: "one or more SAST runs were observed in the lookback window, backed by " +
			"at least a medium-confidence workflow match or CodeQL default setup (not a low-confidence-" +
			"only match)",
		model.StatusPartial: "one or more runs were observed, but only a low-confidence (workflow-name-" +
			"only) match identified the tool — not enough signal to confirm this cadence reflects genuine " +
			"SAST activity",
		model.StatusVerifiedFail: "a SAST tool is configured (workflow match or CodeQL default setup), but " +
			"zero SAST runs were observed in the lookback window",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or no SAST tool is configured at " +
			"all (no workflow match of any confidence, and CodeQL default setup does not read " +
			"\"configured\") — nothing to compute cadence for",
	},
	"C05.sast.default-setup": {
		model.StatusVerifiedPass: "CodeQL default setup's state reads \"configured\"",
		model.StatusVerifiedFail: "the default-setup query succeeded, but the state reads anything other " +
			"than \"configured\" (e.g. \"not-configured\")",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or the default-setup query itself " +
			"failed (403/plan-gated/other API error)",
	},
}

// sastEvidenceEndpoints are the calls that determine matchedWorkflows —
// which workflows count as SAST-matched, including the CodeQL
// default-setup virtual entry (from ListWorkflows' path-prefix detection,
// independent of the dedicated code-scanning/default-setup endpoint
// below) — shared by every check that consumes that evidence in any way.
var sastEvidenceEndpoints = []string{
	"GET /repos/{owner}/{repo}",
	"GET /repos/{owner}/{repo}/actions/workflows",
	"GET /repos/{owner}/{repo}/contents/{path}",
}

const defaultSetupAPIEndpoint = "GET /repos/{owner}/{repo}/code-scanning/default-setup"
const workflowRunsAPIEndpoint = "GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs"

// checkEndpoints lists which REST endpoint(s) actually back each check's
// status.
var checkEndpoints = map[string][]string{
	"C05.sast.tool-configured": append(append([]string{}, sastEvidenceEndpoints...), defaultSetupAPIEndpoint),
	"C05.sast.ran-per-release": append(append([]string{}, sastEvidenceEndpoints...),
		"GET /repos/{owner}/{repo}/releases",
		"GET /repos/{owner}/{repo}/git/ref/{ref}",
		"GET /repos/{owner}/{repo}/git/tags/{tag_sha}",
		workflowRunsAPIEndpoint,
	),
	"C05.sast.cadence":       append(append([]string{}, sastEvidenceEndpoints...), defaultSetupAPIEndpoint, workflowRunsAPIEndpoint),
	"C05.sast.default-setup": {defaultSetupAPIEndpoint},
}

const fixtureRef = "internal/collect/github/sasthistory/sasthistory_test.go"

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:          id,
			Title:       checkTitles[id],
			Collector:   collectorID,
			TokenScope:  "repo (classic) or Actions: read-only + Contents: read-only (fine-grained) — plus whatever fine-grained category gates the code-scanning default-setup endpoint specifically, not independently verified against GitHub's docs (see C04's TokenScope for the same kind of hedge, and why)",
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			FixtureRef:  fixtureRef,
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

	allWorkflows, wfResp, err := runhistory.ListWorkflows(ctx, client, org, repo)
	if err != nil {
		return allNotCheckable(org, repo, notCheckableReason(wfResp, err, org, repo), client.Provenance())
	}

	// Split out the CodeQL default-setup virtual entry (if present) from
	// the real, content-fetchable workflow files — see
	// codeQLDefaultSetupPathPrefix's doc comment for why this can't go
	// through runhistory.MatchWorkflows' normal path.
	var matchedWorkflows []runhistory.MatchedWorkflow
	var realWorkflows []*ghgithub.Workflow
	for _, wf := range allWorkflows {
		if strings.HasPrefix(wf.GetPath(), codeQLDefaultSetupPathPrefix) {
			if sig, ok := registry.SignatureByID[codeQLSignatureID]; ok {
				matchedWorkflows = append(matchedWorkflows, runhistory.MatchedWorkflow{
					WorkflowID: wf.GetID(),
					Path:       wf.GetPath(),
					Matches: []mapping.ScannerMatch{{
						SignatureID: sig.ID,
						Name:        sig.Name,
						Category:    mapping.CategorySAST,
						Confidence:  mapping.ConfidenceHigh,
						MatchedOn:   "codeql-default-setup",
					}},
				})
			}
			continue
		}
		realWorkflows = append(realWorkflows, wf)
	}
	matchedWorkflows = append(matchedWorkflows, runhistory.MatchWorkflows(ctx, client, registry, org, repo, defaultBranch, realWorkflows, mapping.CategorySAST)...)

	now := time.Now().UTC()
	windowStart := now.AddDate(0, -scope.LookbackMonths, 0)

	rawReleases, relResp, err := runhistory.FetchReleases(ctx, client, org, repo)
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
	var releases []runhistory.ReleaseInfo
	droppedTags := 0
	for _, r := range rawReleases {
		tagName := r.GetTagName()
		if ok, err := filepath.Match(tagPattern, tagName); err != nil || !ok {
			continue // out of scope regardless of resolution outcome — not a drop
		}
		publishedAt := r.GetPublishedAt().Time
		sha, err := runhistory.ResolveReleaseCommit(ctx, client, org, repo, tagName)
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
		releases = append(releases, runhistory.ReleaseInfo{
			TagName:     tagName,
			CommitSHA:   sha,
			PublishedAt: publishedAt,
		})
	}
	filteredReleases := runhistory.FilterReleasesInLookback(releases, tagPattern, scope.LookbackReleases, scope.LookbackMonths, now)

	var runs []runhistory.RunInfo
	for _, mw := range matchedWorkflows {
		wfRuns, err := runhistory.FetchWorkflowRuns(ctx, client, org, repo, mw.WorkflowID, windowStart)
		if err != nil {
			continue // an individual workflow's run history failing to fetch doesn't invalidate the rest
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

	coverage := runhistory.LinkRunsToReleases(filteredReleases, runs, defaultBranch)
	cadence := runhistory.ComputeCadence(runs, windowStart, now)

	sharedProv := client.Provenance() // everything up to (not including) the default-setup call below
	sharedSkip := len(sharedProv)

	defaultSetup, dsResp, dsErr := client.REST.CodeScanning.GetDefaultSetupConfiguration(ctx, org, repo)
	dsProv := tailProvenance(client.Provenance(), sharedSkip)

	return []model.CheckResult{
		checkToolConfigured(org, repo, matchedWorkflows, defaultSetup, dsResp, dsErr, sharedProv),
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
