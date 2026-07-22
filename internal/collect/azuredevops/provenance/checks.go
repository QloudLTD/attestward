package provenance

import (
	"fmt"
	"sort"
	"time"

	"github.com/sioakim/attestward/internal/collect/azuredevops/pipelinehistory"
	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/model"
)

// matchConfidence reports whether matched contains any provenance match at
// all (hasAny) and whether any of those matches are at least medium
// confidence (hasHighOrMedium) — mirrors sasthistory's identical helper.
func matchConfidence(matched []pipelinehistory.MatchedPipeline) (hasAny, hasHighOrMedium bool) {
	for _, mp := range matched {
		for _, m := range mp.Matches {
			hasAny = true
			if m.Confidence != mapping.ConfidenceLow {
				hasHighOrMedium = true
			}
		}
	}
	return hasAny, hasHighOrMedium
}

// checkProvenanceWorkflow is release-independent — like C05/C06's
// tool-configured, it asks "is a provenance-generating tool configured at
// all," not "did it run for this release" (that's commit-linkage's job, via
// a different, more precise mechanism: direct commit matching rather than
// category-matched-pipeline run history). Unlike sasthistory's own
// tool-configured, there is no enablement-style OR condition here at all:
// no ADO-native attestation task or platform feature exists for this
// question (issue #153's own C07 spec), so pipeline-match evidence is the
// only signal this check has. Applies the same confidence-capping rule as
// every other tool-configured-shaped check in this epic: a low-confidence-
// only match (a pipeline merely named "SLSA", with no matched run-pattern
// invocation) can never alone justify verified-pass.
//
// sameRepoSkips are this repo's own entries from
// pipelinehistory.MatchPipelines' skipped return (issue #178 — the same
// fix C06 sca-history's own tool-configured applies): surfaced in Facts
// unconditionally (name + reason per entry), and — only when every other
// signal here would otherwise produce verified-fail — capping that at
// not-checkable instead, since a pipeline this collector couldn't fully
// inspect means "no provenance tool configured" rests on incomplete
// evidence, not a confirmed absence. Found in review: the first version of
// this check discarded MatchPipelines' skipped list entirely, so a repo
// whose only provenance pipeline hit a fetch/parse failure or an
// unresolved template reference got a confirmed verified-fail instead.
func checkProvenanceWorkflow(org, repo string, matched []pipelinehistory.MatchedPipeline, sameRepoSkips []pipelinehistory.SkippedPipeline, prov []model.Provenance) model.CheckResult {
	const id = idWorkflow

	hasAny, hasHighOrMedium := matchConfidence(matched)

	names := map[string]bool{}
	for _, mp := range matched {
		for _, m := range mp.Matches {
			names[m.Name] = true
		}
	}

	skipDetails := make([]map[string]any, 0, len(sameRepoSkips))
	for _, sp := range sameRepoSkips {
		skipDetails = append(skipDetails, map[string]any{"name": sp.Name, "reason": sp.Reason})
	}
	hasSkips := len(sameRepoSkips) > 0

	status, reason := model.StatusVerifiedFail, "no provenance-generating tool (Sigstore/cosign, a SLSA generator, or comparable) was detected in any pipeline"
	switch {
	case hasHighOrMedium:
		status = model.StatusVerifiedPass
		reason = "a provenance-generating tool is configured"
	case hasAny:
		status = model.StatusPartial
		reason = "only a low-confidence (pipeline/step-name-only) match was found — not enough signal alone to confirm a provenance tool is genuinely configured"
	case hasSkips:
		status = model.StatusNotCheckable
		reason = fmt.Sprintf("no matched provenance-tool pipeline evidence, but %d pipeline(s) in this repo could not be fully inspected — a confirmed absence can't be asserted over incomplete evidence (issue #178 tracks fully consuming these skips)", len(sameRepoSkips))
	}

	toolNames := make([]string, 0, len(names))
	for n := range names {
		toolNames = append(toolNames, n)
	}
	sort.Strings(toolNames)

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"tool_names":                toolNames,
			"low_confidence_match_only": hasAny && !hasHighOrMedium,
			"skipped_pipelines":         skipDetails,
		},
	}
}

// commitLinkageResult is one release's build-coverage evidence for
// checkCommitLinkage: how many builds (any pipeline, any result) ran
// directly against that release's resolved commit SHA.
type commitLinkageResult struct {
	TagName  string
	RunCount int
}

// commitLinkageBuildGraceWindow bounds how much further back than the
// oldest in-window release's own PublishedAt collectRepo will search for
// its build (see collectRepo's own comment for where this is applied) —
// the fix for the boundary false-fail found in review: FetchBuilds'
// minTime was previously the same LookbackMonths cutoff releases are
// admitted at-or-after, so a release admitted right at that cutoff whose
// commit's build was queued earlier (routine for an annotated tag created
// some time after the commit/build it names — an annotated tag's own date
// is the tagger's date, not the underlying commit's, see
// pipelinehistory.ResolveReleases) fell outside the fetched build window
// entirely, producing a false "no build traceable to its commit." Widening
// the fetch to start at each repo's own oldest-evaluated-release date
// minus this grace window (rather than fetching unboundedly, which a
// large project's build history makes impractical) absorbs that routine
// case. 90 days is a judgment call, not derived from any real
// release-cadence data [fixture-verify / policy judgment]: generous enough
// for a tag applied weeks-to-a-couple-of-months after the commit/build it
// names, far short of an unbounded query. The residual limitation this
// still leaves — a real build queued more than 90 days before its
// release's own date would still be missed — is disclosed in
// C07.provenance.commit-linkage's own Rubric and in Facts.
// builds_search_start on every run (see checkCommitLinkage).
const commitLinkageBuildGraceWindow = 90 * 24 * time.Hour

// linkBuildsToCommits reports, for each release, how many builds in runs
// ran directly against that release's resolved commit SHA — deliberately
// NOT pipelinehistory.LinkRunsToReleases' own algorithm: that function's
// branch+time-window fallback exists for continuous tool-coverage checks
// (C05/C06's own ran-per-release), where a scheduled/triggered scan that
// merely ran "around" a release still counts as covering it. This check's
// own question is narrower and exact, mirroring the GitHub twin's identical
// choice (fetchWorkflowRunsForCommit, filtered server-side by HeadSHA with
// no window/branch fallback of its own and no Result filtering): is this
// specific commit traceable to ANY build at all, regardless of that
// build's own result — a release whose assets were produced by a build
// that ran on an unrelated commit (or no build at all) is exactly the gap
// this check exists to catch, and a window/branch-proximity heuristic
// would paper over it. "No window" here describes this MATCHING function
// only, which does plain SHA equality over whatever runs it's handed — the
// runs slice itself is still time-bounded upstream, by FetchBuilds' own
// minTime (see commitLinkageBuildGraceWindow and collectRepo), not an
// unbounded fetch of the whole project's build history. Pure function: no
// I/O.
func linkBuildsToCommits(releases []pipelinehistory.ReleaseInfo, runs []pipelinehistory.RunInfo) []commitLinkageResult {
	results := make([]commitLinkageResult, 0, len(releases))
	for _, rel := range releases {
		count := 0
		for _, run := range runs {
			if run.SourceVersion == rel.CommitSHA {
				count++
			}
		}
		results = append(results, commitLinkageResult{TagName: rel.TagName, RunCount: count})
	}
	return results
}

// checkCommitLinkage implements the issue's stated semantics: every
// release tag's commit must have at least one build (pass); a release
// with zero builds on its commit is a real gap (fail); a release tag that
// couldn't even be dated is unresolved, not a confirmed pass or fail —
// applies C05/C06's own unconditional-dropped-tag "any drop caps at
// partial" rule (see the package doc comment for why that's a deliberate,
// not-default choice on Azure DevOps specifically).
//
// buildsSearchStart is the actual minTime collectRepo passed to
// FetchBuilds for this repo (see commitLinkageBuildGraceWindow) — disclosed
// in Facts and in the verified-fail/per-release Reason text on every run,
// so a report reader can judge for themselves whether an unusually large
// tag-to-build gap could have produced a false fail this collector's own
// bounded search wouldn't have caught. Meaningless (and unused) when
// filteredReleases is empty, since no builds are fetched in that case.
func checkCommitLinkage(org, repo string, filteredReleases []pipelinehistory.ReleaseInfo, results []commitLinkageResult, dropped []string, buildsErr error, buildsSearchStart time.Time, prov []model.Provenance) model.CheckResult {
	const id = idCommitLinkage

	if len(filteredReleases) == 0 {
		status, reason := model.StatusNotCheckable, "no release tags match the configured pattern within the lookback window"
		if len(dropped) > 0 {
			status = model.StatusPartial
			reason = fmt.Sprintf("%d release tag(s) matching the pattern could not be dated, so no release could be evaluated", len(dropped))
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
			Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"dropped_tags": dropped},
		}
	}

	if buildsErr != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not fetch build history to evaluate commit linkage: %v", buildsErr),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	searchStartStr := buildsSearchStart.Format(time.RFC3339)

	anyMissing := false
	table := make([]map[string]any, 0, len(results))
	for _, r := range results {
		reason := fmt.Sprintf("%d build(s) found on this release's commit", r.RunCount)
		if r.RunCount == 0 {
			anyMissing = true
			reason = fmt.Sprintf("no build found on this release's commit (builds searched from %s onward)", searchStartStr)
		}
		table = append(table, map[string]any{"tag": r.TagName, "run_count": r.RunCount, "reason": reason})
	}

	status, reason := model.StatusVerifiedPass, "every release in the lookback window is traceable to a build on its commit"
	switch {
	case anyMissing:
		status, reason = model.StatusVerifiedFail, fmt.Sprintf("at least one release in the lookback window has no build traceable to its commit — builds were searched from %s onward (the oldest evaluated release's own date minus a %.0f-day grace window), not an unbounded history, so an unusually large gap between a release tag and the build/commit it names could in principle still be missed; see Facts.per_release for which release(s)", searchStartStr, commitLinkageBuildGraceWindow.Hours()/24)
	case len(dropped) > 0:
		status, reason = model.StatusPartial, fmt.Sprintf("every evaluated release is traceable to a build on its commit, but %d release tag(s) could not be dated and were excluded from evaluation", len(dropped))
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"per_release": table, "dropped_tags": dropped, "builds_search_start": searchStartStr},
	}
}
