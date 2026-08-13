package sasthistory

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/collect/gitlab/cihistory"
	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// gatherEvidence is a thin seam over cihistory.Gather so tests can pin the
// clock — every other input a check reads comes off the wire.
var gatherEvidence = func(
	ctx context.Context,
	client *gitlabcollect.Client,
	projID string,
	scope collect.Scope,
	registry *mapping.ScannerSignatureRegistry,
	reportType string,
	category mapping.ScannerCategory,
	segment func() []model.Provenance,
) cihistory.Evidence {
	return cihistory.Gather(ctx, client, projID, scope.ReleaseTagPattern,
		scope.LookbackReleases, scope.LookbackMonths, time.Now().UTC(),
		reportType, category, registry, segment)
}

func result(id, org, repo string, status model.Status, reason string, prov []model.Provenance, facts map[string]any) model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope:      model.ScopeRef{Org: org, Repo: repo, Platform: platform},
		Provenance: prov, Facts: facts,
	}
}

func notCheckable(id, org, repo, reason string, prov []model.Provenance, facts map[string]any) model.CheckResult {
	return result(id, org, repo, model.StatusNotCheckable, reason, prov, facts)
}

func concatProv(segments ...[]model.Provenance) []model.Provenance {
	out := []model.Provenance{}
	for _, s := range segments {
		out = append(out, s...)
	}
	return out
}

// -----------------------------------------------------------------------
// C05.sast.tool-configured
// -----------------------------------------------------------------------

// checkToolConfigured judges the merged CI configuration alone. It reads no
// run history: a scanner configured today but never yet run is still
// configured, and whether it ran is C05.sast.cadence's question.
func checkToolConfigured(org, repo string, ev cihistory.Evidence) model.CheckResult {
	if ev.LintErr != nil || !ev.ConfigParsed {
		return notCheckable(idToolConfigured, org, repo, ev.ConfigUnavailableReason(), ev.LintProv, nil)
	}

	facts := map[string]any{"scanner_jobs": cihistory.JobsToFacts(ev.Jobs)}
	confidence, found := cihistory.StrongestConfidence(ev.Jobs)
	if !found {
		return result(idToolConfigured, org, repo, model.StatusVerifiedFail,
			"this project's merged CI configuration resolved cleanly and contains no runnable job that emits "+
				"a GitLab SAST report, invokes a recognized SAST scanner CLI, or is named like one",
			ev.LintProv, facts)
	}
	facts["confidence"] = string(confidence)

	if confidence == cihistory.ConfidenceLow {
		return result(idToolConfigured, org, repo, model.StatusPartial,
			fmt.Sprintf("%s (%s) is named like a SAST scanner but neither emits a GitLab SAST report nor "+
				"invokes a recognized scanner CLI — a naming convention is not evidence the tool is actually run",
				cihistory.Plural(len(ev.Jobs), "job", "jobs"), cihistory.DescribeJobNames(ev.Jobs)),
			ev.LintProv, facts)
	}
	return result(idToolConfigured, org, repo, model.StatusVerifiedPass,
		fmt.Sprintf("%s in this project's CI configuration run a SAST scanner: %s",
			cihistory.Plural(len(ev.Jobs), "job", "jobs"), cihistory.DescribeJobNames(ev.Jobs)),
		ev.LintProv, facts)
}

// -----------------------------------------------------------------------
// C05.sast.ran-per-release
// -----------------------------------------------------------------------

// checkRanPerRelease joins each release's own commit against the matched
// scanner runs.
//
// The truncation rule is asymmetric with checkCadence's, deliberately, and
// the asymmetry is the same one the GitHub twin arrived at in issue #291:
// coverage is MONOTONE in the run pool — more runs can only turn missing
// into failed or ran, never the reverse — so a truncated walk whose coverage
// already reads ran or failed for every release cannot have been overstated
// by the runs this build did not fetch. Only a release reading missing is
// unsafe to certify from an incomplete pool.
func checkRanPerRelease(org, repo string, ev cihistory.Evidence) model.CheckResult {
	prov := concatProv(ev.LintProv, ev.ReleasesProv, ev.JobsProv)

	if ev.LintErr != nil || !ev.ConfigParsed {
		return notCheckable(idRanPerRelease, org, repo, ev.ConfigUnavailableReason(), prov, nil)
	}
	if ev.ReleasesErr != nil {
		return notCheckable(idRanPerRelease, org, repo,
			fmt.Sprintf("could not read this project's releases: %v", ev.ReleasesErr), prov, nil)
	}
	if ev.RunsErr != nil {
		return notCheckable(idRanPerRelease, org, repo,
			fmt.Sprintf("could not read this project's job history: %v", ev.RunsErr), prov, nil)
	}
	if len(ev.Releases) == 0 {
		return notCheckable(idRanPerRelease, org, repo,
			"no release matches the configured release tag pattern within the lookback window, so there is "+
				"nothing to evaluate", prov, nil)
	}

	missing := cihistory.MissingCoverageTags(ev.Coverage)
	failed := cihistory.FailedCoverageTags(ev.Coverage)
	facts := map[string]any{
		"release_coverage":      cihistory.CoverageToFacts(ev.Coverage),
		"scanner_jobs":          cihistory.JobsToFacts(ev.Jobs),
		"job_history_truncated": ev.Truncated,
	}

	if ev.Truncated && len(missing) > 0 {
		return notCheckable(idRanPerRelease, org, repo,
			fmt.Sprintf("the job-history walk hit its page bound before reaching the start of the lookback "+
				"window, and %s still reads as having no SAST run at all (%s) — an incomplete run pool cannot "+
				"certify that absence", cihistory.Plural(len(missing), "release", "releases"),
				strings.Join(missing, ", ")),
			prov, facts)
	}

	switch {
	case len(missing) > 0:
		return result(idRanPerRelease, org, repo, model.StatusVerifiedFail,
			fmt.Sprintf("%s in the lookback window had no SAST job run on its own commit at all: %s",
				cihistory.Plural(len(missing), "release", "releases"), strings.Join(missing, ", ")),
			prov, facts)
	case len(failed) > 0:
		return result(idRanPerRelease, org, repo, model.StatusPartial,
			fmt.Sprintf("a SAST job ran on every release commit in the lookback window, but for %s none of "+
				"those jobs succeeded: %s", cihistory.Plural(len(failed), "release", "releases"),
				strings.Join(failed, ", ")),
			prov, facts)
	default:
		return result(idRanPerRelease, org, repo, model.StatusVerifiedPass,
			fmt.Sprintf("a SAST job ran successfully on the commit of every one of the %d release(s) in the "+
				"lookback window", len(ev.Releases)),
			prov, facts)
	}
}

// -----------------------------------------------------------------------
// C05.sast.cadence
// -----------------------------------------------------------------------

// checkCadence reports how regularly the scanner actually ran.
//
// Unlike coverage, a run count and a longest gap are NOT monotone in the run
// pool — a run this build did not fetch could raise the count or split a gap
// — so any truncation taints this check outright rather than conditionally.
func checkCadence(org, repo string, ev cihistory.Evidence) model.CheckResult {
	prov := concatProv(ev.LintProv, ev.JobsProv)

	if ev.LintErr != nil || !ev.ConfigParsed {
		return notCheckable(idCadence, org, repo, ev.ConfigUnavailableReason(), prov, nil)
	}
	confidence, found := cihistory.StrongestConfidence(ev.Jobs)
	if !found {
		return notCheckable(idCadence, org, repo,
			"no SAST scanner is configured in this project's CI configuration, so there is no cadence to "+
				"compute — C05.sast.tool-configured reports that absence", prov, nil)
	}
	if ev.RunsErr != nil {
		return notCheckable(idCadence, org, repo,
			fmt.Sprintf("could not read this project's job history: %v", ev.RunsErr), prov, nil)
	}
	if ev.Truncated {
		return notCheckable(idCadence, org, repo,
			"the job-history walk hit its page bound before reaching the start of the lookback window, so the "+
				"run pool is incomplete — a run count and a longest gap computed from part of the history "+
				"could understate the one and overstate the other", prov, nil)
	}

	facts := map[string]any{
		"runs":             ev.Cadence.Runs,
		"runs_per_week":    ev.Cadence.RunsPerWeek,
		"longest_gap_days": ev.Cadence.LongestGapDays,
		"confidence":       string(confidence),
		"scanner_jobs":     cihistory.JobsToFacts(ev.Jobs),
	}

	if ev.Cadence.Runs == 0 {
		return result(idCadence, org, repo, model.StatusVerifiedFail,
			fmt.Sprintf("a SAST scanner is configured (%s) but not one of its jobs finished inside the "+
				"lookback window", cihistory.DescribeJobNames(ev.Jobs)),
			prov, facts)
	}
	if confidence == cihistory.ConfidenceLow {
		return result(idCadence, org, repo, model.StatusPartial,
			fmt.Sprintf("%s finished inside the lookback window, but the only thing identifying the job as a "+
				"SAST scanner is its name — the cadence may not reflect SAST activity at all",
				cihistory.Plural(ev.Cadence.Runs, "job run", "job runs")),
			prov, facts)
	}
	return result(idCadence, org, repo, model.StatusVerifiedPass,
		fmt.Sprintf("%s finished inside the lookback window (%.1f per week, longest gap %.0f days)",
			cihistory.Plural(ev.Cadence.Runs, "SAST job run", "SAST job runs"),
			ev.Cadence.RunsPerWeek, ev.Cadence.LongestGapDays),
		prov, facts)
}
