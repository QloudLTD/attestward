package scahistory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/collect/gitlab/cihistory"
	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// criticalTriageWindow is how long a critical dependency vulnerability may
// stay open before this check reports it. Deliberately the same 30 days its
// GitHub twin uses (internal/collect/github/scahistory's
// criticalTriageThresholdDays), so the two platforms answer the same
// question with the same bar rather than each inventing one.
const criticalTriageWindow = 30 * 24 * time.Hour

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

// tierGatedReason describes a refused Ultimate-tier read without claiming to
// know which of the two causes it was. See the package doc comment: an empty
// answer here would not have meant "clean", so nothing is reported either way.
func tierGatedReason(endpoint string, err error) string {
	if gitlabcollect.IsTierGated(err) {
		return fmt.Sprintf("%s answered 403. GitLab returns 403 both for a Dependency Scanning feature a Free "+
			"project is not entitled to and for a token without the required role, and this build does not "+
			"claim to tell those apart — either way, reading an empty answer as a clean one would be a "+
			"fabricated pass: %v", endpoint, err)
	}
	return fmt.Sprintf("could not read %s: %v", endpoint, err)
}

// -----------------------------------------------------------------------
// C06.sca.tool-configured
// -----------------------------------------------------------------------

// checkToolConfigured judges the merged CI configuration alone — a scanner
// configured today but never yet run is still configured.
func checkToolConfigured(org, repo string, ev cihistory.Evidence) model.CheckResult {
	if ev.LintErr != nil || !ev.ConfigParsed {
		return notCheckable(idToolConfigured, org, repo, ev.ConfigUnavailableReason(), ev.LintProv, nil)
	}

	facts := map[string]any{"scanner_jobs": cihistory.JobsToFacts(ev.Jobs)}
	confidence, found := cihistory.StrongestConfidence(ev.Jobs)
	if !found {
		return result(idToolConfigured, org, repo, model.StatusVerifiedFail,
			"this project's merged CI configuration resolved cleanly and contains no runnable job that emits "+
				"a GitLab dependency-scanning report, invokes a recognized dependency scanner CLI, or is "+
				"named like one",
			ev.LintProv, facts)
	}
	facts["confidence"] = string(confidence)

	if confidence == cihistory.ConfidenceLow {
		return result(idToolConfigured, org, repo, model.StatusPartial,
			fmt.Sprintf("%s (%s) is named like a dependency scanner but neither emits a GitLab "+
				"dependency-scanning report nor invokes a recognized scanner CLI — a naming convention is not "+
				"evidence the tool is actually run",
				cihistory.Plural(len(ev.Jobs), "job", "jobs"), cihistory.DescribeJobNames(ev.Jobs)),
			ev.LintProv, facts)
	}
	return result(idToolConfigured, org, repo, model.StatusVerifiedPass,
		fmt.Sprintf("%s in this project's CI configuration run a dependency scanner: %s",
			cihistory.Plural(len(ev.Jobs), "job", "jobs"), cihistory.DescribeJobNames(ev.Jobs)),
		ev.LintProv, facts)
}

// -----------------------------------------------------------------------
// C06.sca.ran-per-release
// -----------------------------------------------------------------------

// checkRanPerRelease joins each release's own commit against the matched
// scanner runs. Its truncation rule is the conditional one — see the C05
// twin's identical function for the monotonicity reasoning behind it.
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
				"window, and %s still reads as having no dependency-scanning run at all (%s) — an incomplete "+
				"run pool cannot certify that absence", cihistory.Plural(len(missing), "release", "releases"),
				strings.Join(missing, ", ")),
			prov, facts)
	}

	switch {
	case len(missing) > 0:
		return result(idRanPerRelease, org, repo, model.StatusVerifiedFail,
			fmt.Sprintf("%s in the lookback window had no dependency-scanning job run on its own commit at "+
				"all: %s", cihistory.Plural(len(missing), "release", "releases"), strings.Join(missing, ", ")),
			prov, facts)
	case len(failed) > 0:
		return result(idRanPerRelease, org, repo, model.StatusPartial,
			fmt.Sprintf("a dependency-scanning job ran on every release commit in the lookback window, but "+
				"for %s none of those jobs succeeded: %s",
				cihistory.Plural(len(failed), "release", "releases"), strings.Join(failed, ", ")),
			prov, facts)
	default:
		return result(idRanPerRelease, org, repo, model.StatusVerifiedPass,
			fmt.Sprintf("a dependency-scanning job ran successfully on the commit of every one of the %d "+
				"release(s) in the lookback window", len(ev.Releases)),
			prov, facts)
	}
}

// -----------------------------------------------------------------------
// C06.sca.dependabot-config — manifest coverage
// -----------------------------------------------------------------------

// checkManifestCoverage compares the dependency files GitLab reported
// scanning against the manifests actually in the repository.
//
// The comparison is on file PATHS, which is what makes it honest: GET
// /projects/:id/dependencies returns a dependency_file_path per dependency
// and the tree returns paths, so nothing here needs a lockfile-to-package-
// manager table that could be wrong. See the package doc comment for why
// there is no verified-fail outcome.
func checkManifestCoverage(org, repo string, scanned []string, scannedErr error, manifests []string, manifestsErr error, prov []model.Provenance) model.CheckResult {
	if scannedErr != nil {
		return notCheckable(idManifestCoverage, org, repo, tierGatedReason(dependenciesEndpoint, scannedErr), prov, nil)
	}
	if manifestsErr != nil {
		return notCheckable(idManifestCoverage, org, repo,
			fmt.Sprintf("could not list this project's repository tree, so which dependency manifests exist "+
				"is unknown: %v", manifestsErr), prov, nil)
	}
	if len(manifests) == 0 {
		return notCheckable(idManifestCoverage, org, repo,
			"this project's repository contains no dependency manifest of a kind GitLab's Dependency Scanning "+
				"template gates its analyzers on, so there is no coverage question to answer", prov,
			map[string]any{"scanned_files": scanned})
	}

	scannedSet := map[string]bool{}
	for _, f := range scanned {
		scannedSet[f] = true
	}
	var uncovered []string
	for _, m := range manifests {
		if !scannedSet[m] {
			uncovered = append(uncovered, m)
		}
	}
	sort.Strings(uncovered)

	facts := map[string]any{
		"repository_manifests": manifests,
		"scanned_files":        scanned,
		"uncovered_manifests":  uncovered,
	}

	if len(uncovered) > 0 {
		return result(idManifestCoverage, org, repo, model.StatusPartial,
			fmt.Sprintf("GitLab reported no dependencies from %s present in this repository (%s). That is not "+
				"necessarily a gap — a test fixture, a vendored copy, or a path matched by DS_EXCLUDED_PATHS "+
				"is uncovered without being a finding — so this is reported for a reader who knows the "+
				"repository rather than asserted as a failure",
				cihistory.Plural(len(uncovered), "dependency manifest", "dependency manifests"),
				strings.Join(uncovered, ", ")),
			prov, facts)
	}
	return result(idManifestCoverage, org, repo, model.StatusVerifiedPass,
		fmt.Sprintf("GitLab reported dependencies from every one of the %d dependency manifest(s) in this "+
			"repository", len(manifests)),
		prov, facts)
}

// -----------------------------------------------------------------------
// C06.sca.alerts-triaged
// -----------------------------------------------------------------------

// checkAlertsTriaged reports whether open critical dependency vulnerabilities
// are being triaged.
//
// "Open" is internal/collect/gitlab.IsOpenVulnerability's decision, not a
// fresh one: dismissed and resolved are triage outcomes and must never count
// against a producer, while confirmed — a human explicitly verifying a
// finding is real — must. An unrecognised state is neither bucketed nor
// ignored: it caps the result at partial and is named in Facts, because a
// state this build has never seen could be an open one.
func checkAlertsTriaged(org, repo string, vulns []vulnerability, vulnsErr error, now time.Time, prov []model.Provenance) model.CheckResult {
	if vulnsErr != nil {
		return notCheckable(idAlertsTriaged, org, repo, tierGatedReason(vulnerabilitiesEndpoint, vulnsErr), prov, nil)
	}

	var openCritical []vulnerability
	var stale []string
	unrecognised := map[string]bool{}
	for _, v := range vulns {
		if v.ReportType != reportTypeDependencyScanning {
			continue
		}
		open, err := gitlabcollect.IsOpenVulnerability(v.State)
		if err != nil {
			unrecognised[v.State] = true
			continue
		}
		if !open || !strings.EqualFold(v.Severity, "critical") {
			continue
		}
		openCritical = append(openCritical, v)
		if now.Sub(v.CreatedAt) > criticalTriageWindow {
			stale = append(stale, v.Title)
		}
	}

	unrecognisedStates := make([]string, 0, len(unrecognised))
	for s := range unrecognised {
		unrecognisedStates = append(unrecognisedStates, s)
	}
	sort.Strings(unrecognisedStates)

	facts := map[string]any{
		"open_critical_count":      len(openCritical),
		"stale_critical_count":     len(stale),
		"triage_window_days":       int(criticalTriageWindow.Hours() / 24),
		"unrecognized_states":      unrecognisedStates,
		"oldest_open_critical_age": oldestAgeDays(openCritical, now),
	}

	if len(stale) > 0 {
		sort.Strings(stale)
		return result(idAlertsTriaged, org, repo, model.StatusVerifiedFail,
			fmt.Sprintf("%s open longer than the %d-day triage window: %s",
				cihistory.Plural(len(stale), "critical dependency vulnerability is", "critical dependency vulnerabilities are"),
				int(criticalTriageWindow.Hours()/24), strings.Join(stale, "; ")),
			prov, facts)
	}
	if len(unrecognisedStates) > 0 {
		return result(idAlertsTriaged, org, repo, model.StatusPartial,
			fmt.Sprintf("no critical dependency vulnerability is beyond the %d-day triage window among the "+
				"findings this build could interpret, but %s carried a state it does not recognize (%s) — a "+
				"state GitLab added since this build was written is not silently bucketed as open or closed, "+
				"so a stale critical finding cannot be ruled out",
				int(criticalTriageWindow.Hours()/24),
				cihistory.Plural(len(unrecognisedStates), "finding", "findings"),
				strings.Join(unrecognisedStates, ", ")),
			prov, facts)
	}
	return result(idAlertsTriaged, org, repo, model.StatusVerifiedPass,
		fmt.Sprintf("no open critical dependency vulnerability has been open longer than the %d-day triage "+
			"window (%d open critical finding(s) in total)",
			int(criticalTriageWindow.Hours()/24), len(openCritical)),
		prov, facts)
}

func oldestAgeDays(vulns []vulnerability, now time.Time) float64 {
	var oldest float64
	for _, v := range vulns {
		if age := now.Sub(v.CreatedAt).Hours() / 24; age > oldest {
			oldest = age
		}
	}
	return oldest
}
