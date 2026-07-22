package pipelinehistory

import (
	"sort"
	"strings"
	"time"
)

// ReleaseCoverageStatus is how a single release's tool coverage resolved —
// mirrors runhistory.ReleaseCoverageStatus exactly; see LinkRunsToReleases'
// doc comment for the exact definition of each.
type ReleaseCoverageStatus string

const (
	// CoverageRan means at least one build whose Result is "succeeded"
	// (case-insensitive — see LinkRunsToReleases' own doc comment for why)
	// covers this release — "succeeded" is the one BuildResult enum value
	// (verified against Azure DevOps's Builds - List reference: none,
	// succeeded, partiallySucceeded, failed, canceled) this package treats
	// as a clean run, mirroring the GitHub twin's "success"-only bar.
	CoverageRan ReleaseCoverageStatus = "ran"
	// CoverageFailed means at least one build covers this release, but
	// none succeeded (whatever its actual Result — failed,
	// partiallySucceeded, canceled, or "" for one still in progress) — the
	// tool is configured and attempted, just not clean for this release.
	CoverageFailed ReleaseCoverageStatus = "failed"
	// CoverageMissing means no matched build at all covers this release.
	CoverageMissing ReleaseCoverageStatus = "missing"
)

// RunInfo is the minimal Azure Pipelines build data the linkage algorithm
// needs — Azure DevOps's counterpart to runhistory.RunInfo, renamed to the
// Build object's own documented field names (sourceVersion, sourceBranch,
// result, queueTime) rather than reusing GitHub's (HeadSHA, HeadBranch,
// Conclusion, CreatedAt), so a caller reading this struct alongside the
// REST reference isn't translating field names in their head.
type RunInfo struct {
	// SourceVersion is the commit SHA the build ran against (Build.sourceVersion).
	SourceVersion string
	// SourceBranch is the fully-qualified ref the build ran against (e.g.
	// "refs/heads/main", Build.sourceBranch) — compared directly against a
	// BuildRepository's own defaultBranch field, which the Builds -
	// List/Definitions - Get references document in the same
	// fully-qualified form, so no normalization is needed on either side
	// (unlike GitHub, where both HeadBranch and the repository's default
	// branch are already bare names on that platform's own API).
	SourceBranch string
	// Result is Build.result: "succeeded", "partiallySucceeded", "failed",
	// "canceled", or "" (BuildResult's "none" — no result yet, e.g. still
	// running).
	Result string
	// QueueTime is Build.queueTime — when the build was queued, this
	// package's analogue of a GitHub workflow run's CreatedAt.
	QueueTime time.Time
}

// ReleaseCoverage is one release's resolved tool coverage.
type ReleaseCoverage struct {
	Release ReleaseInfo
	Status  ReleaseCoverageStatus
}

// LinkRunsToReleases determines, for each release, whether a matched
// pipeline covered it — an exact mirror of runhistory.LinkRunsToReleases'
// algorithm and window semantics (see that function's doc comment for the
// full exclusive-left/inclusive-right window rationale), adapted to this
// package's RunInfo field names: a release is covered by
//  1. any build whose SourceVersion equals the release's own resolved
//     commit SHA, or
//  2. any build on defaultBranch whose QueueTime falls in the window
//     (previousRelease.PublishedAt, thisRelease.PublishedAt].
//
// releases need not be pre-sorted; this function sorts a copy by
// PublishedAt ascending internally to compute windows, then returns
// results in that same (oldest-first) order.
//
// This is a pure function: no I/O, fully covered by table-driven tests
// independent of any Azure DevOps API shape — client-side sourceVersion
// matching is exactly what this function performs, since Builds List
// itself has no server-side sourceVersion filter (verified against the
// full documented parameter list).
//
// Result is compared against "succeeded" case-insensitively: this
// project's own experience with another ADO enum field documented as a
// fixed set of string values (the audit Streams API's status field, issue
// #154/S8) that didn't reliably match its own documented casing in
// practice is why every ADO enum comparison in this project now defaults
// to case-insensitive rather than assuming a real service always echoes
// the reference docs' exact casing back.
func LinkRunsToReleases(releases []ReleaseInfo, runs []RunInfo, defaultBranch string) []ReleaseCoverage {
	sorted := make([]ReleaseInfo, len(releases))
	copy(sorted, releases)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PublishedAt.Before(sorted[j].PublishedAt) })

	coverage := make([]ReleaseCoverage, len(sorted))
	for i, rel := range sorted {
		var windowStart time.Time
		inclusiveStart := true
		if i > 0 {
			windowStart = sorted[i-1].PublishedAt
			inclusiveStart = false
		}

		anyRun, anySuccess := false, false
		for _, run := range runs {
			afterStart := run.QueueTime.After(windowStart)
			if inclusiveStart {
				afterStart = afterStart || run.QueueTime.Equal(windowStart)
			}
			inWindow := afterStart && !run.QueueTime.After(rel.PublishedAt)
			matches := run.SourceVersion == rel.CommitSHA || (run.SourceBranch == defaultBranch && inWindow)
			if !matches {
				continue
			}
			anyRun = true
			if strings.EqualFold(run.Result, "succeeded") {
				anySuccess = true
			}
		}

		status := CoverageMissing
		switch {
		case anySuccess:
			status = CoverageRan
		case anyRun:
			status = CoverageFailed
		}
		coverage[i] = ReleaseCoverage{Release: rel, Status: status}
	}
	return coverage
}
