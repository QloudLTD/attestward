// Package runhistory holds the release/run-linkage, cadence, and
// lookback-filtering machinery shared by any collector that needs to
// answer "did a matched tool actually run for each recent release" — C05
// sast-history was first, C06 sca-history reuses it verbatim rather than
// duplicating it (see issue #18). Nothing here is specific to any scanner
// category; category-specific behavior (e.g. C05's CodeQL default-setup
// virtual-workflow detection) belongs in the collector package that needs
// it, layered on top of ListWorkflows/MatchWorkflows.
package runhistory

import (
	"sort"
	"time"
)

// ReleaseCoverageStatus is how a single release's tool coverage resolved —
// see LinkRunsToReleases' doc comment for the exact definition of each.
type ReleaseCoverageStatus string

const (
	// CoverageRan means at least one successful matched run covers this
	// release.
	CoverageRan ReleaseCoverageStatus = "ran"
	// CoverageFailed means at least one matched run covers this release,
	// but none succeeded — the tool is configured and attempted, just not
	// clean for this release.
	CoverageFailed ReleaseCoverageStatus = "failed"
	// CoverageMissing means no matched run at all covers this release —
	// the tool never actually exercised this release's window.
	CoverageMissing ReleaseCoverageStatus = "missing"
)

// ReleaseInfo is the minimal release data the linkage algorithm needs —
// deliberately decoupled from go-github's RepositoryRelease so this file
// stays testable without constructing API response types.
type ReleaseInfo struct {
	TagName     string
	CommitSHA   string
	PublishedAt time.Time
}

// RunInfo is the minimal workflow-run data the linkage algorithm needs,
// for the same reason.
type RunInfo struct {
	HeadSHA    string
	HeadBranch string
	Conclusion string // "success", "failure", "cancelled", "" (in progress), ...
	CreatedAt  time.Time
}

// ReleaseCoverage is one release's resolved tool coverage.
type ReleaseCoverage struct {
	Release ReleaseInfo
	Status  ReleaseCoverageStatus
}

// LinkRunsToReleases determines, for each release, whether a matched tool
// covered it. A release is covered by:
//  1. any run whose HeadSHA equals the release's own resolved commit SHA
//     (the tool ran directly against the tagged commit), or
//  2. any run on defaultBranch whose CreatedAt falls in the window
//     (previousRelease.PublishedAt, thisRelease.PublishedAt] — exclusive
//     of the previous release's own instant, inclusive of this release's —
//     i.e. "ran on the default branch sometime during this release's
//     development window." Exclusive-left matters: a run whose CreatedAt
//     exactly equals the previous release's PublishedAt must count only
//     for the previous release (as its own right-inclusive endpoint), not
//     be double-counted into this release's window too. The oldest
//     release passed in has no preceding release, so its window is
//     unbounded on the left (any default-branch run at or before it
//     counts).
//
// releases need not be pre-sorted; this function sorts a copy by
// PublishedAt ascending internally to compute windows, then returns
// results in that same (oldest-first) order — callers wanting newest-first
// should reverse the result themselves.
//
// This is a pure function: no I/O, fully covered by table-driven tests
// independent of any GitHub API shape.
func LinkRunsToReleases(releases []ReleaseInfo, runs []RunInfo, defaultBranch string) []ReleaseCoverage {
	sorted := make([]ReleaseInfo, len(releases))
	copy(sorted, releases)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PublishedAt.Before(sorted[j].PublishedAt) })

	coverage := make([]ReleaseCoverage, len(sorted))
	for i, rel := range sorted {
		// The oldest release (i == 0) has an unbounded-left window: any
		// run at or before its PublishedAt counts, so windowStart's zero
		// value combined with inclusiveStart=true is correct there. Every
		// other release's window starts strictly after the previous
		// release's PublishedAt — see the exclusive-left rationale above.
		var windowStart time.Time
		inclusiveStart := true
		if i > 0 {
			windowStart = sorted[i-1].PublishedAt
			inclusiveStart = false
		}

		anyRun, anySuccess := false, false
		for _, run := range runs {
			afterStart := run.CreatedAt.After(windowStart)
			if inclusiveStart {
				afterStart = afterStart || run.CreatedAt.Equal(windowStart)
			}
			inWindow := afterStart && !run.CreatedAt.After(rel.PublishedAt)
			matches := run.HeadSHA == rel.CommitSHA || (run.HeadBranch == defaultBranch && inWindow)
			if !matches {
				continue
			}
			anyRun = true
			if run.Conclusion == "success" {
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
