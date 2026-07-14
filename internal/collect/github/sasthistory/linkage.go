// Package sasthistory implements C05 sast-history: whether a SAST tool is
// configured (via #16's scanner-signature matcher, or GitHub's separate
// CodeQL "default setup" mechanism) and whether it actually ran for each
// recent release (SSDF PW.7, PW.8, RV.1).
package sasthistory

import (
	"sort"
	"time"
)

// releaseCoverageStatus is how a single release's SAST coverage resolved —
// see linkRunsToReleases' doc comment for the exact definition of each.
type releaseCoverageStatus string

const (
	// coverageRan: at least one successful matched run covers this release.
	coverageRan releaseCoverageStatus = "ran"
	// coverageFailed: at least one matched run covers this release, but
	// none succeeded — the tool is configured and attempted, just not
	// clean for this release.
	coverageFailed releaseCoverageStatus = "failed"
	// coverageMissing: no matched run at all covers this release — the
	// tool never actually exercised this release's window.
	coverageMissing releaseCoverageStatus = "missing"
)

// releaseInfo is the minimal release data the linkage algorithm needs —
// deliberately decoupled from go-github's RepositoryRelease so this file
// stays testable without constructing API response types.
type releaseInfo struct {
	TagName     string
	CommitSHA   string
	PublishedAt time.Time
}

// runInfo is the minimal workflow-run data the linkage algorithm needs,
// for the same reason.
type runInfo struct {
	HeadSHA    string
	HeadBranch string
	Conclusion string // "success", "failure", "cancelled", "" (in progress), ...
	CreatedAt  time.Time
}

// releaseCoverage is one release's resolved SAST coverage.
type releaseCoverage struct {
	Release releaseInfo
	Status  releaseCoverageStatus
}

// linkRunsToReleases determines, for each release, whether a matched SAST
// workflow covered it. A release is covered by:
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
func linkRunsToReleases(releases []releaseInfo, runs []runInfo, defaultBranch string) []releaseCoverage {
	sorted := make([]releaseInfo, len(releases))
	copy(sorted, releases)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PublishedAt.Before(sorted[j].PublishedAt) })

	coverage := make([]releaseCoverage, len(sorted))
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

		status := coverageMissing
		switch {
		case anySuccess:
			status = coverageRan
		case anyRun:
			status = coverageFailed
		}
		coverage[i] = releaseCoverage{Release: rel, Status: status}
	}
	return coverage
}
