package pipelinehistory

import (
	"path/filepath"
	"sort"
	"time"
)

// FilterReleasesInLookback selects the releases a scan should evaluate —
// an exact mirror of runhistory.FilterReleasesInLookback's contract, same
// signature shape, same semantics: only releases whose tag matches
// tagPattern (filepath.Match glob syntax, e.g. the default "v*"), bounded
// by whichever of lookbackReleases (a count) or lookbackMonths (a time
// span from now) is hit first — the product brief's "last 5 releases or
// 12 months" framing. Returns releases sorted newest-first.
//
// A malformed tagPattern is treated as matching nothing, same as the
// GitHub twin: filepath.Match's own error isn't surfaced as a hard
// failure here — an unmatchable pattern and a bad pattern produce the
// same practical outcome, no releases in scope, which the caller already
// turns into a clear not-checkable reason.
func FilterReleasesInLookback(releases []ReleaseInfo, tagPattern string, lookbackReleases int, lookbackMonths int, now time.Time) []ReleaseInfo {
	var matched []ReleaseInfo
	for _, r := range releases {
		if ok, err := filepath.Match(tagPattern, r.TagName); err == nil && ok {
			matched = append(matched, r)
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].PublishedAt.After(matched[j].PublishedAt) })

	cutoff := now.AddDate(0, -lookbackMonths, 0)
	out := make([]ReleaseInfo, 0, len(matched))
	for _, r := range matched {
		if len(out) >= lookbackReleases {
			break
		}
		if r.PublishedAt.Before(cutoff) {
			break
		}
		out = append(out, r)
	}
	return out
}
