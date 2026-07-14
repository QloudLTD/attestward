package sasthistory

import (
	"path/filepath"
	"sort"
	"time"
)

// filterReleasesInLookback selects the releases a scan should evaluate:
// only those whose tag matches tagPattern (a glob — filepath.Match syntax,
// e.g. the default "v*"; not a regex — full regex support is a v-next
// enhancement, not needed for any signature this collector currently
// consumes), then bounded by whichever of lookbackReleases (a count) or
// lookbackMonths (a time span from now) is hit first — matching the
// product brief's "last 5 releases or 12 months" framing: keep taking the
// most recent matching releases until either limit stops it, not both
// limits independently unioned or intersected.
//
// Returns releases sorted newest-first. A malformed tagPattern is treated
// as matching nothing (filepath.Match's own error, e.g. ErrBadPattern,
// isn't surfaced as a hard failure here — an unmatchable pattern and a
// bad pattern produce the same practical outcome: no releases in scope,
// which the caller already turns into a clear not-checkable reason).
func filterReleasesInLookback(releases []releaseInfo, tagPattern string, lookbackReleases int, lookbackMonths int, now time.Time) []releaseInfo {
	var matched []releaseInfo
	for _, r := range releases {
		if ok, err := filepath.Match(tagPattern, r.TagName); err == nil && ok {
			matched = append(matched, r)
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].PublishedAt.After(matched[j].PublishedAt) })

	cutoff := now.AddDate(0, -lookbackMonths, 0)
	out := make([]releaseInfo, 0, len(matched))
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
