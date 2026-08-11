package provenance

import (
	"path/filepath"
	"sort"
	"time"
)

// releaseInfo is the minimal per-release data the lookback filter and the
// two asset checks need.
type releaseInfo struct {
	TagName    string
	ReleasedAt time.Time
	AssetNames []string
}

// filterReleasesInLookback duplicates internal/collect/github/runhistory's
// identical function rather than importing it — ADR-0005 keeps every
// platform package independent so a future platform never has to reach
// into another's internals, and this is small enough (the pattern match,
// newest-first sort, then a count-or-date cutoff, whichever comes first)
// that duplicating it costs less than a cross-platform dependency would.
func filterReleasesInLookback(releases []releaseInfo, tagPattern string, lookbackReleases, lookbackMonths int, now time.Time) []releaseInfo {
	var matched []releaseInfo
	for _, r := range releases {
		if ok, err := filepath.Match(tagPattern, r.TagName); err == nil && ok {
			matched = append(matched, r)
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].ReleasedAt.After(matched[j].ReleasedAt) })

	cutoff := now.AddDate(0, -lookbackMonths, 0)
	out := make([]releaseInfo, 0, len(matched))
	for _, r := range matched {
		if len(out) >= lookbackReleases {
			break
		}
		if r.ReleasedAt.Before(cutoff) {
			break
		}
		out = append(out, r)
	}
	return out
}
