package sasthistory

import (
	"testing"
	"time"
)

func day(n int) time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, n)
}

func TestLinkRunsToReleases(t *testing.T) {
	tests := []struct {
		name         string
		releases     []releaseInfo
		runs         []runInfo
		wantStatuses map[string]releaseCoverageStatus // by TagName
	}{
		{
			name:         "no releases at all",
			releases:     nil,
			runs:         []runInfo{{HeadSHA: "abc", Conclusion: "success", CreatedAt: day(1)}},
			wantStatuses: map[string]releaseCoverageStatus{},
		},
		{
			name:         "no runs at all: every release missing",
			releases:     []releaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs:         nil,
			wantStatuses: map[string]releaseCoverageStatus{"v1.0.0": coverageMissing},
		},
		{
			name:     "direct commit match, successful run: ran",
			releases: []releaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []runInfo{
				{HeadSHA: "abc", Conclusion: "success", CreatedAt: day(5)},
			},
			wantStatuses: map[string]releaseCoverageStatus{"v1.0.0": coverageRan},
		},
		{
			name:     "direct commit match, failed run: failed not missing",
			releases: []releaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []runInfo{
				{HeadSHA: "abc", Conclusion: "failure", CreatedAt: day(5)},
			},
			wantStatuses: map[string]releaseCoverageStatus{"v1.0.0": coverageFailed},
		},
		{
			name:     "failed run then successful run for the same release: success wins",
			releases: []releaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []runInfo{
				{HeadSHA: "abc", Conclusion: "failure", CreatedAt: day(4)},
				{HeadSHA: "abc", Conclusion: "success", CreatedAt: day(5)},
			},
			wantStatuses: map[string]releaseCoverageStatus{"v1.0.0": coverageRan},
		},
		{
			name:     "default-branch run within the oldest release's unbounded-left window: ran",
			releases: []releaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []runInfo{
				// Not the release commit itself, but a default-branch run
				// well before the release date — the oldest release's
				// window has no lower bound, so this must still count.
				{HeadSHA: "def", HeadBranch: "main", Conclusion: "success", CreatedAt: day(1)},
			},
			wantStatuses: map[string]releaseCoverageStatus{"v1.0.0": coverageRan},
		},
		{
			name: "default-branch run between two releases attributes to the LATER one only",
			releases: []releaseInfo{
				{TagName: "v1.0.0", CommitSHA: "aaa", PublishedAt: day(5)},
				{TagName: "v1.1.0", CommitSHA: "bbb", PublishedAt: day(10)},
			},
			runs: []runInfo{
				{HeadSHA: "ccc", HeadBranch: "main", Conclusion: "success", CreatedAt: day(7)},
			},
			wantStatuses: map[string]releaseCoverageStatus{
				"v1.0.0": coverageMissing,
				"v1.1.0": coverageRan,
			},
		},
		{
			name: "rerun after a tag lands in the NEXT release's window, not the tagged one",
			releases: []releaseInfo{
				{TagName: "v1.0.0", CommitSHA: "aaa", PublishedAt: day(5)},
				{TagName: "v1.1.0", CommitSHA: "bbb", PublishedAt: day(10)},
			},
			runs: []runInfo{
				// A default-branch run one day AFTER v1.0.0 was published —
				// must not retroactively cover v1.0.0's own window (which
				// ends exactly at day(5)), only v1.1.0's (day(5), day(10)].
				{HeadSHA: "ccc", HeadBranch: "main", Conclusion: "success", CreatedAt: day(6)},
			},
			wantStatuses: map[string]releaseCoverageStatus{
				"v1.0.0": coverageMissing,
				"v1.1.0": coverageRan,
			},
		},
		{
			name: "run exactly AT a release's own PublishedAt counts only for that release, not the next one",
			releases: []releaseInfo{
				{TagName: "v1.0.0", CommitSHA: "aaa", PublishedAt: day(5)},
				{TagName: "v1.1.0", CommitSHA: "bbb", PublishedAt: day(10)},
			},
			runs: []runInfo{
				// CreatedAt exactly equals v1.0.0's PublishedAt (day(5)) —
				// this is v1.0.0's own right-inclusive endpoint, and must
				// not also be double-counted as v1.1.0's window start
				// (which is exclusive-left at day(5)).
				{HeadSHA: "ddd", HeadBranch: "main", Conclusion: "success", CreatedAt: day(5)},
			},
			wantStatuses: map[string]releaseCoverageStatus{
				"v1.0.0": coverageRan,
				"v1.1.0": coverageMissing,
			},
		},
		{
			name: "run after the newest release's PublishedAt does not count for it",
			releases: []releaseInfo{
				{TagName: "v1.0.0", CommitSHA: "aaa", PublishedAt: day(5)},
			},
			runs: []runInfo{
				{HeadSHA: "zzz", HeadBranch: "main", Conclusion: "success", CreatedAt: day(6)},
			},
			wantStatuses: map[string]releaseCoverageStatus{"v1.0.0": coverageMissing},
		},
		{
			name:     "run on a non-default branch, not matching the release commit: missing",
			releases: []releaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []runInfo{
				{HeadSHA: "def", HeadBranch: "feature/x", Conclusion: "success", CreatedAt: day(3)},
			},
			wantStatuses: map[string]releaseCoverageStatus{"v1.0.0": coverageMissing},
		},
		{
			name: "releases passed out of order still resolve correctly (function sorts internally)",
			releases: []releaseInfo{
				{TagName: "v1.1.0", CommitSHA: "bbb", PublishedAt: day(10)},
				{TagName: "v1.0.0", CommitSHA: "aaa", PublishedAt: day(5)},
			},
			runs: []runInfo{
				{HeadSHA: "aaa", Conclusion: "success", CreatedAt: day(5)},
				{HeadSHA: "bbb", Conclusion: "success", CreatedAt: day(10)},
			},
			wantStatuses: map[string]releaseCoverageStatus{
				"v1.0.0": coverageRan,
				"v1.1.0": coverageRan,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := linkRunsToReleases(tt.releases, tt.runs, "main")
			if len(got) != len(tt.wantStatuses) {
				t.Fatalf("linkRunsToReleases returned %d entries, want %d (%+v)", len(got), len(tt.wantStatuses), got)
			}
			for _, c := range got {
				want, ok := tt.wantStatuses[c.Release.TagName]
				if !ok {
					t.Errorf("unexpected release %q in result", c.Release.TagName)
					continue
				}
				if c.Status != want {
					t.Errorf("release %q status = %q, want %q", c.Release.TagName, c.Status, want)
				}
			}
		})
	}
}
