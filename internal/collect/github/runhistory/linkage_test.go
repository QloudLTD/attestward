package runhistory

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
		releases     []ReleaseInfo
		runs         []RunInfo
		wantStatuses map[string]ReleaseCoverageStatus // by TagName
	}{
		{
			name:         "no releases at all",
			releases:     nil,
			runs:         []RunInfo{{HeadSHA: "abc", Conclusion: "success", CreatedAt: day(1)}},
			wantStatuses: map[string]ReleaseCoverageStatus{},
		},
		{
			name:         "no runs at all: every release missing",
			releases:     []ReleaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs:         nil,
			wantStatuses: map[string]ReleaseCoverageStatus{"v1.0.0": CoverageMissing},
		},
		{
			name:     "direct commit match, successful run: ran",
			releases: []ReleaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []RunInfo{
				{HeadSHA: "abc", Conclusion: "success", CreatedAt: day(5)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{"v1.0.0": CoverageRan},
		},
		{
			name:     "direct commit match, failed run: failed not missing",
			releases: []ReleaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []RunInfo{
				{HeadSHA: "abc", Conclusion: "failure", CreatedAt: day(5)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{"v1.0.0": CoverageFailed},
		},
		{
			name:     "failed run then successful run for the same release: success wins",
			releases: []ReleaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []RunInfo{
				{HeadSHA: "abc", Conclusion: "failure", CreatedAt: day(4)},
				{HeadSHA: "abc", Conclusion: "success", CreatedAt: day(5)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{"v1.0.0": CoverageRan},
		},
		{
			name:     "default-branch run within the oldest release's unbounded-left window: ran",
			releases: []ReleaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []RunInfo{
				// Not the release commit itself, but a default-branch run
				// well before the release date — the oldest release's
				// window has no lower bound, so this must still count.
				{HeadSHA: "def", HeadBranch: "main", Conclusion: "success", CreatedAt: day(1)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{"v1.0.0": CoverageRan},
		},
		{
			name: "default-branch run between two releases attributes to the LATER one only",
			releases: []ReleaseInfo{
				{TagName: "v1.0.0", CommitSHA: "aaa", PublishedAt: day(5)},
				{TagName: "v1.1.0", CommitSHA: "bbb", PublishedAt: day(10)},
			},
			runs: []RunInfo{
				{HeadSHA: "ccc", HeadBranch: "main", Conclusion: "success", CreatedAt: day(7)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{
				"v1.0.0": CoverageMissing,
				"v1.1.0": CoverageRan,
			},
		},
		{
			name: "rerun after a tag lands in the NEXT release's window, not the tagged one",
			releases: []ReleaseInfo{
				{TagName: "v1.0.0", CommitSHA: "aaa", PublishedAt: day(5)},
				{TagName: "v1.1.0", CommitSHA: "bbb", PublishedAt: day(10)},
			},
			runs: []RunInfo{
				// A default-branch run one day AFTER v1.0.0 was published —
				// must not retroactively cover v1.0.0's own window (which
				// ends exactly at day(5)), only v1.1.0's (day(5), day(10)].
				{HeadSHA: "ccc", HeadBranch: "main", Conclusion: "success", CreatedAt: day(6)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{
				"v1.0.0": CoverageMissing,
				"v1.1.0": CoverageRan,
			},
		},
		{
			name: "run exactly AT a release's own PublishedAt counts only for that release, not the next one",
			releases: []ReleaseInfo{
				{TagName: "v1.0.0", CommitSHA: "aaa", PublishedAt: day(5)},
				{TagName: "v1.1.0", CommitSHA: "bbb", PublishedAt: day(10)},
			},
			runs: []RunInfo{
				// CreatedAt exactly equals v1.0.0's PublishedAt (day(5)) —
				// this is v1.0.0's own right-inclusive endpoint, and must
				// not also be double-counted as v1.1.0's window start
				// (which is exclusive-left at day(5)).
				{HeadSHA: "ddd", HeadBranch: "main", Conclusion: "success", CreatedAt: day(5)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{
				"v1.0.0": CoverageRan,
				"v1.1.0": CoverageMissing,
			},
		},
		{
			name: "run after the newest release's PublishedAt does not count for it",
			releases: []ReleaseInfo{
				{TagName: "v1.0.0", CommitSHA: "aaa", PublishedAt: day(5)},
			},
			runs: []RunInfo{
				{HeadSHA: "zzz", HeadBranch: "main", Conclusion: "success", CreatedAt: day(6)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{"v1.0.0": CoverageMissing},
		},
		{
			name:     "run on a non-default branch, not matching the release commit: missing",
			releases: []ReleaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []RunInfo{
				{HeadSHA: "def", HeadBranch: "feature/x", Conclusion: "success", CreatedAt: day(3)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{"v1.0.0": CoverageMissing},
		},
		{
			name: "releases passed out of order still resolve correctly (function sorts internally)",
			releases: []ReleaseInfo{
				{TagName: "v1.1.0", CommitSHA: "bbb", PublishedAt: day(10)},
				{TagName: "v1.0.0", CommitSHA: "aaa", PublishedAt: day(5)},
			},
			runs: []RunInfo{
				{HeadSHA: "aaa", Conclusion: "success", CreatedAt: day(5)},
				{HeadSHA: "bbb", Conclusion: "success", CreatedAt: day(10)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{
				"v1.0.0": CoverageRan,
				"v1.1.0": CoverageRan,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LinkRunsToReleases(tt.releases, tt.runs, "main")
			if len(got) != len(tt.wantStatuses) {
				t.Fatalf("LinkRunsToReleases returned %d entries, want %d (%+v)", len(got), len(tt.wantStatuses), got)
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
