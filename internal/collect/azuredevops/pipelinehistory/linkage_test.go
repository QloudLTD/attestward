package pipelinehistory

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
			runs:         []RunInfo{{SourceVersion: "abc", Result: "succeeded", QueueTime: day(1)}},
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
				{SourceVersion: "abc", Result: "succeeded", QueueTime: day(5)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{"v1.0.0": CoverageRan},
		},
		{
			name:     "direct commit match, failed run: failed not missing",
			releases: []ReleaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []RunInfo{
				{SourceVersion: "abc", Result: "failed", QueueTime: day(5)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{"v1.0.0": CoverageFailed},
		},
		{
			name:     "direct commit match, still-running build (empty result): failed not missing",
			releases: []ReleaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []RunInfo{
				{SourceVersion: "abc", Result: "", QueueTime: day(5)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{"v1.0.0": CoverageFailed},
		},
		{
			name:     "failed run then successful run for the same release: success wins",
			releases: []ReleaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []RunInfo{
				{SourceVersion: "abc", Result: "failed", QueueTime: day(4)},
				{SourceVersion: "abc", Result: "succeeded", QueueTime: day(5)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{"v1.0.0": CoverageRan},
		},
		{
			name:     "default-branch run within the oldest release's unbounded-left window: ran",
			releases: []ReleaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []RunInfo{
				{SourceVersion: "def", SourceBranch: "refs/heads/main", Result: "succeeded", QueueTime: day(1)},
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
				{SourceVersion: "ccc", SourceBranch: "refs/heads/main", Result: "succeeded", QueueTime: day(7)},
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
				{SourceVersion: "ccc", SourceBranch: "refs/heads/main", Result: "succeeded", QueueTime: day(6)},
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
				{SourceVersion: "ddd", SourceBranch: "refs/heads/main", Result: "succeeded", QueueTime: day(5)},
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
				{SourceVersion: "zzz", SourceBranch: "refs/heads/main", Result: "succeeded", QueueTime: day(6)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{"v1.0.0": CoverageMissing},
		},
		{
			name:     "run on a non-default branch, not matching the release commit: missing",
			releases: []ReleaseInfo{{TagName: "v1.0.0", CommitSHA: "abc", PublishedAt: day(5)}},
			runs: []RunInfo{
				{SourceVersion: "def", SourceBranch: "refs/heads/feature/x", Result: "succeeded", QueueTime: day(3)},
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
				{SourceVersion: "aaa", Result: "succeeded", QueueTime: day(5)},
				{SourceVersion: "bbb", Result: "succeeded", QueueTime: day(10)},
			},
			wantStatuses: map[string]ReleaseCoverageStatus{
				"v1.0.0": CoverageRan,
				"v1.1.0": CoverageRan,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LinkRunsToReleases(tt.releases, tt.runs, "refs/heads/main")
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
