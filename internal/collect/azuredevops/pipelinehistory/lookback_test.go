package pipelinehistory

import "testing"

func TestFilterReleasesInLookback(t *testing.T) {
	now := day(1000)
	releases := []ReleaseInfo{
		{TagName: "v3.0.0", PublishedAt: day(990)},
		{TagName: "v2.0.0", PublishedAt: day(900)},
		{TagName: "v1.0.0", PublishedAt: day(100)},
		// Not a "v*" tag — must be excluded by the glob, regardless of how
		// recent it is.
		{TagName: "nightly-build", PublishedAt: day(995)},
	}

	t.Run("glob filters non-matching tags", func(t *testing.T) {
		got := FilterReleasesInLookback(releases, "v*", 10, 120, now)
		for _, r := range got {
			if r.TagName == "nightly-build" {
				t.Errorf("nightly-build matched the v* pattern, want excluded")
			}
		}
	})

	t.Run("lookbackReleases count bounds the result", func(t *testing.T) {
		got := FilterReleasesInLookback(releases, "v*", 2, 1200, now)
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2", len(got))
		}
		if got[0].TagName != "v3.0.0" || got[1].TagName != "v2.0.0" {
			t.Errorf("got = %+v, want [v3.0.0 v2.0.0] (newest first)", got)
		}
	})

	t.Run("lookbackMonths cutoff bounds the result even under a high release count", func(t *testing.T) {
		got := FilterReleasesInLookback(releases, "v*", 10, 3, now)
		if len(got) != 1 || got[0].TagName != "v3.0.0" {
			t.Errorf("got = %+v, want only [v3.0.0]", got)
		}
	})

	t.Run("whichever bound hits first wins, not a union or intersection surprise", func(t *testing.T) {
		got := FilterReleasesInLookback(releases, "v*", 1, 36, now)
		if len(got) != 1 || got[0].TagName != "v3.0.0" {
			t.Errorf("got = %+v, want only [v3.0.0]", got)
		}
	})

	t.Run("no matching releases at all", func(t *testing.T) {
		got := FilterReleasesInLookback(nil, "v*", 5, 12, now)
		if len(got) != 0 {
			t.Errorf("got = %+v, want empty", got)
		}
	})

	t.Run("malformed glob pattern matches nothing rather than erroring", func(t *testing.T) {
		got := FilterReleasesInLookback(releases, "[", 10, 120, now)
		if len(got) != 0 {
			t.Errorf("got = %+v, want empty for a malformed pattern", got)
		}
	})
}
