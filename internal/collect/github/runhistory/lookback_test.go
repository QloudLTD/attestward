package runhistory

import (
	"testing"
)

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
		// now = day(1000); a 3-month cutoff excludes anything older than
		// day(1000 - ~90) = ~day(910) — v1.0.0 (day 100) and v2.0.0
		// (day 900) both fall outside that.
		got := FilterReleasesInLookback(releases, "v*", 10, 3, now)
		if len(got) != 1 || got[0].TagName != "v3.0.0" {
			t.Errorf("got = %+v, want only [v3.0.0]", got)
		}
	})

	t.Run("whichever bound hits first wins, not a union or intersection surprise", func(t *testing.T) {
		// lookbackReleases=1 stops after v3.0.0 even though the months
		// cutoff alone would have allowed v2.0.0 too.
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

// TestFilterReleasesInLookback_TagWithoutReleaseIsStructurallyExcluded
// documents a scoping decision, not a bug to fix: this package's input
// comes from GitHub's Releases API (GET /repos/{o}/{r}/releases), which
// only returns actual GitHub Release objects, never raw git tags without
// one. A tag pushed without ever creating a release for it never becomes a
// ReleaseInfo in the first place, so it's excluded by construction rather
// than by any filtering logic here.
func TestFilterReleasesInLookback_TagWithoutReleaseIsStructurallyExcluded(t *testing.T) {
	// No ReleaseInfo entry exists for a tag-only ref — there is nothing to
	// construct in this test; the absence itself is the point.
	got := FilterReleasesInLookback([]ReleaseInfo{}, "v*", 5, 12, day(0))
	if len(got) != 0 {
		t.Errorf("got = %+v, want empty", got)
	}
}
