package pipelinehistory

import (
	"context"
	"net/http"
	"testing"
	"time"

	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops/adofixture"
)

const (
	testOrg          = "attestward-demo"
	testProject      = "demo-project"
	testRepositoryID = "repo-guid-1"
)

func refsPath() string {
	return "/" + testOrg + "/" + testProject + "/_apis/git/repositories/" + testRepositoryID + "/refs"
}

// TestResolveReleases_AnnotatedAndLightweightTags proves both tag kinds
// resolve to the correct commit SHA and date: an annotated tag's commit
// SHA comes from peeledObjectId (not objectId, which is the tag object's
// own SHA) and its date from the annotated-tag object's taggedBy.date; a
// lightweight tag's commit SHA is objectId directly and its date comes
// from that commit's own committer.date.
func TestResolveReleases_AnnotatedAndLightweightTags(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, refsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 2,
			"value": []map[string]any{
				{"name": "refs/tags/v1.0.0", "objectId": "tag-object-sha", "peeledObjectId": "annotated-commit-sha"},
				{"name": "refs/tags/v2.0.0", "objectId": "lightweight-commit-sha"},
			},
		},
	})
	fx.Set("GET", azuredevops.HostCore, "/"+testOrg+"/"+testProject+"/_apis/git/repositories/"+testRepositoryID+"/annotatedtags/tag-object-sha", adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"taggedBy": map[string]any{"date": "2026-01-05T00:00:00Z"}},
	})
	fx.Set("GET", azuredevops.HostCore, "/"+testOrg+"/"+testProject+"/_apis/git/repositories/"+testRepositoryID+"/commits/lightweight-commit-sha", adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"committer": map[string]any{"date": "2026-02-10T00:00:00Z"}},
	})

	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)
	releases, dropped, err := ResolveReleases(context.Background(), client, testProject, testRepositoryID, "v*")
	if err != nil {
		t.Fatalf("ResolveReleases: %v", err)
	}
	if len(dropped) != 0 {
		t.Errorf("dropped = %v, want none", dropped)
	}
	if len(releases) != 2 {
		t.Fatalf("len(releases) = %d, want 2 (%+v)", len(releases), releases)
	}

	byTag := map[string]ReleaseInfo{}
	for _, r := range releases {
		byTag[r.TagName] = r
	}
	if got := byTag["v1.0.0"]; got.CommitSHA != "annotated-commit-sha" {
		t.Errorf("v1.0.0 CommitSHA = %q, want the peeled commit SHA, not the tag object's own SHA", got.CommitSHA)
	}
	if got := byTag["v2.0.0"]; got.CommitSHA != "lightweight-commit-sha" {
		t.Errorf("v2.0.0 CommitSHA = %q, want the ref's objectId directly", got.CommitSHA)
	}
}

// TestResolveReleases_TagPatternMismatchIsNotADrop proves a tag that
// doesn't match tagPattern is silently excluded from both releases and the
// dropped count — the same "out of scope, not a drop" rule
// runhistory/sasthistory.go applies.
func TestResolveReleases_TagPatternMismatchIsNotADrop(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, refsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 1,
			"value": []map[string]any{
				{"name": "refs/tags/nightly-build", "objectId": "some-sha"},
			},
		},
	})
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)

	releases, dropped, err := ResolveReleases(context.Background(), client, testProject, testRepositoryID, "v*")
	if err != nil {
		t.Fatalf("ResolveReleases: %v", err)
	}
	if len(releases) != 0 {
		t.Errorf("releases = %+v, want none (nightly-build doesn't match v*)", releases)
	}
	if len(dropped) != 0 {
		t.Errorf("dropped = %v, want none (a pattern mismatch is out of scope, not a drop)", dropped)
	}
}

// TestResolveReleases_AnnotatedTagDateFallsBackToPeeledCommitDate proves
// that when the annotated-tag object's own date lookup fails, ResolveReleases
// falls back to the peeled commit's own date (already in hand from the refs
// listing) rather than dropping a tag it can otherwise fully identify.
func TestResolveReleases_AnnotatedTagDateFallsBackToPeeledCommitDate(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, refsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 1,
			"value": []map[string]any{
				{"name": "refs/tags/v1.0.0", "objectId": "tag-object-sha", "peeledObjectId": "peeled-commit-sha"},
			},
		},
	})
	fx.Set("GET", azuredevops.HostCore, "/"+testOrg+"/"+testProject+"/_apis/git/repositories/"+testRepositoryID+"/annotatedtags/tag-object-sha", adofixture.Response{
		Status: http.StatusInternalServerError,
		Body:   map[string]any{"message": "TF400xxx: something went wrong"},
	})
	fx.Set("GET", azuredevops.HostCore, "/"+testOrg+"/"+testProject+"/_apis/git/repositories/"+testRepositoryID+"/commits/peeled-commit-sha", adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"committer": map[string]any{"date": "2026-02-10T00:00:00Z"}},
	})

	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)
	releases, dropped, err := ResolveReleases(context.Background(), client, testProject, testRepositoryID, "v*")
	if err != nil {
		t.Fatalf("ResolveReleases: %v", err)
	}
	if len(dropped) != 0 {
		t.Errorf("dropped = %v, want none (the peeled-commit fallback should have succeeded)", dropped)
	}
	if len(releases) != 1 || releases[0].TagName != "v1.0.0" || releases[0].CommitSHA != "peeled-commit-sha" {
		t.Errorf("releases = %+v, want exactly one v1.0.0 release with the peeled commit SHA", releases)
	}
	wantDate := time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC)
	if !releases[0].PublishedAt.Equal(wantDate) {
		t.Errorf("PublishedAt = %v, want %v (the fallback commit's own date)", releases[0].PublishedAt, wantDate)
	}
}

// TestResolveReleases_UnresolvableDateIsDroppedNotFatal proves one tag
// whose date resolution fails outright — including the peeled-commit
// fallback, when there is one — is named in dropped and excluded from
// releases, without aborting resolution of the other, resolvable tag.
func TestResolveReleases_UnresolvableDateIsDroppedNotFatal(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, refsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 2,
			"value": []map[string]any{
				{"name": "refs/tags/v1.0.0", "objectId": "tag-object-sha", "peeledObjectId": "commit-sha-1"},
				{"name": "refs/tags/v2.0.0", "objectId": "commit-sha-2"},
			},
		},
	})
	fx.Set("GET", azuredevops.HostCore, "/"+testOrg+"/"+testProject+"/_apis/git/repositories/"+testRepositoryID+"/annotatedtags/tag-object-sha", adofixture.Response{
		Status: http.StatusInternalServerError,
		Body:   map[string]any{"message": "TF400xxx: something went wrong"},
	})
	// The peeled-commit fallback ALSO fails here (no fixture registered for
	// commits/commit-sha-1) — v1.0.0 must still be dropped, not fatal.
	fx.Set("GET", azuredevops.HostCore, "/"+testOrg+"/"+testProject+"/_apis/git/repositories/"+testRepositoryID+"/commits/commit-sha-2", adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"committer": map[string]any{"date": "2026-02-10T00:00:00Z"}},
	})

	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)
	releases, dropped, err := ResolveReleases(context.Background(), client, testProject, testRepositoryID, "v*")
	if err != nil {
		t.Fatalf("ResolveReleases: %v", err)
	}
	if len(dropped) != 1 || dropped[0] != "v1.0.0" {
		t.Errorf("dropped = %v, want exactly [v1.0.0] (its annotated-tag lookup AND the peeled-commit fallback both failed)", dropped)
	}
	if len(releases) != 1 || releases[0].TagName != "v2.0.0" {
		t.Errorf("releases = %+v, want exactly [v2.0.0] (the resolvable one)", releases)
	}
}

// TestResolveReleases_ListTagsFailureIsFatal proves a failure of the
// top-level refs listing call itself (unlike a single tag's date
// resolution) surfaces as a real error, not a silently empty result.
func TestResolveReleases_ListTagsFailureIsFatal(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, refsPath(), adofixture.Response{
		Status: http.StatusInternalServerError,
		Body:   map[string]any{"message": "TF400xxx: something went wrong"},
	})
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)

	_, _, err := ResolveReleases(context.Background(), client, testProject, testRepositoryID, "v*")
	if err == nil {
		t.Fatal("ResolveReleases() = nil error, want an error when the refs listing call itself fails")
	}
}

// TestAdoDate_DecodesTimezoneLessForm pins the [fixture-verify] leniency:
// the official Annotated Tags - Get sample response itself shows a
// timezone-less date ("2017-06-22T04:28:23"), which Go's default RFC3339
// decode rejects outright — adoDate must accept both that form (treated as
// UTC) and an ordinary RFC3339 value with an explicit "Z"/offset.
func TestAdoDate_DecodesTimezoneLessForm(t *testing.T) {
	tests := []struct {
		name string
		json string
		want time.Time
	}{
		{
			name: "RFC3339 with Z",
			json: `"2026-01-05T00:00:00Z"`,
			want: time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "timezone-less form from the official sample response, treated as UTC",
			json: `"2017-06-22T04:28:23"`,
			want: time.Date(2017, 6, 22, 4, 28, 23, 0, time.UTC),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d adoDate
			if err := d.UnmarshalJSON([]byte(tt.json)); err != nil {
				t.Fatalf("UnmarshalJSON(%s): %v", tt.json, err)
			}
			if !d.Equal(tt.want) {
				t.Errorf("d.Time = %v, want %v", d.Time, tt.want)
			}
		})
	}
}

// TestAdoDate_RejectsGarbage proves a genuinely malformed date string is a
// decode error, not a silently zero time.
func TestAdoDate_RejectsGarbage(t *testing.T) {
	var d adoDate
	if err := d.UnmarshalJSON([]byte(`"not-a-date"`)); err == nil {
		t.Fatal("UnmarshalJSON(\"not-a-date\") = nil error, want an error")
	}
}
