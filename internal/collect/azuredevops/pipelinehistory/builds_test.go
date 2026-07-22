package pipelinehistory

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/collect/azuredevops/adofixture"
)

func buildsPath() string {
	return "/" + testOrg + "/" + testProject + "/_apis/build/builds"
}

// TestFetchBuilds_DecodesFields proves the Build shape decodes into
// RunInfo's own field names correctly.
func TestFetchBuilds_DecodesFields(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostCore, buildsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 1,
			"value": []map[string]any{
				{
					"sourceVersion": "abc123",
					"sourceBranch":  "refs/heads/main",
					"result":        "succeeded",
					"queueTime":     "2026-03-01T12:00:00Z",
				},
			},
		},
	})
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)

	runs, err := FetchBuilds(context.Background(), client, testProject, testRepositoryID, nil, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("FetchBuilds: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1", len(runs))
	}
	got := runs[0]
	if got.SourceVersion != "abc123" || got.SourceBranch != "refs/heads/main" || got.Result != "succeeded" {
		t.Errorf("runs[0] = %+v, want {abc123 refs/heads/main succeeded ...}", got)
	}
	wantQueueTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	if !got.QueueTime.Equal(wantQueueTime) {
		t.Errorf("QueueTime = %v, want %v", got.QueueTime, wantQueueTime)
	}
}

// TestFetchBuilds_SendsRepositoryScopedQueryParams pins the exact query
// parameters this project relies on: repositoryId, repositoryType=TfsGit,
// minTime, and queryOrder=queueTimeDescending (without which minTime binds
// on finish time server-side, not queue time, per FetchBuilds' own doc
// comment) — and confirms NO sourceVersion parameter is ever sent (there
// is none to send — see FetchBuilds' doc comment).
func TestFetchBuilds_SendsRepositoryScopedQueryParams(t *testing.T) {
	var gotQuery url.Values
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, buildsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"count": 0, "value": []map[string]any{}},
	})
	capture := &queryCapturingTransport{base: fx}
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", capture)

	since := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	if _, err := FetchBuilds(context.Background(), client, testProject, testRepositoryID, []int{7, 9}, since); err != nil {
		t.Fatalf("FetchBuilds: %v", err)
	}
	gotQuery = capture.lastQuery

	if got := gotQuery.Get("repositoryId"); got != testRepositoryID {
		t.Errorf("repositoryId = %q, want %q", got, testRepositoryID)
	}
	if got := gotQuery.Get("repositoryType"); got != "TfsGit" {
		t.Errorf("repositoryType = %q, want TfsGit", got)
	}
	if got := gotQuery.Get("minTime"); got != "2026-03-15T00:00:00Z" {
		t.Errorf("minTime = %q, want 2026-03-15T00:00:00Z", got)
	}
	if got := gotQuery.Get("queryOrder"); got != "queueTimeDescending" {
		t.Errorf("queryOrder = %q, want queueTimeDescending (without it, minTime binds on finish time server-side, not queue time)", got)
	}
	if got := gotQuery.Get("definitions"); got != "7,9" {
		t.Errorf("definitions = %q, want \"7,9\" (comma-delimited, both IDs in one call)", got)
	}
	if gotQuery.Has("sourceVersion") {
		t.Error("sourceVersion query param present — Builds List has no such parameter (verified against the full documented list); matching must be client-side")
	}
}

// TestFetchBuilds_NoDefinitionFilterOmitsParam proves an empty
// definitionIDs list fetches every build for the repository, unfiltered
// by definition — the `definitions` param must not appear at all (an
// empty string value would filter to zero definitions, not "no filter").
func TestFetchBuilds_NoDefinitionFilterOmitsParam(t *testing.T) {
	capture := &queryCapturingTransport{base: adofixture.New().Set("GET", azuredevops.HostCore, buildsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"count": 0, "value": []map[string]any{}},
	})}
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", capture)

	if _, err := FetchBuilds(context.Background(), client, testProject, testRepositoryID, nil, time.Time{}); err != nil {
		t.Fatalf("FetchBuilds: %v", err)
	}
	if capture.lastQuery.Has("definitions") {
		t.Error("definitions query param present for a nil definitionIDs list, want it omitted entirely")
	}
}

// queryCapturingTransport records the query parameters of the last request
// that reached it — used to assert on FetchBuilds' exact query shape,
// mirroring runhistory's identical need (its own capturingTransport tests
// continuation tokens; this one tests the full query).
type queryCapturingTransport struct {
	base      http.RoundTripper
	lastQuery url.Values
}

func (c *queryCapturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.lastQuery = req.URL.Query()
	return c.base.RoundTrip(req)
}
