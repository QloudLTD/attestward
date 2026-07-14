package sasthistory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
)

// TestFetchWorkflowRuns_SendsServerSideCreatedFilter pins the rate-limit
// mitigation documented on fetchWorkflowRuns: the Created filter must
// actually reach GitHub as a ">=YYYY-MM-DD" query param, not just be set
// on the request struct and silently dropped or malformed in transit.
// Previously nothing in this package asserted the outgoing request at all.
func TestFetchWorkflowRuns_SendsServerSideCreatedFilter(t *testing.T) {
	var gotCreated string
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestor-demo/repo-a/actions/workflows/1/runs", func(w http.ResponseWriter, r *http.Request) {
		gotCreated = r.URL.Query().Get("created")
		writeJSON(t, w, http.StatusOK, map[string]any{"total_count": 0, "workflow_runs": []any{}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := ghcollect.NewClient("ghp_test-token")
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	client.REST.BaseURL = baseURL

	since := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	if _, err := fetchWorkflowRuns(context.Background(), client, "attestor-demo", "repo-a", 1, since); err != nil {
		t.Fatalf("fetchWorkflowRuns: %v", err)
	}

	want := ">=2026-03-15"
	if gotCreated != want {
		t.Errorf("created query param = %q, want %q", gotCreated, want)
	}
}
