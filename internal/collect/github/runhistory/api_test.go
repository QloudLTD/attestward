package runhistory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
)

func writeJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode fixture response: %v", err)
	}
}

// TestFetchWorkflowRuns_SendsServerSideCreatedFilter pins the rate-limit
// mitigation documented on FetchWorkflowRuns: the Created filter must
// actually reach GitHub as a ">=YYYY-MM-DD" query param, not just be set
// on the request struct and silently dropped or malformed in transit.
func TestFetchWorkflowRuns_SendsServerSideCreatedFilter(t *testing.T) {
	var gotCreated string
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/repo-a/actions/workflows/1/runs", func(w http.ResponseWriter, r *http.Request) {
		gotCreated = r.URL.Query().Get("created")
		writeJSON(t, w, http.StatusOK, map[string]any{"total_count": 0, "workflow_runs": []any{}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := ghcollect.NewClient("ghp_test-token", ghcollect.ClientConfig{})
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	client.REST.BaseURL = baseURL

	since := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	if _, err := FetchWorkflowRuns(context.Background(), client, "attestward-demo", "repo-a", 1, since); err != nil {
		t.Fatalf("FetchWorkflowRuns: %v", err)
	}

	want := ">=2026-03-15"
	if gotCreated != want {
		t.Errorf("created query param = %q, want %q", gotCreated, want)
	}
}
