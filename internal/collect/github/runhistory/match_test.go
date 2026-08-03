package runhistory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/mappings"
)

func newTestClient(t *testing.T, mux *http.ServeMux) *ghcollect.Client {
	t.Helper()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := ghcollect.NewClient("ghp_test-token", ghcollect.ClientConfig{})
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	client.REST.BaseURL = baseURL
	return client
}

const codeqlWorkflowYAML = `name: CodeQL
on: [push]
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/analyze@v4
`

const trivyWorkflowYAML = `name: Trivy
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/trivy-action@0.24.0
`

// TestListWorkflowsAndMatchWorkflows_CategoryFiltering proves ListWorkflows
// + MatchWorkflows together reproduce what C05's fetchAndMatchWorkflows
// used to do (minus the CodeQL default-setup special case, deliberately
// left to callers) — a repo with one SAST workflow and one SCA workflow
// only matches the one requested via the category parameter.
func TestListWorkflowsAndMatchWorkflows_CategoryFiltering(t *testing.T) {
	registry, err := mapping.LoadScannerSignaturesFS(mappings.FS, "scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignaturesFS: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/mixed-repo/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 2,
			"workflows": []map[string]any{
				{"id": 1, "name": "CodeQL", "path": ".github/workflows/codeql.yml", "state": "active"},
				{"id": 2, "name": "Trivy", "path": ".github/workflows/trivy.yml", "state": "active"},
			},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/mixed-repo/contents/.github/workflows/codeql.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"content": codeqlWorkflowYAML, "sha": "sha-codeql"})
	})
	mux.HandleFunc("/repos/attestward-demo/mixed-repo/contents/.github/workflows/trivy.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"content": trivyWorkflowYAML, "sha": "sha-trivy"})
	})

	client := newTestClient(t, mux)

	workflows, resp, err := ListWorkflows(context.Background(), client, "attestward-demo", "mixed-repo")
	if err != nil {
		t.Fatalf("ListWorkflows: %v", err)
	}
	if resp != nil {
		t.Errorf("ListWorkflows response = %+v, want nil on success", resp)
	}
	if len(workflows) != 2 {
		t.Fatalf("len(workflows) = %d, want 2", len(workflows))
	}

	sastMatches, sastSkipped := MatchWorkflows(context.Background(), client, registry, "attestward-demo", "mixed-repo", "main", workflows, mapping.CategorySAST)
	if len(sastMatches) != 1 || sastMatches[0].Path != ".github/workflows/codeql.yml" {
		t.Errorf("SAST matches = %+v, want exactly the CodeQL workflow", sastMatches)
	}
	if len(sastSkipped) != 0 {
		t.Errorf("SAST skipped = %+v, want none — both workflows were readable", sastSkipped)
	}

	scaMatches, scaSkipped := MatchWorkflows(context.Background(), client, registry, "attestward-demo", "mixed-repo", "main", workflows, mapping.CategorySCA)
	if len(scaMatches) != 1 || scaMatches[0].Path != ".github/workflows/trivy.yml" {
		t.Errorf("SCA matches = %+v, want exactly the Trivy workflow", scaMatches)
	}
	if len(scaSkipped) != 0 {
		t.Errorf("SCA skipped = %+v, want none — both workflows were readable", scaSkipped)
	}
}

// TestMatchWorkflows_UnreadableWorkflowIsSkippedNotFatal proves an
// individual workflow whose content can't be fetched doesn't abort the
// whole batch — the other, readable workflow must still be matched — and
// that the unreadable one is recorded in the skipped return (issue #178),
// not silently dropped as if it simply had no match.
func TestMatchWorkflows_UnreadableWorkflowIsSkippedNotFatal(t *testing.T) {
	registry, err := mapping.LoadScannerSignaturesFS(mappings.FS, "scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignaturesFS: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/flaky-repo/contents/.github/workflows/gone.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
	mux.HandleFunc("/repos/attestward-demo/flaky-repo/contents/.github/workflows/codeql.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"content": codeqlWorkflowYAML, "sha": "sha-codeql"})
	})

	client := newTestClient(t, mux)
	workflows := []*ghgithub.Workflow{
		{ID: ghgithub.Ptr(int64(1)), Path: ghgithub.Ptr(".github/workflows/gone.yml")},
		{ID: ghgithub.Ptr(int64(2)), Path: ghgithub.Ptr(".github/workflows/codeql.yml")},
	}

	matches, skipped := MatchWorkflows(context.Background(), client, registry, "attestward-demo", "flaky-repo", "main", workflows, mapping.CategorySAST)
	if len(matches) != 1 || matches[0].Path != ".github/workflows/codeql.yml" {
		t.Errorf("matches = %+v, want exactly the readable CodeQL workflow (the 404'd one skipped, not fatal)", matches)
	}
	if len(skipped) != 1 || skipped[0].Path != ".github/workflows/gone.yml" || skipped[0].Reason == "" {
		t.Errorf("skipped = %+v, want exactly one entry for gone.yml with a non-empty reason", skipped)
	}
}
