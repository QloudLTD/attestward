package github

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/sioakim/attestward/internal/collect/github/ghfixture"
)

// TestTokenNeverLeaksIntoErrors exercises go-github's own error-wrapping Do
// method (which formats *github.ErrorResponse strings including the request
// URL and response body) against a failing request, and confirms the token
// appears nowhere in the resulting error — per the threat model, a token
// must never reach a log line or an evidence pack through any path,
// including error formatting we don't directly control.
func TestTokenNeverLeaksIntoErrors(t *testing.T) {
	const token = "ghp_should-never-appear-in-any-error-string-anywhere"
	fx := ghfixture.New().Set("GET", "/repos/attestward-demo/missing-repo", ghfixture.Response{
		Status: http.StatusNotFound,
		Body:   map[string]any{"message": "Not Found", "documentation_url": "https://docs.github.com/rest"},
	})
	client := newTestClient(t, token, fx)

	req, err := client.REST.NewRequest(http.MethodGet, "repos/attestward-demo/missing-repo", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	_, doErr := client.REST.Do(context.Background(), req, nil)
	if doErr == nil {
		t.Fatal("Do() = nil error, want a 404 error to inspect")
	}
	if strings.Contains(doErr.Error(), token) {
		t.Fatalf("token leaked into go-github error string: %v", doErr)
	}

	for _, p := range client.Provenance() {
		if strings.Contains(p.Endpoint, token) {
			t.Errorf("token leaked into Provenance.Endpoint: %q", p.Endpoint)
		}
	}
}
