package github

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/sioakim/ssdf/internal/collect/github/ghfixture"
)

func TestProvenanceTransportInjectsAuthAndRecordsProvenance(t *testing.T) {
	fx := ghfixture.New().Set("GET", "/orgs/attestor-demo", ghfixture.Response{
		Status: 200,
		Body:   map[string]any{"login": "attestor-demo"},
	})

	// Sits between provenanceTransport and the fixture, capturing the
	// Authorization header provenanceTransport injects before delegating.
	var gotAuth string
	capture := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotAuth = req.Header.Get("Authorization")
		return fx.RoundTrip(req)
	})

	const token = "ghp_test-token-should-never-leak-into-provenance"
	prov := newProvenanceTransport(token, capture)
	client := &http.Client{Transport: prov}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.github.com/orgs/attestor-demo?ignored=1", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if gotAuth != "Bearer "+token {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer "+token)
	}

	entries := prov.Provenance()
	if len(entries) != 1 {
		t.Fatalf("len(Provenance()) = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Endpoint != "/orgs/attestor-demo" {
		t.Errorf("Endpoint = %q, want %q (query string must not leak in)", entry.Endpoint, "/orgs/attestor-demo")
	}
	if entry.Method != "GET" {
		t.Errorf("Method = %q, want GET", entry.Method)
	}
	if entry.HTTPStatus != 200 {
		t.Errorf("HTTPStatus = %d, want 200", entry.HTTPStatus)
	}
	if entry.ResponseSHA256 == "" {
		t.Error("ResponseSHA256 is empty")
	}
	if strings.Contains(entry.Endpoint, token) {
		t.Error("token leaked into Provenance.Endpoint")
	}
}

func TestProvenanceTransportRecordsEveryRetryAsItsOwnEntry(t *testing.T) {
	fx := ghfixture.New().SetSequence("GET", "/repos/attestor-demo/good-repo",
		ghfixture.Response{Status: 200, Body: map[string]any{"attempt": 1}},
		ghfixture.Response{Status: 200, Body: map[string]any{"attempt": 2}},
	)
	prov := newProvenanceTransport("tok", fx)
	client := &http.Client{Transport: prov}

	for i := 0; i < 2; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.github.com/repos/attestor-demo/good-repo", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do #%d: %v", i, err)
		}
		_ = resp.Body.Close()
	}

	if got := len(prov.Provenance()); got != 2 {
		t.Fatalf("len(Provenance()) = %d, want 2 (one entry per call, including retries)", got)
	}
}

// roundTripFunc adapts a function to http.RoundTripper for test wiring.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
