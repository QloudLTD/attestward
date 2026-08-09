package github

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect/github/ghfixture"
)

func TestProvenanceTransportInjectsAuthAndRecordsProvenance(t *testing.T) {
	fx := ghfixture.New().Set("GET", "/orgs/attestward-demo", ghfixture.Response{
		Status: 200,
		Body:   map[string]any{"login": "attestward-demo"},
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

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.github.com/orgs/attestward-demo?ignored=1", nil)
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
	if entry.Endpoint != "/orgs/attestward-demo" {
		t.Errorf("Endpoint = %q, want %q (query string must not leak in)", entry.Endpoint, "/orgs/attestward-demo")
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
	fx := ghfixture.New().SetSequence("GET", "/repos/attestward-demo/good-repo",
		ghfixture.Response{Status: 200, Body: map[string]any{"attempt": 1}},
		ghfixture.Response{Status: 200, Body: map[string]any{"attempt": 2}},
	)
	prov := newProvenanceTransport("tok", fx)
	client := &http.Client{Transport: prov}

	for i := 0; i < 2; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.github.com/repos/attestward-demo/good-repo", nil)
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

// TestProvenanceTransportRejectsWriteMethods pins issue #31's read-only
// enforcement: any method other than GET/HEAD must be rejected before it
// ever reaches the underlying transport (a real network call, or in this
// test, the base RoundTripper at all) — proving the rejection happens at
// the guard itself, not just that the fixture never got asked to respond
// to a write it wasn't configured for.
func TestProvenanceTransportRejectsWriteMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			baseHit := false
			base := roundTripFunc(func(*http.Request) (*http.Response, error) {
				baseHit = true
				t.Fatalf("base transport was reached for a %s request — the guard must reject before any network call", method)
				return nil, nil
			})

			prov := newProvenanceTransport("tok", base)
			client := &http.Client{Transport: prov}

			req, err := http.NewRequestWithContext(context.Background(), method, "https://api.github.com/repos/attestward-demo/good-repo", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			_, err = client.Do(req)
			if err == nil {
				t.Fatalf("%s request: got nil error, want a rejection", method)
			}
			if !errors.Is(err, ErrWriteMethodRejected) {
				t.Errorf("%s request error = %v, want it to wrap ErrWriteMethodRejected", method, err)
			}
			if baseHit {
				t.Error("base transport was reached — see the Fatalf above")
			}
			if len(prov.Provenance()) != 0 {
				t.Error("a rejected write request was still recorded in Provenance — it never happened, so it must not appear as evidence of anything")
			}
		})
	}
}

// TestProvenanceTransportAllowsHead confirms the guard's allow-list is
// exactly {GET, HEAD}, not GET alone — HEAD is a legitimate read method
// (used, for example, to check resource existence without a body) and
// must not be caught by a guard meant only to block writes.
func TestProvenanceTransportAllowsHead(t *testing.T) {
	fx := ghfixture.New().Set("HEAD", "/repos/attestward-demo/good-repo", ghfixture.Response{Status: 200})
	prov := newProvenanceTransport("tok", fx)
	client := &http.Client{Transport: prov}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, "https://api.github.com/repos/attestward-demo/good-repo", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HEAD request: %v", err)
	}
	_ = resp.Body.Close()

	if len(prov.Provenance()) != 1 {
		t.Errorf("len(Provenance()) = %d, want 1 (HEAD is a read method and must be allowed through)", len(prov.Provenance()))
	}
}

// roundTripFunc adapts a function to http.RoundTripper for test wiring.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
