package github

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/sioakim/ssdf/internal/model"
)

// provenanceTransport wraps an http.RoundTripper: it injects bearer auth on
// every request and records a model.Provenance entry for every response.
// Safe for concurrent use — the per-repo worker pool issues requests from
// many goroutines at once.
//
// Token handling per the threat model: the token lives only in this
// struct's field and the Authorization header of outgoing requests; it is
// never written to Provenance, never logged, and Endpoint deliberately
// records the request path only (no query string, no fragment) so a token
// or other secret accidentally placed in a query parameter can never reach
// an evidence pack through this path — avoiding the leak is preferred over
// relying on model.Scrub to catch it downstream.
type provenanceTransport struct {
	base   http.RoundTripper
	token  string
	scopes *scopeTracker

	mu         sync.Mutex
	provenance []model.Provenance
}

func newProvenanceTransport(token string, base http.RoundTripper) *provenanceTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &provenanceTransport{base: base, token: token, scopes: &scopeTracker{}}
}

func (t *provenanceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}

	start := time.Now().UTC()
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	t.scopes.observe(resp)

	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if readErr != nil {
		return resp, readErr
	}

	sum := sha256.Sum256(body)
	entry := model.Provenance{
		Endpoint:       req.URL.Path,
		Method:         req.Method,
		Timestamp:      start,
		HTTPStatus:     resp.StatusCode,
		ResponseSHA256: hex.EncodeToString(sum[:]),
	}

	t.mu.Lock()
	t.provenance = append(t.provenance, entry)
	t.mu.Unlock()

	return resp, nil
}

// Provenance returns a copy of every request's provenance entry recorded so
// far, in call-completion order.
func (t *provenanceTransport) Provenance() []model.Provenance {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]model.Provenance{}, t.provenance...)
}
