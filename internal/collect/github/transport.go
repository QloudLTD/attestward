package github

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"gitlab.com/sioakeim/attestward/internal/model"
)

// ErrWriteMethodRejected is returned (wrapped) by provenanceTransport.RoundTrip
// for any request whose method isn't GET or HEAD — see its own doc comment.
var ErrWriteMethodRejected = fmt.Errorf("collect/github: this tool is read-only, forever (ADR-0004)")

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
//
// GHES provenance paths (issue #13's GHES epic, settling the question its
// own acceptance criteria pose): Endpoint records req.URL.Path completely
// unmodified — the REAL path, not a github.com-normalized one. On a GHES
// scan this naturally comes out prefixed "/api/v3" (e.g.
// "/api/v3/orgs/{org}"), because go-github's request builder resolves
// every relative endpoint path against Client.BaseURL (see
// ghcollect.NewClient/ResolveHostConfig, issue #11), and BaseURL already
// carries that prefix for a GHES target. No special-casing was needed here
// to make that happen, and none should be added to normalize it away: a
// provenance entry should record what was ACTUALLY called, since that's
// what a reader (or `attestward diff`, comparing provenance across two
// packs) needs to trust the evidence — normalizing away the "/api/v3"
// prefix would make a GHES pack's provenance describe a request that
// never actually happened.
//
// Read-only enforcement (issue #31): RoundTrip rejects any request whose
// method isn't GET or HEAD, before auth injection or the network call —
// ADR-0004's "read-only, forever" rule enforced structurally, not just by
// code review. This is Client's single shared transport for both the REST
// client and the GraphQL client (see NewClient's doc comment), so it also
// covers GraphQL — deliberately without distinguishing a GraphQL "query"
// operation from a "mutation" one, since both travel as an HTTP POST and
// nothing in this codebase issues either today (no collector calls
// Client.GraphQL as of this writing — see docs/threat-model.md). A rejected
// POST is the correct, honest behavior for an unused code path: the first
// attempt to add a real GraphQL query would need to extend this guard
// deliberately (e.g. inspecting the request body for a leading "query"
// keyword), not have it silently pass because the transport never checked.
// Building that allow-list now, before anything needs it, would be
// speculative engineering for a code path this project doesn't use.
type provenanceTransport struct {
	base        http.RoundTripper
	token       string
	scopes      *scopeTracker
	hostVersion *hostVersionTracker

	mu         sync.Mutex
	provenance []model.Provenance
}

func newProvenanceTransport(token string, base http.RoundTripper) *provenanceTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &provenanceTransport{base: base, token: token, scopes: &scopeTracker{}, hostVersion: &hostVersionTracker{}}
}

func (t *provenanceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return nil, fmt.Errorf("%w: refusing %s %s", ErrWriteMethodRejected, req.Method, req.URL.Path)
	}

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
	t.hostVersion.observe(resp)

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
