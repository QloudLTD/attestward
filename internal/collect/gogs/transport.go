package gogs

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
var ErrWriteMethodRejected = fmt.Errorf("collect/gogs: this tool is read-only, forever (ADR-0004)")

// userAgent is sent on every request. It is not cosmetic: a Gogs instance
// published through Cloudflare with Browser Integrity Check enabled answers
// 403 to the default User-Agent of most HTTP libraries, and does so before
// the request reaches Gogs at all — a failure that reads like a broken
// token or a missing endpoint rather than what it is. Sending a real
// identifier avoids an entire class of misdiagnosis; it does not, and is
// not meant to, disguise the client as a browser.
const userAgent = "attestward"

// provenanceTransport wraps an http.RoundTripper: it injects token auth on
// every request and records a model.Provenance entry for every response.
// Safe for concurrent use — a per-repo worker pool issues requests from
// many goroutines at once.
//
// Token handling per the threat model: the token lives only in this
// struct's field and the Authorization header of outgoing requests; it is
// never written to Provenance, never logged, and Endpoint deliberately
// records the request path only (no host, no query string, no fragment).
// Dropping the query string keeps a secret accidentally placed in a
// parameter out of an evidence pack; dropping the host keeps a private
// instance's internal address out of one — see this package's doc comment
// for why that second omission matters more here than on a hosted platform.
//
// Read-only enforcement: RoundTrip rejects any request whose method isn't
// GET or HEAD, before auth injection and before the network call. This is
// ADR-0004's "read-only, forever" rule enforced structurally rather than by
// code review, matching internal/collect/github/transport.go and its Azure
// DevOps twin. Gogs' API would happily accept a POST — it can create repos,
// issues and webhooks — which is precisely why the guard belongs at the
// only layer every collector in this package must pass through.
type provenanceTransport struct {
	base  http.RoundTripper
	token string

	mu         sync.Mutex
	provenance []model.Provenance
}

func newProvenanceTransport(token string, base http.RoundTripper) *provenanceTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &provenanceTransport{base: base, token: token}
}

func (t *provenanceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return nil, fmt.Errorf("%w: refusing %s %s", ErrWriteMethodRejected, req.Method, req.URL.Path)
	}

	req = req.Clone(req.Context())
	if t.token != "" {
		// "token <t>", not "Bearer <t>": Gogs' own scheme. A Bearer
		// header is ignored rather than rejected, which surfaces as an
		// unauthenticated response — a 404 on a private repo — instead
		// of a 401, so getting this wrong looks like a missing repo.
		req.Header.Set("Authorization", "token "+t.token)
	}
	req.Header.Set("User-Agent", userAgent)

	start := time.Now().UTC()
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}

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
