package gitlab

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
// for any request whose method isn't GET or HEAD. This tool is read-only,
// forever (ADR-0004), and that invariant is enforced in the transport rather
// than trusted to every collector: a collector is where a mistake is easy to
// make and hard to see, and one accidental POST against a customer's GitLab
// would be a breach of the promise the whole evidence pack rests on.
var ErrWriteMethodRejected = fmt.Errorf("collect/gitlab: this tool is read-only, forever (ADR-0004)")

// userAgent is sent on every request. As with the Gogs package this is not
// cosmetic: a self-managed GitLab published through a WAF or Cloudflare with
// bot protection enabled will answer 403 to a library's default User-Agent,
// before the request reaches GitLab at all — a failure that presents as a
// broken token or a missing endpoint rather than what it is. Sending a real
// identifier removes a whole class of misdiagnosis. It does not, and is not
// meant to, disguise the client as a browser.
const userAgent = "attestward"

// authHeader is GitLab's token header. Note it is NOT "Authorization:
// Bearer" — that form exists but means an OAuth2 token, not a personal or
// group access token, and sending a PAT that way returns 401 with a message
// that does not mention the header at all. PRIVATE-TOKEN accepts personal,
// project and group access tokens uniformly, which is what every collector
// here is given.
const authHeader = "PRIVATE-TOKEN"

// provenanceTransport injects auth and records one model.Provenance entry per
// real HTTP call, including each retried attempt — a retry is a distinct call
// that really happened, and an evidence pack that hid it would misrepresent
// what the tool did.
type provenanceTransport struct {
	token string
	base  http.RoundTripper

	mu      sync.Mutex
	entries []model.Provenance
}

func newProvenanceTransport(token string, base http.RoundTripper) *provenanceTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &provenanceTransport{token: token, base: base}
}

func (t *provenanceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return nil, fmt.Errorf("%w: refusing %s %s", ErrWriteMethodRejected, req.Method, req.URL.Path)
	}

	// Clone before mutating: RoundTrip must not modify the caller's request.
	r := req.Clone(req.Context())
	if t.token != "" {
		r.Header.Set(authHeader, t.token)
	}
	r.Header.Set("User-Agent", userAgent)
	r.Header.Set("Accept", "application/json")

	start := time.Now().UTC()
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		// A transport-level failure produced no HTTP status and no body, so
		// there is nothing honest to hash. Record the attempt with status 0
		// rather than omitting it: "we tried and the network failed" is
		// materially different from "we never asked".
		t.record(model.Provenance{
			Endpoint:  req.URL.Path,
			Method:    req.Method,
			Timestamp: start,
		})
		return nil, err
	}

	// Hash the body so the pack can prove which bytes a conclusion came from,
	// then put it back for the caller. Reading it here is the only way to
	// hash it, so the body must be replaced rather than consumed.
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))

	sum := sha256.Sum256(body)
	t.record(model.Provenance{
		Endpoint:       req.URL.Path,
		Method:         req.Method,
		Timestamp:      start,
		HTTPStatus:     resp.StatusCode,
		ResponseSHA256: hex.EncodeToString(sum[:]),
	})
	return resp, nil
}

func (t *provenanceTransport) record(e model.Provenance) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = append(t.entries, e)
}

// Provenance returns a copy of everything recorded so far. A copy, not the
// slice itself, so a caller marshalling the pack cannot race a collector
// still making calls.
func (t *provenanceTransport) Provenance() []model.Provenance {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]model.Provenance, len(t.entries))
	copy(out, t.entries)
	return out
}
