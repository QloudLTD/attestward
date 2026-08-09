package azuredevops

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
var ErrWriteMethodRejected = fmt.Errorf("collect/azuredevops: this tool is read-only, forever (ADR-0004)")

// provenanceTransport wraps an http.RoundTripper: it injects Basic-auth PAT
// on every request and records a model.Provenance entry for every response.
// Safe for concurrent use — collectors fan out across many goroutines, same
// as the GitHub client.
//
// Token handling per the threat model: the PAT lives only in this struct's
// field and the Authorization header of outgoing requests; it is never
// written to Provenance, never logged. Endpoint records host + path
// (deliberately no query string, no fragment — a token or other secret
// placed in a query parameter must never reach an evidence pack through
// this path). Host is included, unlike the GitHub twin's path-only Endpoint,
// because a single ADO scan spreads across several hosts (dev.azure.com,
// vssps.dev.azure.com, advsec.dev.azure.com, auditservice.dev.azure.com) —
// a path alone (e.g. "/org/_apis/projects") would be ambiguous about which
// of them it went to.
//
// Read-only enforcement (ADR-0004): RoundTrip rejects any request whose
// method isn't GET or HEAD, before auth injection or the network call —
// the same structural guard as internal/collect/github/transport.go's
// provenanceTransport, ported here as this package's own single choke
// point.
type provenanceTransport struct {
	base http.RoundTripper
	pat  string

	mu         sync.Mutex
	provenance []model.Provenance
}

func newProvenanceTransport(pat string, base http.RoundTripper) *provenanceTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &provenanceTransport{base: base, pat: pat}
}

func (t *provenanceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return nil, fmt.Errorf("%w: refusing %s %s%s", ErrWriteMethodRejected, req.Method, req.URL.Host, req.URL.Path)
	}

	req = req.Clone(req.Context())
	if t.pat != "" {
		// ADO PAT auth is HTTP Basic with an empty username: base64(":"+pat).
		req.SetBasicAuth("", t.pat)
	}

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
		Endpoint:       req.URL.Host + req.URL.Path,
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
