// Package adofixture provides a recorded-fixture http.RoundTripper for
// testing Azure DevOps API collectors without live network calls
// (CONTRIBUTING.md: "no live network calls in go test ./...").
//
// Unlike ghfixture (GitHub's twin, keyed by "METHOD path"), fixtures here
// are keyed by "METHOD host path" — three parts, not two — because a
// single ADO scan spreads across multiple hosts (dev.azure.com,
// vssps.dev.azure.com, advsec.dev.azure.com, auditservice.dev.azure.com); a
// path alone would collide across them (see
// internal/collect/azuredevops/transport.go's Endpoint field for the same
// reasoning applied to provenance).
package adofixture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// Response is one canned HTTP response.
type Response struct {
	Status  int
	Headers map[string]string
	// Body is marshaled to JSON when the Transport serves it. Leave nil
	// for an empty body.
	Body any
}

// ErrNoFixture is returned (wrapped) when a request has no matching
// registered fixture — a loud failure instead of a silent real network
// call.
var ErrNoFixture = fmt.Errorf("adofixture: no fixture registered for request")

// Transport serves canned Responses keyed by "METHOD host path" (query
// strings aren't matched — provenance recording deliberately drops them
// too). Safe for concurrent use.
type Transport struct {
	mu        sync.Mutex
	sequences map[string][]Response
	calls     []string
}

// New returns an empty Transport; register responses with Set/SetSequence
// before using it.
func New() *Transport {
	return &Transport{sequences: map[string][]Response{}}
}

// Set registers a single canned response for method+host+path, served for
// every matching request (the same response repeats).
func (t *Transport) Set(method, host, path string, resp Response) *Transport {
	return t.SetSequence(method, host, path, resp)
}

// SetSequence registers an ordered sequence of responses for
// method+host+path, consumed one at a time as matching requests arrive —
// useful for testing retry/delay behavior (e.g. a 429 followed by a
// success). Once only one response remains in the sequence, it repeats for
// any further matching requests rather than erroring.
func (t *Transport) SetSequence(method, host, path string, responses ...Response) *Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sequences[key(method, host, path)] = responses
	return t
}

// Calls returns every "METHOD host path" this transport has served, in the
// order requests arrived — useful for asserting retry counts.
func (t *Transport) Calls() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string{}, t.calls...)
}

// RoundTrip implements http.RoundTripper by serving the registered fixture
// for req's method+host+path, or ErrNoFixture if none matches.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	k := key(req.Method, req.URL.Host, req.URL.Path)

	t.mu.Lock()
	t.calls = append(t.calls, k)
	queue := t.sequences[k]
	if len(queue) == 0 {
		callNum := len(t.calls)
		t.mu.Unlock()
		return nil, fmt.Errorf("%w: %s (call #%d)", ErrNoFixture, k, callNum)
	}
	resp := queue[0]
	if len(queue) > 1 {
		t.sequences[k] = queue[1:]
	}
	t.mu.Unlock()

	var bodyBytes []byte
	if resp.Body != nil {
		b, err := json.Marshal(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("adofixture: marshal body for %s: %w", k, err)
		}
		bodyBytes = b
	}

	header := http.Header{}
	for hk, v := range resp.Headers {
		header.Set(hk, v)
	}

	return &http.Response{
		StatusCode: resp.Status,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
		Request:    req,
	}, nil
}

func key(method, host, path string) string {
	return method + " " + host + " " + path
}
