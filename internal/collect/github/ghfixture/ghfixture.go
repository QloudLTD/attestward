// Package ghfixture provides a recorded-fixture http.RoundTripper for
// testing GitHub API collectors without live network calls
// (CONTRIBUTING.md: "no live network calls in go test ./...").
package ghfixture

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
var ErrNoFixture = fmt.Errorf("ghfixture: no fixture registered for request")

// Transport serves canned Responses keyed by "METHOD path" (path only, no
// query string or host — matches how the provenance transport in
// internal/collect/github records endpoints). Safe for concurrent use, so
// it works with ForEachRepo's worker pool in tests.
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

// Set registers a single canned response for method+path, served for every
// matching request (the same response repeats).
func (t *Transport) Set(method, path string, resp Response) *Transport {
	return t.SetSequence(method, path, resp)
}

// SetSequence registers an ordered sequence of responses for method+path,
// consumed one at a time as matching requests arrive — useful for testing
// retry behavior (e.g. a rate-limited response followed by a success). Once
// only one response remains in the sequence, it repeats for any further
// matching requests rather than erroring.
func (t *Transport) SetSequence(method, path string, responses ...Response) *Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sequences[method+" "+path] = responses
	return t
}

// Calls returns every "METHOD path" this transport has served, in the order
// requests arrived — useful for asserting retry counts.
func (t *Transport) Calls() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string{}, t.calls...)
}

// RoundTrip implements http.RoundTripper by serving the registered fixture
// for req's method+path, or ErrNoFixture if none matches.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.Method + " " + req.URL.Path

	t.mu.Lock()
	t.calls = append(t.calls, key)
	queue := t.sequences[key]
	if len(queue) == 0 {
		callNum := len(t.calls)
		t.mu.Unlock()
		return nil, fmt.Errorf("%w: %s (call #%d)", ErrNoFixture, key, callNum)
	}
	resp := queue[0]
	if len(queue) > 1 {
		t.sequences[key] = queue[1:]
	}
	t.mu.Unlock()

	var bodyBytes []byte
	if resp.Body != nil {
		b, err := json.Marshal(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("ghfixture: marshal body for %s: %w", key, err)
		}
		bodyBytes = b
	}

	header := http.Header{}
	for k, v := range resp.Headers {
		header.Set(k, v)
	}

	return &http.Response{
		StatusCode: resp.Status,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
		Request:    req,
	}, nil
}
