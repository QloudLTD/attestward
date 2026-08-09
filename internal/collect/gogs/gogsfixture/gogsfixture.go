// Package gogsfixture provides a recorded-fixture http.RoundTripper for
// testing Gogs API collectors without live network calls (CONTRIBUTING.md:
// "no live network calls in go test ./..."). It mirrors ghfixture and
// adofixture; the differences are noted on Transport below.
package gogsfixture

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
	// RawBody, when non-nil, is served verbatim instead of Body — for the
	// raw-file endpoint, whose real responses are file bytes rather than
	// JSON. Setting both is a test-authoring error and panics rather than
	// silently preferring one: a fixture that serves something other than
	// what its author believes it serves is worse than a failing test.
	RawBody []byte
}

// ErrNoFixture is returned (wrapped) when a request has no matching
// registered fixture — a loud failure instead of a silent real network
// call.
var ErrNoFixture = fmt.Errorf("gogsfixture: no fixture registered for request")

// Transport serves canned Responses keyed by "METHOD path", where path is
// the full request path INCLUDING the /api/v1 prefix and any instance
// suburl — i.e. exactly what the client actually requested. This differs
// from ghfixture, whose keys are bare paths, and it is deliberate: a Gogs
// base URL may carry a suburl prefix, so a fixture keyed on the bare path
// would pass while the client was in fact requesting something else, and
// the suburl-joining bug this project specifically cares about would go
// undetected by every test.
//
// Safe for concurrent use, so it works with a per-repo worker pool.
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

// Set registers a single response for every request matching "METHOD path".
func (t *Transport) Set(method, path string, resp Response) {
	t.SetSequence(method, path, resp)
}

// SetSequence registers responses served in order for successive requests
// to the same key; the last one repeats once the sequence is exhausted.
// Used to exercise retry behavior (a 500 followed by a 200).
func (t *Transport) SetSequence(method, path string, responses ...Response) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, r := range responses {
		if r.Body != nil && r.RawBody != nil {
			panic("gogsfixture: Response has both Body and RawBody set")
		}
	}
	t.sequences[method+" "+path] = responses
}

// Calls returns every "METHOD path" served so far, in order — so a test can
// assert not just what a collector concluded but which endpoints it
// actually consulted to conclude it.
func (t *Transport) Calls() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string{}, t.calls...)
}

// RoundTrip serves the registered response for the request's method and
// full path, or fails with ErrNoFixture — never a real network call.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.Method + " " + req.URL.Path

	t.mu.Lock()
	responses, ok := t.sequences[key]
	if ok {
		t.calls = append(t.calls, key)
		if len(responses) > 1 {
			t.sequences[key] = responses[1:]
		}
	}
	t.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoFixture, key)
	}

	resp := responses[0]
	body := resp.RawBody
	if body == nil && resp.Body != nil {
		b, err := json.Marshal(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gogsfixture: marshal body for %s: %w", key, err)
		}
		body = b
	}

	header := http.Header{}
	for k, v := range resp.Headers {
		header.Set(k, v)
	}
	return &http.Response{
		StatusCode: resp.Status,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}, nil
}
