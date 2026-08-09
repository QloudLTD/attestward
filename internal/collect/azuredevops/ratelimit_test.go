package azuredevops

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops/adofixture"
)

// noSleep replaces rateLimitTransport.sleep in tests so delay/retry logic is
// exercised without actually waiting real wall-clock time; it records each
// requested duration into log instead of sleeping.
func noSleep(log *[]time.Duration) func(time.Duration) {
	return func(actual time.Duration) {
		*log = append(*log, actual)
	}
}

// fakeClock replaces rateLimitTransport.now in tests: it lets a test control
// exactly how much (simulated) time has passed between requests, so
// deadline-vs-now assertions are deterministic instead of racing a real
// wall clock that noSleep otherwise leaves frozen.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// TestRateLimitTransport_RetryAfterOn200DelaysAllRequestsUntilDeadline pins
// the deadline-based semantics (not a one-shot "consume and clear"
// duration): a 200's Retry-After sets a delay deadline that every request
// arriving before it must honor — not just the first to observe it, since
// concurrent requests from the collector fan-out pool (a later PR) all race
// to read the same field — and a request arriving after the deadline has
// passed must sleep zero rather than over-sleeping by the original
// Retry-After value.
func TestRateLimitTransport_RetryAfterOn200DelaysAllRequestsUntilDeadline(t *testing.T) {
	fx := adofixture.New().SetSequence("GET", "dev.azure.com", "/org/_apis/projects",
		adofixture.Response{
			Status:  http.StatusOK,
			Headers: map[string]string{"Retry-After": "30"},
			Body:    map[string]any{"call": 1},
		},
		adofixture.Response{Status: http.StatusOK, Body: map[string]any{"call": 2}},
		adofixture.Response{Status: http.StatusOK, Body: map[string]any{"call": 3}},
		adofixture.Response{Status: http.StatusOK, Body: map[string]any{"call": 4}},
	)

	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	var slept []time.Duration
	rl := newRateLimitTransport(fx)
	rl.sleep = noSleep(&slept)
	rl.now = clock.Now

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://dev.azure.com/org/_apis/projects", nil)

	// Call 1: no pending delay yet; the 200's Retry-After sets a deadline
	// 30s out from the current fake time, but must not delay this request.
	resp1, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("call 1: %v", err)
	}
	_ = resp1.Body.Close()
	if len(slept) != 0 {
		t.Fatalf("len(slept) after call 1 = %d, want 0 (Retry-After on a 200 must not delay that same request)", len(slept))
	}

	// Calls 2 and 3 arrive with no simulated time passing between them (the
	// concurrent-request case) — both must observe the full remaining 30s,
	// proving the deadline isn't cleared after the first reader consumes it.
	resp2, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("call 2: %v", err)
	}
	_ = resp2.Body.Close()
	resp3, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("call 3: %v", err)
	}
	_ = resp3.Body.Close()

	if len(slept) != 2 {
		t.Fatalf("len(slept) after calls 2+3 = %d, want 2 (both must independently honor the pending deadline)", len(slept))
	}
	for i, d := range slept {
		if d != 30*time.Second {
			t.Errorf("slept[%d] = %v, want 30s (both requests observe the same undiminished deadline)", i, d)
		}
	}

	// Call 4 arrives after the deadline has passed: it must sleep zero, not
	// over-sleep by the original 30s Retry-After value.
	clock.Advance(30 * time.Second)
	resp4, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("call 4: %v", err)
	}
	_ = resp4.Body.Close()
	if len(slept) != 2 {
		t.Errorf("len(slept) after call 4 = %d, want still 2 (a request past the deadline sleeps zero — no new entry)", len(slept))
	}
}

// TestRateLimitedRetriesEachRecordTheirOwnProvenanceEntry mirrors the GitHub
// twin's TestProvenanceTransportRecordsEveryRetryAsItsOwnEntry: each 429
// retry is a distinct real call to the base transport, so
// provenanceTransport — layered beneath rateLimitTransport, the same order
// the client wiring in the next PR uses — must record one entry per
// attempt, not just the final result.
func TestRateLimitedRetriesEachRecordTheirOwnProvenanceEntry(t *testing.T) {
	fx := adofixture.New().SetSequence("GET", "dev.azure.com", "/org/_apis/projects",
		adofixture.Response{Status: http.StatusTooManyRequests, Headers: map[string]string{"Retry-After": "1"}},
		adofixture.Response{Status: http.StatusTooManyRequests, Headers: map[string]string{"Retry-After": "1"}},
		adofixture.Response{Status: http.StatusOK, Body: map[string]any{"count": 1}},
	)

	prov := newProvenanceTransport("ado-test-pat", fx)
	rl := newRateLimitTransport(prov)
	var slept []time.Duration
	rl.sleep = noSleep(&slept)

	client := &http.Client{Transport: rl}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://dev.azure.com/org/_apis/projects", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	entries := prov.Provenance()
	if len(entries) != 3 {
		t.Fatalf("len(Provenance()) = %d, want 3 (one entry per attempt, including both 429 retries)", len(entries))
	}
	wantStatuses := []int{http.StatusTooManyRequests, http.StatusTooManyRequests, http.StatusOK}
	for i, e := range entries {
		if e.HTTPStatus != wantStatuses[i] {
			t.Errorf("entries[%d].HTTPStatus = %d, want %d", i, e.HTTPStatus, wantStatuses[i])
		}
		if e.Endpoint != "dev.azure.com/org/_apis/projects" {
			t.Errorf("entries[%d].Endpoint = %q, want host-qualified path with no query string", i, e.Endpoint)
		}
	}
}

// TestRateLimitTransport_429RetriesUntilSuccessUsingRetryAfter proves a
// blocked (429) request is retried in place — unlike GitHub's secondary
// limit, ADO's block is a temporary sliding-window ceiling — waiting the
// exact Retry-After duration each time, not falling back to backoff while
// that header is present.
func TestRateLimitTransport_429RetriesUntilSuccessUsingRetryAfter(t *testing.T) {
	fx := adofixture.New().SetSequence("GET", "dev.azure.com", "/org/_apis/projects",
		adofixture.Response{
			Status:  http.StatusTooManyRequests,
			Headers: map[string]string{"Retry-After": "5"},
			Body:    map[string]any{"$id": "1", "message": "TF400733: The request has been blocked"},
		},
		adofixture.Response{
			Status:  http.StatusTooManyRequests,
			Headers: map[string]string{"Retry-After": "5"},
		},
		adofixture.Response{Status: http.StatusOK, Body: map[string]any{"count": 1}},
	)

	var slept []time.Duration
	rl := newRateLimitTransport(fx)
	rl.sleep = noSleep(&slept)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://dev.azure.com/org/_apis/projects", nil)
	resp, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("final status = %d, want 200 (eventual success after retries)", resp.StatusCode)
	}
	if len(fx.Calls()) != 3 {
		t.Errorf("len(Calls()) = %d, want 3 (2 blocked + 1 success)", len(fx.Calls()))
	}
	if len(slept) != 2 {
		t.Fatalf("len(slept) = %d, want 2 (one wait per blocked response before retrying)", len(slept))
	}
	for i, d := range slept {
		if d != 5*time.Second {
			t.Errorf("slept[%d] = %v, want 5s (the Retry-After value, not a backoff guess)", i, d)
		}
	}
}

// TestRateLimitTransport_429WithoutRetryAfterFallsBackToBackoff proves the
// documented fallback: a 429 that omits Retry-After (ADO always sends it in
// practice, but the transport must not assume that) still gets retried,
// using exponential backoff instead of hanging or failing immediately.
func TestRateLimitTransport_429WithoutRetryAfterFallsBackToBackoff(t *testing.T) {
	fx := adofixture.New().SetSequence("GET", "dev.azure.com", "/org/_apis/projects",
		adofixture.Response{Status: http.StatusTooManyRequests},
		adofixture.Response{Status: http.StatusOK},
	)

	var slept []time.Duration
	rl := newRateLimitTransport(fx)
	rl.sleep = noSleep(&slept)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://dev.azure.com/org/_apis/projects", nil)
	resp, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("final status = %d, want 200", resp.StatusCode)
	}
	if len(slept) != 1 {
		t.Fatalf("len(slept) = %d, want 1", len(slept))
	}
	if slept[0] < 0 || slept[0] >= time.Second {
		t.Errorf("slept[0] = %v, want a backoff wait in [0, 1s) for attempt 0 (full jitter over base 1<<0 = 1s)", slept[0])
	}
}

// TestRateLimitTransport_429SurfacedAsErrorAfterCap pins the documented
// difference from GitHub's secondary limit (which returns the still-limited
// response to the caller): after maxRateLimitRetries, a persistent ADO
// block must surface as an error wrapping ErrRateLimited, so a collector can
// report the check not-checkable instead of receiving a 429 it might
// misinterpret as some other kind of failure.
func TestRateLimitTransport_429SurfacedAsErrorAfterCap(t *testing.T) {
	responses := make([]adofixture.Response, maxRateLimitRetries+3)
	for i := range responses {
		responses[i] = adofixture.Response{
			Status:  http.StatusTooManyRequests,
			Headers: map[string]string{"Retry-After": "1"},
		}
	}
	fx := adofixture.New().SetSequence("GET", "dev.azure.com", "/org/_apis/projects", responses...)

	var slept []time.Duration
	rl := newRateLimitTransport(fx)
	rl.sleep = noSleep(&slept)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://dev.azure.com/org/_apis/projects", nil)
	resp, err := rl.RoundTrip(req)
	if resp != nil {
		t.Errorf("resp = %v, want nil (the 429 must be surfaced as an error, not returned)", resp)
	}
	if err == nil {
		t.Fatal("RoundTrip() = nil error, want ErrRateLimited after the retry cap")
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("error = %v, want it to wrap ErrRateLimited", err)
	}
	if got, want := len(fx.Calls()), maxRateLimitRetries+1; got != want {
		t.Errorf("len(Calls()) = %d, want %d (initial attempt + maxRateLimitRetries retries)", got, want)
	}
}

// TestRateLimitTransport_NonRateLimitResponsesPassThroughUnmodified proves a
// non-200/429 status (e.g. a plan-gating 404 on advsec/audit endpoints for
// an unlicensed org) is neither retried nor delayed — interpreting it is a
// collector's job, not the transport's.
func TestRateLimitTransport_NonRateLimitResponsesPassThroughUnmodified(t *testing.T) {
	fx := adofixture.New().Set("GET", "advsec.dev.azure.com", "/org/project/_apis/alerts", adofixture.Response{
		Status: http.StatusNotFound,
		Body:   map[string]any{"message": "Not Found"},
	})
	rl := newRateLimitTransport(fx)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://advsec.dev.azure.com/org/project/_apis/alerts", nil)
	resp, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (non-rate-limit response passes through unmodified)", resp.StatusCode)
	}
	if len(fx.Calls()) != 1 {
		t.Errorf("len(Calls()) = %d, want 1 (no retry for a non-rate-limit status)", len(fx.Calls()))
	}
}
