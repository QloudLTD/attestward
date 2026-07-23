package azuredevops

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// maxRateLimitRetries bounds how many times rateLimitTransport retries a
// 429-blocked request before giving up and surfacing the block as an error.
const maxRateLimitRetries = 5

// ErrRateLimited is returned (wrapped) when a request is still blocked
// (HTTP 429) after maxRateLimitRetries retries.
var ErrRateLimited = fmt.Errorf("collect/azuredevops: rate limit exceeded after %d retries", maxRateLimitRetries)

// rateLimitTransport wraps an http.RoundTripper and honors Azure DevOps's
// TSTU rate-limit model — TSTU is Microsoft's own term, "Azure DevOps
// throughput unit" (an abstract blend of database/compute/storage load, not
// an acronym for a literal "time" unit — see
// https://learn.microsoft.com/en-us/azure/devops/integrate/concepts/rate-limits),
// 200 TSTUs per sliding 5-minute window — which differs from GitHub's
// primary/secondary limits on a structural axis, not just in header names:
//
//   - GitHub signals both of its limits the same way — a failed request
//     (403/429) — and the transport tells them apart after the fact by
//     inspecting response headers (X-RateLimit-Remaining vs a bare
//     Retry-After). One tier is retried, the other is a permanent stop.
//   - ADO instead attaches Retry-After to two outcomes that are already
//     distinguished by status code, no header inspection needed to tell
//     them apart:
//     1. Delay: under load but under the ceiling, the request still
//     succeeds (HTTP 200) — Retry-After asks the caller to slow down
//     before its *next* request, not to redo this one. This is honored
//     unconditionally: there's no secondary-limit-style case where a
//     200's Retry-After should be ignored.
//     2. Block: once the ceiling is hit, ADO returns HTTP 429 (error code
//     TF400733) with Retry-After. Unlike GitHub's secondary limit (a
//     permanent stop), this is retried in place — ADO's block is a
//     temporary sliding-window ceiling, not an abuse signal — but
//     bounded by maxRateLimitRetries, after which the persistent 429 is
//     surfaced as an error so a collector can report the check
//     not-checkable rather than hang indefinitely.
//
// Every other response passes through untouched; interpreting a non-rate-
// limit status (plan-gating, auth failure, etc.) is a collector's job, not
// the transport's.
type rateLimitTransport struct {
	base http.RoundTripper
	// sleep is overridden in tests to avoid real wall-clock waits while
	// still exercising the delay/retry logic.
	sleep func(time.Duration)
	// now is overridden in tests so elapsed-time calculations against
	// delayUntil are deterministic without a real wall-clock wait.
	now func() time.Time

	mu         sync.Mutex
	delayUntil time.Time // zero value: no pending delay
}

func newRateLimitTransport(base http.RoundTripper) *rateLimitTransport {
	return &rateLimitTransport{base: base, sleep: time.Sleep, now: time.Now}
}

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.waitPendingDelay()

	for attempt := 0; ; attempt++ {
		resp, err := t.base.RoundTrip(req)
		if err != nil {
			return resp, err
		}

		if resp.StatusCode == http.StatusOK {
			if wait, ok := retryAfterDelay(resp); ok {
				t.setDelayUntil(wait)
			}
			return resp, nil
		}

		if resp.StatusCode != http.StatusTooManyRequests {
			return resp, nil
		}

		if attempt >= maxRateLimitRetries {
			drainAndClose(resp)
			return nil, fmt.Errorf("%w: %s %s%s", ErrRateLimited, req.Method, req.URL.Host, req.URL.Path)
		}

		wait, ok := retryAfterDelay(resp)
		if !ok {
			wait = backoffDelay(attempt)
		}
		drainAndClose(resp)
		t.sleep(wait)
	}
}

// waitPendingDelay sleeps off whatever remains of the most recently
// announced delay deadline — without clearing it. Storing a deadline
// (mirroring the GitHub twin's time.Until(reset) pattern in
// primaryRetryDelay) rather than a fixed duration gets two properties a
// duration can't:
//
//   - A request that arrives after the deadline has already passed sleeps
//     zero instead of over-sleeping by the original Retry-After value.
//   - N requests that arrive concurrently (the collector fan-out pool, in a
//     later PR) all honor the remaining wait, not just the first one to
//     read the field — a one-shot "consume and clear" duration would let
//     every subsequent concurrent request sail through unthrottled.
func (t *rateLimitTransport) waitPendingDelay() {
	t.mu.Lock()
	deadline := t.delayUntil
	t.mu.Unlock()
	if deadline.IsZero() {
		return
	}
	if remaining := deadline.Sub(t.now()); remaining > 0 {
		t.sleep(remaining)
	}
}

func (t *rateLimitTransport) setDelayUntil(wait time.Duration) {
	t.mu.Lock()
	t.delayUntil = t.now().Add(wait)
	t.mu.Unlock()
}

// retryAfterDelay parses the Retry-After header as whole seconds — ADO
// always sends it that way, never as an HTTP-date — returning false if the
// header is absent or malformed.
func retryAfterDelay(resp *http.Response) (time.Duration, bool) {
	raw := resp.Header.Get("Retry-After")
	if raw == "" {
		return 0, false
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs < 0 {
		return 0, false
	}
	return time.Duration(secs) * time.Second, true
}

// backoffDelay is the fallback wait when a 429 arrives without a Retry-After
// header: exponential backoff with full jitter, same shape as the GitHub
// transport's primary-limit fallback.
func backoffDelay(attempt int) time.Duration {
	base := time.Duration(1<<uint(attempt)) * time.Second
	//nolint:gosec // jitter timing, not a cryptographic use
	return time.Duration(rand.Int63n(int64(base)))
}

func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
