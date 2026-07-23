package github

import (
	"io"
	"math/rand" // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used -- jitter timing, not a cryptographic use (same justification as the //nolint:gosec below)
	"net/http"
	"strconv"
	"time"
)

// maxRateLimitRetries bounds how many times rateLimitTransport retries a
// primary-rate-limited request before giving up and returning the
// still-rate-limited response to the caller.
const maxRateLimitRetries = 5

// rateLimitTransport wraps an http.RoundTripper and honors GitHub's two
// distinct rate-limit signals differently, per GitHub's own guidance:
//
//   - Primary limit (403/429 with X-RateLimit-Remaining: 0): retry, waiting
//     until X-RateLimit-Reset (falling back to exponential backoff with
//     jitter if that header is missing/malformed), up to
//     maxRateLimitRetries times.
//   - Secondary limit (403/429 signaled by a Retry-After header without
//     X-RateLimit-Remaining: 0): never auto-retried — a global stop. GitHub
//     explicitly asks clients not to hammer through secondary limits; the
//     response is returned as-is for the caller (a collector, eventually
//     the orchestrator) to surface as not-checkable or fail the run.
//
// Every other response (including 402/404 plan-gating, which is a
// collector-level semantic judgment, not a transport concern) passes
// through untouched.
type rateLimitTransport struct {
	base http.RoundTripper
	// sleep is overridden in tests to avoid real wall-clock waits while
	// still exercising the retry-count/backoff-selection logic.
	sleep func(time.Duration)
}

func newRateLimitTransport(base http.RoundTripper) *rateLimitTransport {
	return &rateLimitTransport{base: base, sleep: time.Sleep}
}

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; ; attempt++ {
		resp, err = t.base.RoundTrip(req)
		if err != nil {
			return resp, err
		}

		if isSecondaryRateLimited(resp) {
			return resp, nil // global stop, never retried
		}
		if !isPrimaryRateLimited(resp) {
			return resp, nil
		}
		if attempt >= maxRateLimitRetries {
			return resp, nil // exhausted retries; caller sees the 403/429
		}

		wait := primaryRetryDelay(resp, attempt)
		drainAndClose(resp)
		t.sleep(wait)
	}
}

func isPrimaryRateLimited(resp *http.Response) bool {
	return isRateLimitStatus(resp.StatusCode) && resp.Header.Get("X-RateLimit-Remaining") == "0"
}

// isSecondaryRateLimited distinguishes GitHub's secondary (abuse-detection)
// rate limit from the primary one: secondary responses carry a Retry-After
// header and do NOT set X-RateLimit-Remaining: 0 (that combination is
// reserved for the primary limit).
func isSecondaryRateLimited(resp *http.Response) bool {
	return isRateLimitStatus(resp.StatusCode) &&
		resp.Header.Get("Retry-After") != "" &&
		resp.Header.Get("X-RateLimit-Remaining") != "0"
}

func isRateLimitStatus(code int) bool {
	return code == http.StatusForbidden || code == http.StatusTooManyRequests
}

// primaryRetryDelay waits until the window resets per X-RateLimit-Reset (a
// Unix timestamp), falling back to exponential backoff with full jitter if
// that header is absent or malformed.
func primaryRetryDelay(resp *http.Response, attempt int) time.Duration {
	if resetHeader := resp.Header.Get("X-RateLimit-Reset"); resetHeader != "" {
		if resetUnix, err := strconv.ParseInt(resetHeader, 10, 64); err == nil {
			if d := time.Until(time.Unix(resetUnix, 0)); d > 0 {
				return d
			}
		}
	}
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
