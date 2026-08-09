package gogs

import (
	"context"
	"io"
	"math/rand" // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used -- jitter timing, not a cryptographic use (same justification as the GitHub rate-limit transport's)
	"net/http"
	"time"
)

// maxRetries bounds how many times retryTransport re-issues a request that
// came back 5xx before returning the failed response to the caller.
const maxRetries = 3

// retryTransport retries transient server-side failures, and nothing else.
//
// This is deliberately far simpler than the GitHub and Azure DevOps
// rate-limit transports, because Gogs gives it nothing to be clever with:
// the API sends no X-RateLimit-* headers, no Retry-After, and no
// rate-limit status of its own (verified against Gogs 0.15 on 2026-08-03 —
// the only response headers are Content-Type, Set-Cookie and the two
// X-Frame-Options/X-Content-Type-Options security headers). Writing a
// header-driven backoff here would be code that reads as if it honoured a
// signal the server never sends.
//
// A 5xx is retried with exponential backoff plus jitter. A 4xx never is:
// on this API a 401, 403 or 404 is a settled answer about auth or
// existence, and retrying it would turn a fast, honest failure into a slow
// one. Note that a Gogs instance published through Cloudflare can answer
// 5xx from the edge while Gogs itself is fine (or entirely down) — the
// retry is worth having for exactly that case, but a collector must still
// treat an exhausted retry as not-checkable rather than as an observation.
type retryTransport struct {
	base http.RoundTripper
	// after produces the channel wait blocks on, defaulting to time.After.
	// Tests replace it to avoid real wall-clock delays while still going
	// through the identical select below — so a test can never prove
	// cancellation behaviour that production does not have.
	after func(time.Duration) <-chan time.Time
}

// wait blocks for d, returning the context's error if it is done first.
//
// The wait must be interruptible, not merely preceded by a check: a
// deadline that expires *during* a backoff has to end the call then, not at
// the next attempt. Measured with an uninterruptible sleep, a 10ms deadline
// returned after 1.08s and a 1.5s deadline after 3.25s — a cancelled scan
// that reads as a hung one.
func (t *retryTransport) wait(ctx context.Context, d time.Duration) error {
	// Cheap early-out for an already-cancelled caller, so no timer is
	// started at all. The select below is what makes the wait genuinely
	// interruptible; this only avoids the pointless allocation.
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.after(d):
		return nil
	}
}

func newRetryTransport(base http.RoundTripper) *retryTransport {
	return &retryTransport{base: base, after: time.After}
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; ; attempt++ {
		resp, err = t.base.RoundTrip(req)
		if err != nil {
			return resp, err
		}
		if resp.StatusCode < 500 || attempt >= maxRetries {
			return resp, nil
		}

		// Drain and close before retrying: the response is being
		// discarded, and leaking it would hold a connection out of the
		// pool for the rest of the scan.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		// The wait is interruptible, not merely preceded by a check. A
		// deadline that expires *during* a backoff must end the call then,
		// not at the next attempt: with an uninterruptible sleep a 10ms
		// deadline returned after 1.08s and a 1.5s deadline after 3.25s,
		// so a cancelled scan reads as a hung one.
		if err := t.wait(req.Context(), backoff(attempt)); err != nil {
			return nil, err
		}
	}
}

// backoff returns the wait before retry number attempt (0-based): 1s, 2s,
// 4s, each with up to 250ms of jitter so concurrent per-repo workers that
// hit the same failing instance don't retry in lockstep.
func backoff(attempt int) time.Duration {
	base := time.Second << attempt //nolint:gosec // attempt is bounded by maxRetries
	return base + time.Duration(rand.Int63n(int64(250*time.Millisecond)))
}
