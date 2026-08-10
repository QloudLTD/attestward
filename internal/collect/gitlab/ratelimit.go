package gitlab

import (
	"net/http"
	"strconv"
	"time"
)

// rateLimitTransport honours GitLab's rate limiting.
//
// This has no analogue in the Gogs package, which documents that Gogs sends
// no rate-limit headers at all. GitLab is the opposite: gitlab.com enforces
// per-user request budgets and answers 429 with Retry-After when a client
// exceeds them. Scanning a large group is exactly the shape of traffic that
// trips it — many small reads in a burst.
//
// Ignoring a 429 would not just be rude. The retry layer treats <500 as
// final, so an unhandled 429 would surface as a hard failure mid-scan and
// produce a pack missing whichever repositories happened to be after the
// limit — a partial result presented as complete, which is the failure mode
// this package works hardest to avoid.
type rateLimitTransport struct {
	base  http.RoundTripper
	sleep func(d time.Duration)
}

func newRateLimitTransport(base http.RoundTripper) *rateLimitTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &rateLimitTransport{base: base, sleep: time.Sleep}
}

// maxRateLimitWait caps how long a single 429 will park the scan. GitLab
// normally asks for seconds; a Retry-After of an hour means the credential is
// being throttled hard, and blocking a scan that long is worse than failing
// with an error a human can read.
const maxRateLimitWait = 2 * time.Minute

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusTooManyRequests {
		return resp, err
	}

	wait := retryAfter(resp)
	if wait <= 0 || wait > maxRateLimitWait {
		// Hand the 429 back rather than sleeping for an unreasonable time.
		// The caller turns it into a StatusError naming the endpoint, which
		// is a far more actionable outcome than a scan that appears hung.
		return resp, nil
	}
	_ = resp.Body.Close()
	t.sleep(wait)
	return t.base.RoundTrip(req)
}

// retryAfter reads GitLab's backoff hint. Retry-After is the documented
// header; RateLimit-Reset (an epoch second) is used as a fallback because
// some GitLab versions and fronting proxies send only that.
func retryAfter(resp *http.Response) time.Duration {
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
	}
	if v := resp.Header.Get("RateLimit-Reset"); v != "" {
		if epoch, err := strconv.ParseInt(v, 10, 64); err == nil {
			if d := time.Until(time.Unix(epoch, 0)); d > 0 {
				return d
			}
		}
	}
	return 0
}
