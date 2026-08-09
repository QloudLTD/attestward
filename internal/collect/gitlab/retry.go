package gitlab

import (
	"context"
	"math"
	"net/http"
	"time"
)

// maxRetries bounds transient-failure retries per request.
const maxRetries = 3

// retryTransport retries 5xx responses, which are transient by definition —
// a GitLab instance restarting behind a load balancer, a gateway timing out
// mid-deploy. It does NOT retry 4xx: a 401 is a bad token, a 403 is a
// permission or tier limit and a 404 is a missing resource, and hammering
// any of those changes nothing while making the tool look like an attack.
type retryTransport struct {
	base http.RoundTripper
	// sleep is a seam so tests do not actually wait.
	sleep func(ctx context.Context, d time.Duration) error
}

func newRetryTransport(base http.RoundTripper) *retryTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &retryTransport{base: base, sleep: waitOrCancel}
}

func waitOrCancel(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			if werr := t.sleep(req.Context(), backoff(attempt)); werr != nil {
				return nil, werr
			}
		}
		resp, err = t.base.RoundTrip(req)
		if err != nil {
			continue
		}
		if resp.StatusCode < 500 {
			return resp, nil
		}
		// Drain and close so the connection can be reused rather than leaked
		// across every retry of a failing endpoint.
		if attempt < maxRetries {
			resp.Body.Close()
		}
	}
	return resp, err
}

// backoff grows exponentially from 500ms. There is no jitter because this
// tool makes one scan at a time from one process — jitter exists to
// desynchronise a fleet, and there is no fleet here.
func backoff(attempt int) time.Duration {
	return time.Duration(math.Pow(2, float64(attempt-1))*500) * time.Millisecond
}
