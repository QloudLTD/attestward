package github

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/sioakim/attestward/internal/collect/github/ghfixture"
)

// noSleep replaces rateLimitTransport.sleep in tests so retry-count/backoff
// logic is exercised without actually waiting real wall-clock time; it
// records each requested duration into log instead of sleeping.
func noSleep(log *[]time.Duration) func(time.Duration) {
	return func(actual time.Duration) {
		*log = append(*log, actual)
	}
}

func TestRateLimitTransport_PrimaryLimitRetriesUntilSuccess(t *testing.T) {
	resetAt := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	fx := ghfixture.New().SetSequence("GET", "/orgs/attestor-demo",
		ghfixture.Response{
			Status: http.StatusForbidden,
			Headers: map[string]string{
				"X-RateLimit-Remaining": "0",
				"X-RateLimit-Reset":     resetAt,
			},
		},
		ghfixture.Response{
			Status: http.StatusForbidden,
			Headers: map[string]string{
				"X-RateLimit-Remaining": "0",
				"X-RateLimit-Reset":     resetAt,
			},
		},
		ghfixture.Response{Status: http.StatusOK, Body: map[string]any{"login": "attestor-demo"}},
	)

	var slept []time.Duration
	rl := newRateLimitTransport(fx)
	rl.sleep = noSleep(&slept)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.github.com/orgs/attestor-demo", nil)
	resp, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("final status = %d, want 200 (eventual success after retries)", resp.StatusCode)
	}
	if len(fx.Calls()) != 3 {
		t.Errorf("len(Calls()) = %d, want 3 (2 rate-limited + 1 success)", len(fx.Calls()))
	}
	if len(slept) != 2 {
		t.Errorf("len(slept) = %d, want 2 (one wait per rate-limited response before retrying)", len(slept))
	}
}

func TestRateLimitTransport_PrimaryLimitGivesUpAfterMaxRetries(t *testing.T) {
	resetAt := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	responses := make([]ghfixture.Response, maxRateLimitRetries+3)
	for i := range responses {
		responses[i] = ghfixture.Response{
			Status: http.StatusForbidden,
			Headers: map[string]string{
				"X-RateLimit-Remaining": "0",
				"X-RateLimit-Reset":     resetAt,
			},
		}
	}
	fx := ghfixture.New().SetSequence("GET", "/orgs/attestor-demo", responses...)

	var slept []time.Duration
	rl := newRateLimitTransport(fx)
	rl.sleep = noSleep(&slept)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.github.com/orgs/attestor-demo", nil)
	resp, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("final status = %d, want 403 (retries exhausted, caller sees the rate limit)", resp.StatusCode)
	}
	if got, want := len(fx.Calls()), maxRateLimitRetries+1; got != want {
		t.Errorf("len(Calls()) = %d, want %d (initial attempt + maxRateLimitRetries retries)", got, want)
	}
}

func TestRateLimitTransport_SecondaryLimitStopsImmediatelyNoRetry(t *testing.T) {
	fx := ghfixture.New().SetSequence("GET", "/orgs/attestor-demo",
		ghfixture.Response{
			Status: http.StatusForbidden,
			Headers: map[string]string{
				"Retry-After": "60",
				// Deliberately NOT X-RateLimit-Remaining: 0 — that
				// combination is what distinguishes secondary from primary.
			},
			Body: map[string]any{"message": "You have exceeded a secondary rate limit"},
		},
		// If the transport incorrectly retried, this would be served next
		// and the test would pass for the wrong reason — assert call count
		// below to catch that.
		ghfixture.Response{Status: http.StatusOK},
	)

	var slept []time.Duration
	rl := newRateLimitTransport(fx)
	rl.sleep = noSleep(&slept)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.github.com/orgs/attestor-demo", nil)
	resp, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (secondary limit returned as-is, not retried)", resp.StatusCode)
	}
	if len(fx.Calls()) != 1 {
		t.Errorf("len(Calls()) = %d, want 1 (global stop: never retried)", len(fx.Calls()))
	}
	if len(slept) != 0 {
		t.Errorf("len(slept) = %d, want 0 (no backoff wait for a secondary limit)", len(slept))
	}
}

func TestRateLimitTransport_PlanGatedResponsesPassThroughUnmodified(t *testing.T) {
	fx := ghfixture.New().Set("GET", "/orgs/attestor-demo/audit-log", ghfixture.Response{
		Status: http.StatusNotFound,
		Body:   map[string]any{"message": "Not Found"},
	})
	rl := newRateLimitTransport(fx)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.github.com/orgs/attestor-demo/audit-log", nil)
	resp, err := rl.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (plan-gated response passes through; interpreting it is a collector's job, not the transport's)", resp.StatusCode)
	}
	if len(fx.Calls()) != 1 {
		t.Errorf("len(Calls()) = %d, want 1 (no retry for a non-rate-limit status)", len(fx.Calls()))
	}
}
