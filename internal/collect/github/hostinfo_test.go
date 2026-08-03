package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestClient_GHESVersion_ObservedFromResponseHeader proves the
// X-GitHub-Enterprise-Version response header is captured and exposed via
// Client.GHESVersion — the "every response carries X-GitHub-Enterprise-
// Version" detection mechanism issue #12's GHES epic calls for, resolved
// from a real response rather than the configured --github-url (so it
// stays correct even if a GHES install were reachable without one).
func TestClient_GHESVersion_ObservedFromResponseHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-GitHub-Enterprise-Version", "3.9.0")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"attestward-demo","type":"Organization"}`))
	}))
	defer server.Close()

	cfg, err := ResolveHostConfig(server.URL, "")
	if err != nil {
		t.Fatalf("ResolveHostConfig: %v", err)
	}
	client := NewClient("ghp_test-token", cfg)

	if got := client.GHESVersion(); got != "" {
		t.Errorf("GHESVersion() before any call = %q, want empty", got)
	}

	if _, _, err := client.REST.Organizations.Get(context.Background(), "attestward-demo"); err != nil {
		t.Fatalf("Organizations.Get: %v", err)
	}

	if got := client.GHESVersion(); got != "3.9.0" {
		t.Errorf("GHESVersion() = %q, want 3.9.0", got)
	}
}

// TestClient_GHESVersion_EmptyForGitHubCom proves a github.com-shaped
// response (no X-GitHub-Enterprise-Version header) leaves GHESVersion
// empty — the signal collectors use to mean "assume github.com behavior".
func TestClient_GHESVersion_EmptyForGitHubCom(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"attestward-demo","type":"Organization"}`))
	}))
	defer server.Close()

	client := NewClient("ghp_test-token", ClientConfig{})
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	client.REST.BaseURL = baseURL

	if _, _, err := client.REST.Organizations.Get(context.Background(), "attestward-demo"); err != nil {
		t.Fatalf("Organizations.Get: %v", err)
	}
	if got := client.GHESVersion(); got != "" {
		t.Errorf("GHESVersion() = %q, want empty (no header sent)", got)
	}
}

// TestHostVersionTracker_LatchesOnlyOnARealObservation is the regression
// test for a fix that previously survived full reversion with a green
// suite — which, in a repo whose history is this same false inference being
// fixed five times because no guard held, is the more serious half of the
// defect.
//
// The tracker used to latch on the FIRST response whether or not it carried
// the header, so one headerless response — an LB-generated 502 arriving
// first, or a reverse proxy stripping unknown X-* headers, which is the
// normal posture in the networks GHES lives in — pinned the version empty
// for the entire scan, even though every subsequent response announced it.
func TestHostVersionTracker_LatchesOnlyOnARealObservation(t *testing.T) {
	var h hostVersionTracker

	headerless := &http.Response{StatusCode: 502, Header: http.Header{}}
	h.observe(headerless)
	if got := h.Version(); got != "" {
		t.Fatalf("Version() = %q after a headerless response, want empty", got)
	}

	withHeader := &http.Response{StatusCode: 200, Header: http.Header{}}
	withHeader.Header.Set("X-GitHub-Enterprise-Version", "3.12.4")
	h.observe(withHeader)
	if got := h.Version(); got != "3.12.4" {
		t.Errorf("Version() = %q after the header finally arrived, want 3.12.4 — a headerless first response must not pin it empty for the whole scan", got)
	}

	later := &http.Response{StatusCode: 200, Header: http.Header{}}
	later.Header.Set("X-GitHub-Enterprise-Version", "9.9.9")
	h.observe(later)
	if got := h.Version(); got != "3.12.4" {
		t.Errorf("Version() = %q, want the first observed value to win — the version does not change mid-scan", got)
	}
}
