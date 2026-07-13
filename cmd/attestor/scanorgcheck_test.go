package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
)

// TestOrgPreflightPopulatesScopeTrackingForWriteScopeWarning proves the
// actual bug the Fable 5 review caught: before this fix, the write-scope
// warning checked Client.HasWriteScope() before any authenticated call had
// happened whenever repos were given explicitly (the documented usage in
// examples/attestor.yaml), so it could never fire even for a full-write
// token. This builds a REAL ghcollect.Client (not a fake) pointed at a
// local test server that reports a write-capable scope, and confirms the
// org-visibility preflight call alone — via restOrgChecker, exactly as
// runScan invokes it — is enough to make HasWriteScope() true afterward.
func TestOrgPreflightPopulatesScopeTrackingForWriteScopeWarning(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "repo, read:org")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"login":"attestor-demo"}`))
	}))
	defer server.Close()

	client := ghcollect.NewClient("ghp_test-token")
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	client.REST.BaseURL = baseURL

	if client.HasWriteScope() {
		t.Fatal("HasWriteScope() = true before any authenticated call — test setup invalid, should start false")
	}

	checker := &restOrgChecker{client: client.REST}
	if err := checker.CheckOrgVisible(context.Background(), "attestor-demo"); err != nil {
		t.Fatalf("CheckOrgVisible: %v", err)
	}

	if !client.HasWriteScope() {
		t.Error("HasWriteScope() = false after the org-visibility preflight call, want true — the preflight should be the guaranteed first authenticated call that makes the write-scope warning meaningful")
	}
	scopes := client.Scopes()
	if len(scopes) != 2 {
		t.Errorf("Scopes() = %v, want [repo, read:org]", scopes)
	}
}
