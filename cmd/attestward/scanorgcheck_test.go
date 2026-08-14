package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
)

// TestOrgPreflightPopulatesScopeTrackingForWriteScopeWarning proves the
// actual bug the Fable 5 review caught: before this fix, the write-scope
// warning checked Client.HasWriteScope() before any authenticated call had
// happened whenever repos were given explicitly (the documented usage in
// examples/attestward.yaml), so it could never fire even for a full-write
// token. This builds a REAL ghcollect.Client (not a fake) pointed at a
// local test server that reports a write-capable scope, and confirms the
// account preflight call alone — via restOrgChecker, exactly as runScan
// invokes it — is enough to make HasWriteScope() true afterward.
func TestOrgPreflightPopulatesScopeTrackingForWriteScopeWarning(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "repo, read:org")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"login":"attestward-demo","type":"Organization"}`))
	}))
	defer server.Close()

	client := ghcollect.NewClient("ghp_test-token", ghcollect.ClientConfig{})
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	client.REST.BaseURL = baseURL

	if client.HasWriteScope() {
		t.Fatal("HasWriteScope() = true before any authenticated call — test setup invalid, should start false")
	}

	checker := &restOrgChecker{client: client.REST}
	accountType, err := checker.CheckAccount(context.Background(), "attestward-demo")
	if err != nil {
		t.Fatalf("CheckAccount: %v", err)
	}
	if accountType != collect.AccountTypeOrganization {
		t.Errorf("accountType = %q, want organization (server reported type=Organization)", accountType)
	}

	if !client.HasWriteScope() {
		t.Error("HasWriteScope() = false after the account preflight call, want true — the preflight should be the guaranteed first authenticated call that makes the write-scope warning meaningful")
	}
	scopes := client.Scopes()
	if len(scopes) != 2 {
		t.Errorf("Scopes() = %v, want [repo, read:org]", scopes)
	}
}

// TestCheckAccount_UserTypeDetected confirms CheckAccount correctly
// classifies a personal account (issue #102): GET /users/{account} returns
// type="User" for a personal account the same way it returns
// type="Organization" for an org — this is the actual API-shape assumption
// the whole issue #102 fix rests on, so it's worth pinning independently of
// the write-scope test above (which only asserts the Organization case).
func TestCheckAccount_UserTypeDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"login":"sioakim","type":"User"}`))
	}))
	defer server.Close()

	client := ghcollect.NewClient("ghp_test-token", ghcollect.ClientConfig{})
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	client.REST.BaseURL = baseURL

	checker := &restOrgChecker{client: client.REST}
	accountType, err := checker.CheckAccount(context.Background(), "sioakim")
	if err != nil {
		t.Fatalf("CheckAccount: %v", err)
	}
	if accountType != collect.AccountTypeUser {
		t.Errorf("accountType = %q, want user (server reported type=User)", accountType)
	}
}

// TestRestRepoLister_ListReposHitsOrgEndpointForOrganization and its User
// sibling below prove restRepoLister.ListRepos actually dispatches to the
// right real REST endpoint for each account type — found missing in Fable
// review of PR #103: the existing resolveRepos tests only exercise
// threading via fakeRepoLister, so a mutation flipping the dispatch branch
// in restRepoLister.ListRepos itself would have gone uncaught.
func TestRestRepoLister_ListReposHitsOrgEndpointForOrganization(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	client := ghcollect.NewClient("ghp_test-token", ghcollect.ClientConfig{})
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	client.REST.BaseURL = baseURL

	lister := &restRepoLister{client: client.REST}
	if _, err := lister.ListRepos(context.Background(), "attestward-demo", collect.AccountTypeOrganization); err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	if gotPath != "/orgs/attestward-demo/repos" {
		t.Errorf("request path = %q, want /orgs/attestward-demo/repos", gotPath)
	}
}

func TestRestRepoLister_ListReposHitsUserEndpointForUserAccount(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	client := ghcollect.NewClient("ghp_test-token", ghcollect.ClientConfig{})
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	client.REST.BaseURL = baseURL

	lister := &restRepoLister{client: client.REST}
	if _, err := lister.ListRepos(context.Background(), "sioakim", collect.AccountTypeUser); err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	if gotPath != "/users/sioakim/repos" {
		t.Errorf("request path = %q, want /users/sioakim/repos", gotPath)
	}
}
