package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
)

type fakeRepoLister struct {
	repos []repoInfo
	err   error
	// gotAccountType records the accountType ListRepos was last called
	// with, so a test can assert resolveRepos actually threads it through
	// rather than just compiling against the new parameter.
	gotAccountType collect.AccountType
}

func (f *fakeRepoLister) ListRepos(_ context.Context, _ string, accountType collect.AccountType) ([]repoInfo, error) {
	f.gotAccountType = accountType
	return f.repos, f.err
}

func TestResolveRepos_ExplicitReposSkipsListing(t *testing.T) {
	lister := &fakeRepoLister{err: errors.New("should not be called")}
	warned := false

	repos, err := resolveRepos(context.Background(), lister, "attestward-demo", collect.AccountTypeOrganization, []string{"a", "b"}, func(string) { warned = true })
	if err != nil {
		t.Fatalf("resolveRepos: %v", err)
	}
	if len(repos) != 2 {
		t.Errorf("repos = %v, want [a b]", repos)
	}
	if warned {
		t.Error("warn callback fired, want no warning when repos are explicit")
	}
}

// TestResolveRepos_NilListerWithExplicitReposStillWorks proves a nil lister
// (what buildScanDeps leaves for an azuredevops scan today, since there's
// no ADO repoLister yet) doesn't matter as long as --repo was given
// explicitly — resolveRepos never touches the lister in that path.
func TestResolveRepos_NilListerWithExplicitReposStillWorks(t *testing.T) {
	repos, err := resolveRepos(context.Background(), nil, "attestward-demo", collect.AccountTypeOrganization, []string{"a", "b"}, func(string) {})
	if err != nil {
		t.Fatalf("resolveRepos: %v", err)
	}
	if len(repos) != 2 {
		t.Errorf("repos = %v, want [a b]", repos)
	}
}

// TestResolveRepos_NilListerWithNoExplicitReposErrors pins the fix for the
// mined ADO seam review of #169 found: buildScanDeps leaves repoLister nil
// for an azuredevops scan, and the moment a real ADO collector lands
// without an accompanying ADO repoLister, `scan --platform azuredevops`
// with no --repo would otherwise nil-pointer panic here instead of
// producing an actionable error.
func TestResolveRepos_NilListerWithNoExplicitReposErrors(t *testing.T) {
	_, err := resolveRepos(context.Background(), nil, "attestward-demo", collect.AccountTypeOrganization, nil, func(string) {})
	if err == nil {
		t.Fatal("resolveRepos(nil lister, no explicit repos) = nil error, want an actionable error instead of a nil-pointer panic")
	}
	if !strings.Contains(err.Error(), "--repo") {
		t.Errorf("error = %v, want it to suggest passing --repo explicitly", err)
	}
}

func TestResolveRepos_EmptyFiltersArchivedAndForksWithWarning(t *testing.T) {
	lister := &fakeRepoLister{repos: []repoInfo{
		{Name: "good-repo"},
		{Name: "archived-repo", Archived: true},
		{Name: "forked-repo", Fork: true},
		{Name: "another-good-repo"},
	}}
	var warnMsg string

	repos, err := resolveRepos(context.Background(), lister, "attestward-demo", collect.AccountTypeOrganization, nil, func(msg string) { warnMsg = msg })
	if err != nil {
		t.Fatalf("resolveRepos: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("repos = %v, want 2 non-archived non-fork repos", repos)
	}
	for _, r := range repos {
		if r == "archived-repo" || r == "forked-repo" {
			t.Errorf("repos = %v, want archived/forked repos excluded", repos)
		}
	}
	if warnMsg == "" {
		t.Error("warn callback did not fire when scanning all repos")
	}
}

func TestResolveRepos_ListerErrorPropagates(t *testing.T) {
	lister := &fakeRepoLister{err: errors.New("org not found")}
	_, err := resolveRepos(context.Background(), lister, "nonexistent-org", collect.AccountTypeOrganization, nil, func(string) {})
	if err == nil {
		t.Fatal("resolveRepos with a lister error = nil error, want it propagated")
	}
}

// TestResolveRepos_ThreadsAccountTypeToLister confirms resolveRepos passes
// the accountType it was given straight through to ListRepos — issue #102:
// this is what lets restRepoLister pick ListByOrg vs ListByUser correctly.
func TestResolveRepos_ThreadsAccountTypeToLister(t *testing.T) {
	lister := &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}}

	if _, err := resolveRepos(context.Background(), lister, "sioakim", collect.AccountTypeUser, nil, func(string) {}); err != nil {
		t.Fatalf("resolveRepos: %v", err)
	}
	if lister.gotAccountType != collect.AccountTypeUser {
		t.Errorf("ListRepos was called with accountType %q, want user", lister.gotAccountType)
	}
}

// TestResolveRepos_UserAccountWarningNamesPublicRepoLimitation confirms the
// warning text for a user-account target (issue #102) is distinct from the
// org warning and honestly flags that private repos aren't auto-listed —
// see listByUser's own doc comment for why that limitation is real.
func TestResolveRepos_UserAccountWarningNamesPublicRepoLimitation(t *testing.T) {
	lister := &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}}
	var warnMsg string

	if _, err := resolveRepos(context.Background(), lister, "sioakim", collect.AccountTypeUser, nil, func(msg string) { warnMsg = msg }); err != nil {
		t.Fatalf("resolveRepos: %v", err)
	}
	if warnMsg == "" {
		t.Fatal("warn callback did not fire when scanning all repos for a user account")
	}
	if !strings.Contains(warnMsg, "PUBLIC") || !strings.Contains(warnMsg, "private") {
		t.Errorf("warning = %q, want it to name the public-only listing limitation for a user account", warnMsg)
	}
}
