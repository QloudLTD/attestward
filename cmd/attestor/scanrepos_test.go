package main

import (
	"context"
	"errors"
	"testing"
)

type fakeRepoLister struct {
	repos []repoInfo
	err   error
}

func (f *fakeRepoLister) ListRepos(context.Context, string) ([]repoInfo, error) {
	return f.repos, f.err
}

func TestResolveRepos_ExplicitReposSkipsListing(t *testing.T) {
	lister := &fakeRepoLister{err: errors.New("should not be called")}
	warned := false

	repos, err := resolveRepos(context.Background(), lister, "attestor-demo", []string{"a", "b"}, func(string) { warned = true })
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

func TestResolveRepos_EmptyFiltersArchivedAndForksWithWarning(t *testing.T) {
	lister := &fakeRepoLister{repos: []repoInfo{
		{Name: "good-repo"},
		{Name: "archived-repo", Archived: true},
		{Name: "forked-repo", Fork: true},
		{Name: "another-good-repo"},
	}}
	var warnMsg string

	repos, err := resolveRepos(context.Background(), lister, "attestor-demo", nil, func(msg string) { warnMsg = msg })
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
	_, err := resolveRepos(context.Background(), lister, "nonexistent-org", nil, func(string) {})
	if err == nil {
		t.Fatal("resolveRepos with a lister error = nil error, want it propagated")
	}
}
