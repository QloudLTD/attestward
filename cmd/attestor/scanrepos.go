package main

import (
	"context"
	"fmt"

	"github.com/google/go-github/v75/github"
)

// repoInfo is the minimal repo metadata scope resolution needs.
type repoInfo struct {
	Name     string
	Archived bool
	Fork     bool
}

// repoLister lists an org's repos — abstracted so tests can inject a
// fixture-backed implementation instead of hitting a real client.
type repoLister interface {
	ListRepos(ctx context.Context, org string) ([]repoInfo, error)
}

// restRepoLister lists repos via the real GitHub REST API, paginating
// through every page.
type restRepoLister struct {
	client *github.Client
}

func (l *restRepoLister) ListRepos(ctx context.Context, org string) ([]repoInfo, error) {
	var all []repoInfo
	opts := &github.RepositoryListByOrgOptions{ListOptions: github.ListOptions{PerPage: 100}}

	for {
		repos, resp, err := l.client.Repositories.ListByOrg(ctx, org, opts)
		if err != nil {
			return nil, fmt.Errorf("list repos for org %s: %w", org, err)
		}
		for _, r := range repos {
			all = append(all, repoInfo{Name: r.GetName(), Archived: r.GetArchived(), Fork: r.GetFork()})
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

// orgChecker confirms an org is visible with the token in use — the
// preflight check issue #10 asks for, and (as a side effect) the guaranteed
// first authenticated call: HasWriteScope()'s least-privilege warning has
// nothing to report on until at least one authenticated response has been
// observed (internal/collect/github/scopes.go), so this must run before
// that warning is checked, not after resolveRepos alone (which makes zero
// API calls whenever repos are given explicitly — the documented usage in
// examples/attestor.yaml).
type orgChecker interface {
	CheckOrgVisible(ctx context.Context, org string) error
}

// restOrgChecker checks org visibility via the real GitHub REST API.
type restOrgChecker struct {
	client *github.Client
}

func (c *restOrgChecker) CheckOrgVisible(ctx context.Context, org string) error {
	_, _, err := c.client.Organizations.Get(ctx, org)
	return err
}

// resolveRepos returns the explicit repo list if non-empty (blank entries
// dropped — a stray `--repo=""` must not silently become a repo literally
// named ""), or every non-archived, non-fork repo in the org otherwise —
// printing a warning when it does the latter, per issue #10's "empty = all
// non-archived, non-fork repos with a warning" requirement.
func resolveRepos(ctx context.Context, lister repoLister, org string, explicit []string, warn func(string)) ([]string, error) {
	filtered := make([]string, 0, len(explicit))
	for _, r := range explicit {
		if r != "" {
			filtered = append(filtered, r)
		}
	}
	if len(filtered) > 0 {
		return filtered, nil
	}

	all, err := lister.ListRepos(ctx, org)
	if err != nil {
		return nil, err
	}

	repos := make([]string, 0, len(all))
	for _, r := range all {
		if r.Archived || r.Fork {
			continue
		}
		repos = append(repos, r.Name)
	}
	warn(fmt.Sprintf("no repos specified — scanning all %d non-archived, non-fork repos in %s", len(repos), org))
	return repos, nil
}
