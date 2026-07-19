package main

import (
	"context"
	"fmt"

	"github.com/google/go-github/v75/github"

	"github.com/sioakim/attestward/internal/collect"
)

// repoInfo is the minimal repo metadata scope resolution needs.
type repoInfo struct {
	Name     string
	Archived bool
	Fork     bool
}

// repoLister lists an account's repos — abstracted so tests can inject a
// fixture-backed implementation instead of hitting a real client.
// accountType picks the underlying endpoint (issue #102): an Organization
// and a personal User account are listed via different GitHub REST
// endpoints, with no single call that works for both.
type repoLister interface {
	ListRepos(ctx context.Context, account string, accountType collect.AccountType) ([]repoInfo, error)
}

// restRepoLister lists repos via the real GitHub REST API, paginating
// through every page.
type restRepoLister struct {
	client *github.Client
}

func (l *restRepoLister) ListRepos(ctx context.Context, account string, accountType collect.AccountType) ([]repoInfo, error) {
	if accountType == collect.AccountTypeUser {
		return l.listByUser(ctx, account)
	}
	return l.listByOrg(ctx, account)
}

func (l *restRepoLister) listByOrg(ctx context.Context, org string) ([]repoInfo, error) {
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

// listByUser is Repositories.ListByOrg's user-account equivalent (issue
// #102). go-github's own doc comment on ListByUser says it "lists public
// repositories for the specified user" — unlike ListByOrg, there's no
// token-visibility-aware "everything this token can see" behavior
// documented here, so a private repo owned by a personal account may not
// appear even when the token belongs to that account. resolveRepos below
// warns about this explicitly rather than silently under-scanning; passing
// --repo explicitly (bypassing listing entirely) is the reliable way to
// include a private repo owned by a user account.
func (l *restRepoLister) listByUser(ctx context.Context, user string) ([]repoInfo, error) {
	var all []repoInfo
	opts := &github.RepositoryListByUserOptions{ListOptions: github.ListOptions{PerPage: 100}}

	for {
		repos, resp, err := l.client.Repositories.ListByUser(ctx, user, opts)
		if err != nil {
			return nil, fmt.Errorf("list repos for user %s: %w", user, err)
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

// orgChecker confirms the scan's target account is visible with the token
// in use — the preflight check issue #10 asks for — and reports which kind
// of account it is (issue #102), and (as a side effect) the guaranteed
// first authenticated call: HasWriteScope()'s least-privilege warning has
// nothing to report on until at least one authenticated response has been
// observed (internal/collect/github/scopes.go), so this must run before
// that warning is checked, not after resolveRepos alone (which makes zero
// API calls whenever repos are given explicitly — the documented usage in
// examples/attestor.yaml).
type orgChecker interface {
	CheckAccount(ctx context.Context, account string) (collect.AccountType, error)
}

// restOrgChecker checks account visibility and type via the real GitHub
// REST API.
type restOrgChecker struct {
	client *github.Client
}

// CheckAccount calls GET /users/{account} rather than GET /orgs/{account}:
// unlike the org-only endpoint, this one resolves either an Organization or
// a personal User account (issue #102) — GitHub's API returns the same
// resource shape either way, distinguished by the Type field. A genuine
// "account doesn't exist" error still fails preflight exactly as it always
// has; this only removes the false preflight failure for a *valid*
// personal-account target. Any Type value other than "Organization"
// (in practice just "User"; GitHub does not return other values for a repo
// owner) is treated as AccountTypeUser — the only thing that actually
// matters to a collector is whether the org-scoped API surface applies,
// not enumerating every account type GitHub's schema could theoretically
// return.
func (c *restOrgChecker) CheckAccount(ctx context.Context, account string) (collect.AccountType, error) {
	u, _, err := c.client.Users.Get(ctx, account)
	if err != nil {
		return collect.AccountTypeUnknown, err
	}
	if u.GetType() == "Organization" {
		return collect.AccountTypeOrganization, nil
	}
	return collect.AccountTypeUser, nil
}

// resolveRepos returns the explicit repo list if non-empty (blank entries
// dropped — a stray `--repo=""` must not silently become a repo literally
// named ""), or every non-archived, non-fork repo in the account otherwise —
// printing a warning when it does the latter, per issue #10's "empty = all
// non-archived, non-fork repos with a warning" requirement. For a personal
// user account (issue #102), the warning additionally flags that only
// public repos are listed this way — see listByUser's doc comment.
func resolveRepos(ctx context.Context, lister repoLister, account string, accountType collect.AccountType, explicit []string, warn func(string)) ([]string, error) {
	filtered := make([]string, 0, len(explicit))
	for _, r := range explicit {
		if r != "" {
			filtered = append(filtered, r)
		}
	}
	if len(filtered) > 0 {
		return filtered, nil
	}

	all, err := lister.ListRepos(ctx, account, accountType)
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
	if accountType == collect.AccountTypeUser {
		warn(fmt.Sprintf("no repos specified — scanning all %d non-archived, non-fork PUBLIC repos visible for user account %s (private repos owned by a personal account aren't listed automatically; pass --repo explicitly to include them)", len(repos), account))
	} else {
		warn(fmt.Sprintf("no repos specified — scanning all %d non-archived, non-fork repos in %s", len(repos), account))
	}
	return repos, nil
}
