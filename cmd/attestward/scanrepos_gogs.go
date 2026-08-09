package main

import (
	"context"
	"fmt"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gogscollect "gitlab.com/sioakeim/attestward/internal/collect/gogs"
)

// gogsRepoLister lists an account's repos on a self-hosted Gogs instance.
//
// Unlike the GitHub lister, it does not branch on accountType, and that is
// a property of the platform rather than a shortcut. Verified against Gogs
// 0.15 on 2026-08-03: GET /users/{name}/repos, GET /orgs/{name}/repos and
// GET /user/repos all returned the identical 48 repositories for the same
// account, and the org-scoped path answered 200 for a name that is a
// personal user, not an organization. Gogs simply does not enforce the
// distinction here, so picking an endpoint by account type would be
// ceremony that decides nothing. GET /users/{name}/repos is used because
// it names the account explicitly — GET /user/repos would silently list
// the token owner's repos instead of the requested account's, which is the
// kind of quiet substitution that produces a pack attributed to the wrong
// subject.
//
// The response includes private repositories the token can see, so a
// personal account's private repos are listed here — the GitHub side's
// documented under-scanning caveat for user accounts does not apply.
type gogsRepoLister struct {
	client *gogscollect.Client
}

// gogsRepo is the subset of Gogs' repository shape scope resolution needs.
// Gogs has no "archived" concept at all, so Archived is never set on the
// repoInfo values this returns — see ListRepos.
type gogsRepo struct {
	Name   string `json:"name"`
	Fork   bool   `json:"fork"`
	Mirror bool   `json:"mirror"`
	Empty  bool   `json:"empty"`
}

// ListRepos implements repoLister. accountType is accepted to satisfy the
// interface and deliberately ignored — see the type's doc comment.
//
// Archived is left false on every returned repo because Gogs has no
// archive state: there is no field to read and no UI concept behind it.
// That means resolveRepos' archived-repo filtering is a no-op here, which
// is correct — it filters out repos a platform has marked read-only, and
// no Gogs repo ever is. It is called out because a reader comparing
// platforms would otherwise reasonably wonder whether the field was simply
// forgotten.
func (l *gogsRepoLister) ListRepos(ctx context.Context, account string, _ collect.AccountType) ([]repoInfo, error) {
	var repos []gogsRepo
	path := fmt.Sprintf("/users/%s/repos", account)
	if err := gogscollect.GetJSON(ctx, l.client, path, nil, &repos); err != nil {
		return nil, fmt.Errorf("list repos for account %s: %w", account, err)
	}

	out := make([]repoInfo, 0, len(repos))
	for _, r := range repos {
		out = append(out, repoInfo{Name: r.Name, Fork: r.Fork})
	}
	return out, nil
}
