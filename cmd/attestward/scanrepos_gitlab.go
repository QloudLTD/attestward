package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
)

// gitlabRepoLister lists the projects in a GitLab group.
//
// Without this, `scan --platform gitlab` required an explicit --repo for
// every project, which is unusable on a group of any size and silently
// invites under-scanning: a producer who lists four of their nine projects
// gets a pack that looks complete and attests to four.
//
// # Subgroups are included, deliberately
//
// GET /groups/{id}/projects returns only direct children unless
// include_subgroups=true. GitLab organisations habitually nest — a top-level
// group per business unit, subgroups per team — so scanning only the top
// level would miss most of the estate while appearing to succeed. That is
// the same class of quiet incompleteness the pagination handling exists to
// prevent, so this asks for the whole tree.
//
// # Archived projects are filtered by the caller, not here
//
// GitLab does have an archived flag, unlike Gogs, so it is read and returned
// and resolveRepos' existing filter does the work. archived=false is NOT
// passed as a query parameter: letting the server filter would hide from the
// pack how many projects were skipped and why.
type gitlabRepoLister struct {
	client *gitlabcollect.Client
}

// gitlabProject is the subset of GitLab's project shape scope resolution
// needs. Path, not Name: Name is the human label ("My Project") while Path is
// the URL segment ("my-project"), and every other endpoint addresses a
// project by path.
type gitlabProject struct {
	// PathWithNamespace, not Path. Path is the last URL segment only, so a
	// project at group/team-a/proj comes back as "proj" and is then addressed
	// as group/proj — a project that usually does not exist, and when it does,
	// is a DIFFERENT repository. That scanned one project twice under two
	// identical rows while never reading the subgroup one, which is the same
	// silent-incompleteness failure include_subgroups exists to prevent.
	PathWithNamespace string `json:"path_with_namespace"`
	Path              string `json:"path"`
	Archived          bool   `json:"archived"`
	// ForkedFromProject is present only on forks, so its presence is the
	// fork signal — GitLab has no boolean "fork" field the way Gogs does.
	ForkedFromProject *struct {
		ID int `json:"id"`
	} `json:"forked_from_project"`
}

// ListRepos implements repoLister. accountType is accepted to satisfy the
// interface and ignored.
//
// ⚠ This lists a GROUP. /groups/{id}/projects 404s for a personal user
// namespace, whose projects come from /users/{id}/projects instead. Scanning a
// user namespace is not supported yet; --repo must be passed explicitly, and
// the 404 reason names the group so the cause is visible rather than mysterious.
func (l *gitlabRepoLister) ListRepos(ctx context.Context, account string, _ collect.AccountType) ([]repoInfo, error) {
	q := url.Values{}
	q.Set("include_subgroups", "true")
	// with_shared=false: a project shared *into* this group belongs to
	// another namespace and is another producer's to attest to. Including it
	// would put someone else's repository in this pack.
	q.Set("with_shared", "false")

	projects, err := gitlabcollect.GetJSONPaged[gitlabProject](ctx, l.client,
		"/groups/"+url.PathEscape(account)+"/projects", q)
	if err != nil {
		return nil, fmt.Errorf("list projects for group %s: %w", account, err)
	}

	// Strip the group prefix using the CANONICAL full_path from the API, not
	// the string the user typed. --org is matched case-insensitively by GitLab
	// and may be a numeric ID, so "MyGroup" or "42" would both fail a literal
	// prefix test and leave every name as its full path — which then re-joins
	// downstream to "MyGroup/MyGroup/team-a/proj" and 404s the entire scan.
	// One extra call buys a scan that cannot silently address the wrong thing.
	prefix := account + "/"
	var g struct {
		FullPath string `json:"full_path"`
	}
	if err := gitlabcollect.GetJSON(ctx, l.client, "/groups/"+url.PathEscape(account), nil, &g); err == nil && g.FullPath != "" {
		prefix = g.FullPath + "/"
	}
	out := make([]repoInfo, 0, len(projects))
	for _, p := range projects {
		name := p.PathWithNamespace
		// Case-insensitive: GitLab paths are lowercased, but a self-managed
		// instance or an older project can differ in case from the group.
		if len(name) >= len(prefix) && strings.EqualFold(name[:len(prefix)], prefix) {
			name = name[len(prefix):]
		} else if name == "" {
			name = p.Path
		}
		out = append(out, repoInfo{
			Name:     name,
			Archived: p.Archived,
			Fork:     p.ForkedFromProject != nil,
		})
	}
	return out, nil
}
