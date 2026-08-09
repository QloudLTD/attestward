package pipelinehistory

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops"
)

// RepositoryInfo is the minimal repository data any per-repo caller of this
// package needs to resolve before calling its other functions: every one
// of them (ResolveReleases, FetchBuilds, LinkRunsToReleases, MatchPipelines'
// own repo-filtering via MatchedPipeline.RepositoryID) takes a repository
// ID and/or a default branch, neither of which collect.Scope.Repos (repo
// NAMES) carries directly.
type RepositoryInfo struct {
	ID            string
	Name          string
	DefaultBranch string
}

// repositoryRaw is the subset of Azure DevOps's GitRepository shape
// (Repositories - List) FetchRepositories needs — mirrors
// repoprotection's own identical, independently-defined type (a repo's
// default branch, absent entirely for a genuinely empty repository, is a
// fact every ADO collector reading repository metadata needs the same
// way, verified against the same Microsoft reference sample response).
type repositoryRaw struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	DefaultBranch string `json:"defaultBranch"`
}

// FetchRepositories lists every repository in project via GET
// .../{project}/_apis/git/repositories (Repositories - List, scope
// vso.code) — the project-scoped call a per-repo caller uses once per
// Collect to resolve every repo name in collect.Scope.Repos to the
// repositoryID and defaultBranch this package's other functions require,
// exactly the same repeated need C05 and C06 (issue #152's own two
// collector consumers) both have, so it lives here rather than being
// duplicated in each of their packages.
func FetchRepositories(ctx context.Context, client *azuredevops.Client, project string) ([]RepositoryInfo, error) {
	path := fmt.Sprintf("/%s/%s/_apis/git/repositories", client.Org(), project)
	query := url.Values{"api-version": {"7.1"}}

	var raw []repositoryRaw
	if err := azuredevops.GetJSON(ctx, client, azuredevops.HostCore, path, query, &raw); err != nil {
		return nil, err
	}

	out := make([]RepositoryInfo, len(raw))
	for i, r := range raw {
		// repositoryRaw and RepositoryInfo share identical field
		// names/types/order — a direct conversion, not a field-by-field
		// copy.
		out[i] = RepositoryInfo(r)
	}
	return out, nil
}

// FindRepository looks up name in repos case-insensitively — Azure DevOps
// repository names are case-insensitive (two repos cannot differ only by
// case within the same project), and a caller resolving a user-supplied
// --repo value has no repoLister to canonicalize casing against first (no
// ADO repoLister exists yet — see cmd/attestward/scan.go's own doc
// comment); a case-sensitive comparison here would report a real,
// existing repo as not-checkable ("not found") whenever --repo was typed
// in different casing than the platform stored it in.
func FindRepository(repos []RepositoryInfo, name string) (RepositoryInfo, bool) {
	for _, r := range repos {
		if strings.EqualFold(r.Name, name) {
			return r, true
		}
	}
	return RepositoryInfo{}, false
}
