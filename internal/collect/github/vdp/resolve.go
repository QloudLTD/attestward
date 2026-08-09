package vdp

import (
	"context"
	"net/http"

	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
)

// candidatePaths is GitHub's documented community-health-file search
// order within a single repo — confirmed against GitHub's own docs
// ("Creating a default community health file"): the .github folder, then
// the repository root, then the docs folder. This applies to SECURITY.md
// the same as every other community health file type GitHub names
// (CONTRIBUTING.md, CODE_OF_CONDUCT.md, etc.) — the docs don't spell out
// SECURITY.md's own order separately, but state the general rule applies
// to the whole file-type list SECURITY.md is explicitly a member of.
var candidatePaths = []string{".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md"}

// resolvedSecurityMD is the outcome of walking candidatePaths against one
// repo (see resolveSecurityMD for the org-.github fallback on top of
// this).
type resolvedSecurityMD struct {
	// Repo is "owner/repo" of wherever the file actually resolved —
	// which may differ from the repo being scanned if resolution fell
	// back to the org's .github repo.
	Repo    string
	Path    string
	Content string
	Found   bool
}

// resolveSecurityMDInRepo walks candidatePaths against one specific
// owner/repo and returns the first match. A 404 at a given path means
// "try the next one", not an error — only a non-404 failure (403,
// unreachable, etc.) is treated as a real error, since GitHub's Contents
// API 404s for every path that simply doesn't have a file there,
// including when owner/repo doesn't exist at all (the same signal, not
// distinguishable from this call alone — callers needing to tell those
// apart, like checkSecurityPolicyOrg, check the repo's existence
// separately first). A file that GetContents finds but GetContent can't
// decode (GitHub returns encoding "none" — undecodable inline — for
// files over 1MB, among other cases) is likewise a real error, not a
// "not found": the file demonstrably exists, so reporting it as absent
// would be a false verified-fail rather than an honest not-checkable.
func resolveSecurityMDInRepo(ctx context.Context, client *ghcollect.Client, owner, repo string) (resolvedSecurityMD, error) {
	for _, path := range candidatePaths {
		content, _, resp, err := client.REST.Repositories.GetContents(ctx, owner, repo, path, nil)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				continue
			}
			return resolvedSecurityMD{}, err
		}
		if content == nil {
			continue
		}
		raw, err := content.GetContent()
		if err != nil {
			return resolvedSecurityMD{}, err
		}
		return resolvedSecurityMD{Repo: owner + "/" + repo, Path: path, Content: raw, Found: true}, nil
	}
	return resolvedSecurityMD{}, nil
}

// resolveSecurityMD implements GitHub's full documented fallback: try the
// scanned repo first; if nothing resolves there, try the org's own
// ".github" repo (GitHub's org-wide default community-health-file repo)
// using the same candidatePaths order. A resolveErr from either call is
// returned immediately — a genuine API failure (as opposed to "not
// found") should surface as not-checkable to every caller, not be
// silently treated as "keep trying."
func resolveSecurityMD(ctx context.Context, client *ghcollect.Client, org, repo string) (resolvedSecurityMD, error) {
	r, err := resolveSecurityMDInRepo(ctx, client, org, repo)
	if err != nil {
		return resolvedSecurityMD{}, err
	}
	if r.Found {
		return r, nil
	}
	return resolveSecurityMDInRepo(ctx, client, org, ".github")
}
