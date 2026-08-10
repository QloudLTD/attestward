package vdp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"

	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
)

// candidatePaths mirrors azuredevops/vdp's own two-path chain exactly, for
// the identical reason: GitLab, like Azure DevOps and unlike GitHub,
// documents no community-health-file search order and has no org-wide
// default-repo mechanism (see C10.vdp.security-policy-org, always
// not-checkable for that reason) — this is purely a repo-content
// convention this collector checks for, not one GitLab itself enforces.
var candidatePaths = []string{"SECURITY.md", "docs/SECURITY.md"}

type resolvedSecurityMD struct {
	Path    string
	Content string
	Found   bool
}

// repositoryFile is the subset of GitLab's Repository Files response
// (GET /projects/:id/repository/files/:file_path) this needs, verified
// 2026-08-11 against this repo's own live, real SECURITY.md.
type repositoryFile struct {
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

// resolveSecurityMD walks candidatePaths against one project via GET
// /projects/{id}/repository/files/{path}?ref={defaultBranch}, returning
// the first match.
//
// Unlike the GitHub and Azure DevOps twins' combined file/tree endpoints,
// GitLab's Repository Files API addresses a single file blob and has no
// isFolder ambiguity to resolve: a path that is a directory, not a file,
// 404s here exactly like a path that doesn't exist at all — a
// SECURITY.md/ directory cannot be silently mistaken for a resolved file
// the way it could on the other two platforms.
//
// A 404 at one candidate path means "try the next one", not an error —
// the same convention as both twins, with the same caveat: a 404 also
// covers a project that doesn't exist or isn't visible to this token,
// indistinguishable from this call alone.
//
// Two further guards exist for a 2xx response that isn't actually a
// readable file, mirroring the judgment call review already made for the
// Azure DevOps twin (found there, applies identically here): encoding
// must be "base64" — GitLab's documented and, so far, only observed
// value — and the decoded content must be non-empty, or this is a
// genuine error (not-checkable), never treated as "keep trying, not
// found". Trusting an unrecognised 2xx shape as a resolved SECURITY.md
// would be worse than reporting not-checkable: it could pass a repo that
// was never actually read.
func resolveSecurityMD(ctx context.Context, client *gitlabcollect.Client, projID, defaultBranch string) (resolvedSecurityMD, error) {
	for _, path := range candidatePaths {
		var f repositoryFile
		q := url.Values{"ref": {defaultBranch}}
		err := gitlabcollect.GetJSON(ctx, client, "/projects/"+projID+"/repository/files/"+escapePath(path), q, &f)
		if err != nil {
			if code, ok := gitlabcollect.StatusCodeOf(err); ok && code == 404 {
				continue
			}
			return resolvedSecurityMD{}, err
		}

		if f.Encoding != "base64" {
			return resolvedSecurityMD{}, fmt.Errorf(
				"repository files returned an unexpected encoding %q for %s, want base64", f.Encoding, path)
		}
		decoded, decErr := base64.StdEncoding.DecodeString(f.Content)
		if decErr != nil {
			return resolvedSecurityMD{}, fmt.Errorf("repository files returned undecodable base64 content for %s: %w", path, decErr)
		}
		if len(decoded) == 0 {
			return resolvedSecurityMD{}, fmt.Errorf(
				"repository files returned a 2xx response for %s but decoded to empty content — "+
					"indistinguishable from this response alone from a genuinely empty file", path)
		}
		return resolvedSecurityMD{Path: path, Content: string(decoded), Found: true}, nil
	}
	return resolvedSecurityMD{}, nil
}
