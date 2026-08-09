package vdp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops"
)

// candidatePaths is the two-path chain issue #154 (S8/C10) specifies for
// Azure DevOps: unlike GitHub, which documents a community-health-file
// search order (.github/, repo root, docs/) this project's GitHub twin
// walks, Azure DevOps has no platform-level SECURITY.md convention at
// all — this is purely a repo-content convention this collector checks
// for, not one Azure DevOps itself enforces or searches on the producer's
// behalf. There is also no org-wide-default-repo mechanism the way
// GitHub's own ".github" special repo works (see C10.vdp.security-policy-org,
// always not-checkable for that exact reason), so there is no third,
// cross-repo fallback step to add here.
var candidatePaths = []string{"/SECURITY.md", "/docs/SECURITY.md"}

// resolvedSecurityMD is the outcome of walking candidatePaths against one
// repo.
type resolvedSecurityMD struct {
	Path    string
	Content string
	Found   bool
}

// gitItemRaw is the subset of Azure DevOps's GitItem shape (Items - Get)
// resolveSecurityMD needs to tell a real, readable file apart from a
// folder or a shape this collector doesn't understand — see
// resolveSecurityMD's own doc comment for why each field matters (found in
// review: decoding Content alone let a folder named SECURITY.md silently
// verified-pass with empty content).
type gitItemRaw struct {
	IsFolder      bool   `json:"isFolder"`
	GitObjectType string `json:"gitObjectType"`
	ObjectID      string `json:"objectId"`
	Content       string `json:"content"`
}

// resolveSecurityMD walks candidatePaths against one repo via GET
// .../{project}/_apis/git/repositories/{repositoryId}/items?path=...&
// includeContent=true&$format=json&api-version=7.1, returning the first
// match. repositoryId accepts either the repository's name or its GUID
// (Microsoft's own Items - Get reference: "The name or ID of the
// repository") — scope.Repos already holds names, so no separate
// name-to-GUID resolution call is needed here, unlike
// C09.repo.webhooks' publisherInputs.projectId comparison, which is
// always a GUID with no name-acceptance.
//
// $format=json is required, not optional: Items - Get is content-negotiated,
// and the transport this project's Client uses sets no Accept header at
// all, so its documented default response for a file blob is the raw byte
// stream, not a JSON envelope — without this parameter, decoding into
// gitItemRaw would fail on every real (non-fixture) response, since
// adofixture always replies with JSON regardless of what's requested and
// so cannot catch this by itself (the same lesson
// pipelinehistory.FetchYAMLContent's own doc comment records, found in
// review of #168). This precondition — and the isFolder/gitObjectType/
// objectId shape assumption immediately below, which the same "no live
// org to record a real response against yet" limitation applies to — is
// part of what the S9 recorded-fixture verification pass (issue #34/#155)
// must confirm [fixture-verify].
//
// A 404 at one candidate path means "try the next one", not an error —
// matching the GitHub twin's resolveSecurityMDInRepo, and with the same
// caveat: Items - Get 404s for every path with no file there, including
// when the repository itself doesn't exist or isn't visible to this
// token — indistinguishable from this call alone. A 2xx response with
// IsFolder true is treated identically (try the next path): a folder
// happening to be named SECURITY.md is not a file this check could ever
// read, the same way GitHub's own GetContents returns a directory
// listing (content == nil) for a path that's a folder there, which the
// GitHub twin's resolveSecurityMDInRepo also treats as "keep trying, not
// found" rather than a match.
//
// Two further guards exist because a bare "does the JSON decode" check
// isn't enough to trust a 2xx response as a real, read file — found in
// review, both against the same failure mode: a 2xx response silently
// treated as a resolved SECURITY.md when it wasn't actually one.
//   - GitObjectType must be "blob" and ObjectID must be non-empty, or this
//     returns a genuine error (not-checkable, not "try the next path"):
//     an unexpected-but-2xx shape (this collector has no live Entra org to
//     confirm every shape Items - Get can return) must not be silently
//     trusted as a resolved file.
//   - A validated blob whose Content field is still empty is likewise a
//     genuine error, not a match: Azure DevOps may omit inline content for
//     some content types even with includeContent=true (e.g. binary), and
//     this collector can't distinguish that from a genuinely empty file —
//     mirroring the GitHub twin's own identical judgment call for a file
//     GetContents finds but GetContent can't decode ("the file
//     demonstrably exists, so reporting it as absent would be a false
//     verified-fail rather than an honest not-checkable").
func resolveSecurityMD(ctx context.Context, client *azuredevops.Client, project, repo string) (resolvedSecurityMD, error) {
	for _, path := range candidatePaths {
		reqPath := fmt.Sprintf("/%s/%s/_apis/git/repositories/%s/items", client.Org(), project, repo)
		query := url.Values{
			"path":           {path},
			"includeContent": {"true"},
			"$format":        {"json"},
			"api-version":    {"7.1"},
		}

		var item gitItemRaw
		err := azuredevops.GetJSONObject(ctx, client, azuredevops.HostCore, reqPath, query, &item)
		if err != nil {
			var se *azuredevops.StatusError
			if errors.As(err, &se) && se.StatusCode == http.StatusNotFound {
				continue
			}
			return resolvedSecurityMD{}, err
		}

		if item.IsFolder {
			continue
		}
		if item.GitObjectType != "blob" || item.ObjectID == "" {
			return resolvedSecurityMD{}, fmt.Errorf(
				"items - get returned an unexpected shape for %s: gitObjectType=%q objectId=%q, want a blob with a non-empty objectId",
				path, item.GitObjectType, item.ObjectID)
		}
		if item.Content == "" {
			return resolvedSecurityMD{}, fmt.Errorf(
				"items - get returned a 2xx response for %s but no content field was populated — likely a "+
					"content type Azure DevOps doesn't inline (e.g. binary) despite includeContent=true, "+
					"indistinguishable from this response alone from a genuinely empty file", path)
		}
		return resolvedSecurityMD{Path: path, Content: item.Content, Found: true}, nil
	}
	return resolvedSecurityMD{}, nil
}
