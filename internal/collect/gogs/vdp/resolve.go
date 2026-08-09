package vdp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	gogscollect "gitlab.com/sioakeim/attestward/internal/collect/gogs"
)

// candidatePaths is the chain this collector walks looking for a
// vulnerability-disclosure policy, in order.
//
// Gogs has no platform-level SECURITY.md convention of any kind — it does
// not search for one, surface one in its UI, or treat `.github/` specially
// — so unlike the GitHub twin, which walks GitHub's own documented
// community-health-file search order, this is purely a repo-content
// convention being checked for. `.github/SECURITY.md` is included anyway,
// first: a great many Gogs repos are mirrors of, or migrations from,
// GitHub and carry the file at that path, and the file being present in
// the tree is a true observation about the repo regardless of whether the
// hosting platform assigns it meaning. What must not be claimed is that
// Gogs *does* anything with it, and no Reason or Rubric in this package
// claims that.
//
// There is no org-wide-default mechanism to fall back to the way GitHub's
// special `.github` repo works — see C10.vdp.security-policy-org, always
// not-checkable for that reason.
var candidatePaths = []string{".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md"}

// resolvedSecurityMD is the outcome of walking candidatePaths against one
// repo.
type resolvedSecurityMD struct {
	Path    string
	Content string
	Found   bool
}

// contentsEntry is the subset of Gogs' contents-API response this
// collector needs. Verified against Gogs 0.15 on 2026-08-03: a file
// returns {"type":"file","encoding":"base64","size":N,"name":...,
// "path":...,"content":"<base64>"}.
//
// Type and Encoding are both checked rather than assumed. A directory path
// returns a JSON *array* instead of an object (also verified), which is
// why resolveSecurityMD inspects the raw shape before decoding — the Azure
// DevOps twin found in review that decoding content alone let a *folder*
// named SECURITY.md silently verified-pass with empty content, and the
// same trap exists here in a different shape.
type contentsEntry struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Size     int    `json:"size"`
	Path     string `json:"path"`
	Content  string `json:"content"`
}

// resolveSecurityMD walks candidatePaths against one repo via
// GET /repos/{owner}/{repo}/contents/{path}, returning the first real file
// that resolves.
//
// A 404 at one path is not an error — it means "try the next one" — and a
// 404 at every path means the policy genuinely is not there, which is a
// confirmed observation the caller reports as verified-fail. Any other
// failure (auth, a 5xx that survived retry, an undecodable body) is
// returned as an error, so the caller reports not-checkable instead of
// asserting an absence it never established. That distinction is the whole
// point: this codebase's recurring defect class is a value that silently
// defaults on error and is then presented as a confirmed observation.
func resolveSecurityMD(ctx context.Context, client *gogscollect.Client, owner, repo string) (resolvedSecurityMD, error) {
	for _, path := range candidatePaths {
		endpoint := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, path)

		var raw json.RawMessage
		err := gogscollect.GetJSON(ctx, client, endpoint, nil, &raw)
		if err != nil {
			if code, ok := gogscollect.StatusCodeOf(err); ok && code == http.StatusNotFound {
				continue
			}
			return resolvedSecurityMD{}, err
		}

		entry, ok, err := decodeFileEntry(raw)
		if err != nil {
			return resolvedSecurityMD{}, fmt.Errorf("%s: %w", path, err)
		}
		if !ok {
			// A directory, a submodule, or a symlink at this path.
			// Not a policy file, and not an error either — keep
			// walking rather than reporting a find that isn't one.
			continue
		}

		content, err := base64.StdEncoding.DecodeString(entry.Content)
		if err != nil {
			return resolvedSecurityMD{}, fmt.Errorf("%s: decode base64 content: %w", path, err)
		}
		return resolvedSecurityMD{Path: path, Content: string(content), Found: true}, nil
	}
	return resolvedSecurityMD{}, nil
}

// decodeFileEntry interprets one contents-API response body. It reports
// (entry, true, nil) only for a genuine base64-encoded file; (_, false,
// nil) for a shape that is validly something else (a directory, which
// comes back as a JSON array, or an entry whose type isn't "file"); and an
// error for a body this collector cannot interpret at all.
//
// An unexpected encoding is an error rather than a skip: silently treating
// a file whose content this collector could not read as "no policy here"
// would report a confirmed absence on the strength of a decoding failure.
func decodeFileEntry(raw json.RawMessage) (contentsEntry, bool, error) {
	trimmed := leadingNonSpace(raw)
	if trimmed == '[' {
		return contentsEntry{}, false, nil // a directory listing
	}

	var entry contentsEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return contentsEntry{}, false, fmt.Errorf("decode contents response: %w", err)
	}
	if entry.Type != "file" {
		return contentsEntry{}, false, nil
	}
	if entry.Encoding != "base64" {
		return contentsEntry{}, false, fmt.Errorf("unexpected content encoding %q (want base64)", entry.Encoding)
	}
	return entry, true, nil
}

// leadingNonSpace returns the first non-whitespace byte of raw, or 0 for an
// empty or all-whitespace body — enough to tell a JSON array from an
// object without decoding twice.
func leadingNonSpace(raw []byte) byte {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return b
		}
	}
	return 0
}
