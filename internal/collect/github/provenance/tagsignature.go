package provenance

import (
	"context"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "github.com/sioakim/attestward/internal/collect/github"
)

// tagSignature is the resolved signature-verification state of one
// release's tag, plus the commit SHA it ultimately points at (needed by
// the commit-linkage check regardless of whether the tag is signed).
type tagSignature struct {
	CommitSHA string
	Annotated bool
	Signed    bool
	Verified  bool
	Reason    string
}

// resolveTagSignature resolves tagName to its commit SHA and, for an
// annotated tag, its signature-verification status via REST's
// GitService.GetTag (which returns a Verification field — the same shape
// used on commits — for annotated tag objects). GraphQL was considered and
// rejected: its Tag object has no signature field at all (only Commit
// does; confirmed via schema introspection), so REST is not just
// sufficient here but the only path that actually exposes annotated-tag
// signature verification.
//
// A lightweight tag has no separate tag object and thus can never be
// signed — git's own object model only lets `git tag -s` (which always
// creates an annotated tag) attach a signature. So a lightweight tag's
// Signed/Verified are unconditionally false, with a Reason explaining why,
// and no second API call is needed to know that.
func resolveTagSignature(ctx context.Context, client *ghcollect.Client, org, repo, tagName string) (tagSignature, error) {
	ref, _, err := client.REST.Git.GetRef(ctx, org, repo, "tags/"+tagName)
	if err != nil {
		return tagSignature{}, err
	}
	obj := ref.GetObject()
	if obj.GetType() != "tag" {
		return tagSignature{
			CommitSHA: obj.GetSHA(),
			Annotated: false,
			Reason:    "lightweight tag (not annotated; cannot be signed)",
		}, nil
	}

	tag, _, err := client.REST.Git.GetTag(ctx, org, repo, obj.GetSHA())
	if err != nil {
		return tagSignature{}, err
	}
	v := tag.GetVerification()
	return tagSignature{
		CommitSHA: tag.GetObject().GetSHA(),
		Annotated: true,
		Signed:    v.GetSignature() != "",
		Verified:  v.GetVerified(),
		Reason:    verificationReason(v),
	}, nil
}

// verificationReason gives a human-readable reason even when GetTag
// succeeds but returns no Verification at all (a nil *SignatureVerification
// — GetReason() on a nil receiver safely returns "", which would otherwise
// read as a blank, unhelpful Facts value).
func verificationReason(v *ghgithub.SignatureVerification) string {
	if v == nil {
		return "no verification data returned for this tag"
	}
	if r := v.GetReason(); r != "" {
		return r
	}
	return "unsigned"
}
