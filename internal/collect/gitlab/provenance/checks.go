package provenance

import (
	"context"
	"fmt"

	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/model"
)

type releaseVerdict int

const (
	releasePassed releaseVerdict = iota
	releaseFailed
	releaseUnresolved
)

// releaseCheckResult is one release's verdict, in the shape
// rollupReleaseResults consumes. Reproduced from the GitHub twin's
// identical type per ADR-0005.
type releaseCheckResult struct {
	TagName string
	Verdict releaseVerdict
	Reason  string
	Facts   map[string]any
}

// rollupReleaseResults: "overall status = worst recent release, with
// per-release table in facts." A confirmed failure anywhere always wins —
// an unresolvable release elsewhere doesn't soften a genuine gap. Absent
// any confirmed failure, an unresolvable release caps the result at
// partial rather than reading as a clean pass. Only when every release
// both resolved and passed does this reach verified-pass. Reproduced from
// the GitHub twin's identical function per ADR-0005.
func rollupReleaseResults(results []releaseCheckResult) (model.Status, []map[string]any) {
	table := make([]map[string]any, 0, len(results))
	anyFailed, anyUnresolved := false, false
	for _, r := range results {
		row := map[string]any{"tag": r.TagName, "passed": r.Verdict == releasePassed, "reason": r.Reason}
		for k, v := range r.Facts {
			row[k] = v
		}
		table = append(table, row)
		switch r.Verdict {
		case releaseFailed:
			anyFailed = true
		case releaseUnresolved:
			anyUnresolved = true
		}
	}
	switch {
	case anyFailed:
		return model.StatusVerifiedFail, table
	case anyUnresolved:
		return model.StatusPartial, table
	default:
		return model.StatusVerifiedPass, table
	}
}

func checkChecksums(org, repo string, releases []releaseInfo, prov []model.Provenance) model.CheckResult {
	const id = idChecksums
	if len(releases) == 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: noReleasesInWindowReason,
			Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		}
	}
	results := make([]releaseCheckResult, 0, len(releases))
	for _, rel := range releases {
		matched := matchingAssetNames(rel.AssetNames, checksumAssetPatterns)
		verdict, reason := releaseFailed, "no checksum asset found among this release's assets"
		if len(matched) > 0 {
			verdict, reason = releasePassed, fmt.Sprintf("checksum asset(s) found: %v", matched)
		}
		results = append(results, releaseCheckResult{TagName: rel.TagName, Verdict: verdict, Reason: reason,
			Facts: map[string]any{"matched_assets": matched}})
	}
	status, table := rollupReleaseResults(results)
	reason := "every release in the lookback window ships a checksum asset"
	if status == model.StatusVerifiedFail {
		reason = "at least one release in the lookback window has no checksum asset"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		Facts: map[string]any{"per_release": table},
	}
}

func checkSignatures(org, repo string, releases []releaseInfo, prov []model.Provenance) model.CheckResult {
	const id = idSignatures
	if len(releases) == 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: noReleasesInWindowReason,
			Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		}
	}
	results := make([]releaseCheckResult, 0, len(releases))
	for _, rel := range releases {
		matched := matchingAssetNames(rel.AssetNames, signatureAssetPatterns)
		verdict, reason := releaseFailed, "no signature/attestation asset found among this release's assets"
		if len(matched) > 0 {
			verdict, reason = releasePassed, fmt.Sprintf("signature asset(s) found: %v", matched)
		}
		results = append(results, releaseCheckResult{TagName: rel.TagName, Verdict: verdict, Reason: reason,
			Facts: map[string]any{"matched_assets": matched}})
	}
	status, table := rollupReleaseResults(results)
	reason := "every release in the lookback window ships a signature/attestation asset"
	if status == model.StatusVerifiedFail {
		reason = "at least one release in the lookback window has no signature/attestation asset"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		Facts: map[string]any{"per_release": table},
	}
}

// checkTagsSigned looks up each release tag's own signature independently
// — one call per tag, GET /projects/:id/repository/tags/:tag/signature —
// since GitLab has no bulk endpoint that returns verification status
// alongside the release/tag listing the way it does for release assets.
//
// A 404 means genuinely unsigned (verified live against an unsigned tag on
// the scratch project: {"message":"404 Signature Not Found"}) — a
// confirmed fail, not a gap. Any other error is unresolved: it says
// nothing about whether the tag is actually signed.
func checkTagsSigned(ctx context.Context, client *gitlabcollect.Client, org, repo string, releases []releaseInfo) model.CheckResult {
	const id = idTagsSigned
	projID := projectID(org, repo)

	if len(releases) == 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: noReleasesInWindowReason,
			Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: client.Provenance(),
		}
	}

	results := make([]releaseCheckResult, 0, len(releases))
	for _, rel := range releases {
		var sig tagSignature
		err := gitlabcollect.GetJSON(ctx, client, "/projects/"+projID+"/repository/tags/"+escapePath(rel.TagName)+"/signature", nil, &sig)
		switch {
		case err == nil && sig.VerificationStatus == "verified":
			results = append(results, releaseCheckResult{TagName: rel.TagName, Verdict: releasePassed,
				Reason: "signed, verification_status \"verified\""})
		case err == nil && sig.VerificationStatus == "":
			// A 2xx response with no verification_status field says nothing
			// about whether the tag is signed — that's not the documented
			// signed/unsigned shape, so it's unresolved, not a confirmed
			// fail asserting a signed-but-bad state that was never observed.
			results = append(results, releaseCheckResult{TagName: rel.TagName, Verdict: releaseUnresolved,
				Reason: "signature endpoint returned 2xx with no verification_status field"})
		case err == nil:
			results = append(results, releaseCheckResult{TagName: rel.TagName, Verdict: releaseFailed,
				Reason: fmt.Sprintf("signed, but verification_status is %q, not \"verified\"", sig.VerificationStatus)})
		default:
			if code, ok := gitlabcollect.StatusCodeOf(err); ok && code == 404 {
				results = append(results, releaseCheckResult{TagName: rel.TagName, Verdict: releaseFailed,
					Reason: "tag is not signed (404 at the signature endpoint)"})
				continue
			}
			results = append(results, releaseCheckResult{TagName: rel.TagName, Verdict: releaseUnresolved,
				Reason: fmt.Sprintf("could not look up this tag's signature: %v", err)})
		}
	}

	status, table := rollupReleaseResults(results)
	reason := "every release tag in the lookback window is signed and verified"
	switch status {
	case model.StatusVerifiedFail:
		reason = "at least one release tag in the lookback window is unsigned or unverified"
	case model.StatusPartial:
		reason = "every resolvable release tag is signed and verified, but at least one tag's signature lookup itself failed"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: client.Provenance(),
		Facts: map[string]any{"per_release": table},
	}
}
