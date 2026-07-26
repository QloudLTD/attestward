package pipelinehistory

import (
	"context"
	"fmt"
	"net/url"

	"github.com/sioakim/attestward/internal/collect/azuredevops"
)

// RepoEnablementInfo is GHAzDO (GitHub Advanced Security for Azure DevOps)'s
// per-repository Advanced Security feature-enablement state — flattened
// from RepoEnablementSettings' two feature blocks for caller convenience.
// Exposed here, not in a per-collector package, because C05 sast-history
// (CodeQLEnabled), C06 sca-history (DependencyScanningInjectionEnabled,
// CodeSecurityEnabled — issue #152's own C06 spec), and C04's secrets
// checks (SecretProtectionEnabled, BlockPushes) all read different fields
// off the exact same response; decoding it once here means no collector
// duplicates the request/response-shape code another already has.
type RepoEnablementInfo struct {
	CodeQLEnabled                      bool
	DependencyScanningInjectionEnabled bool
	CodeSecurityEnabled                bool
	// SecretProtectionEnabled and BlockPushes are *bool, unlike the three
	// codeSecurityFeatures fields above — see repoEnablementRaw's own doc
	// comment for why the two feature blocks need different nullability
	// treatment (found in review, addendum to issue #152/#154's original
	// C05 work: C04's own secrets checks need BlockPushes, and it is
	// genuinely null — not just "documented as nullable but never
	// actually null" the way every codeSecurityFeatures field is — when
	// includeAllProperties isn't sent, so this package must not collapse
	// that real null into a false "explicitly disabled" false).
	SecretProtectionEnabled *bool
	BlockPushes             *bool
}

// repoEnablementRaw is the subset of Azure DevOps's RepoEnablementSettings
// shape (Repo Enablement - Get) FetchRepoEnablement needs, decoded with two
// different nullability strategies for its two feature blocks:
//
//   - codeSecurityFeatures' three fields decode as plain bool, even though
//     Microsoft's own reference documents each as nullable ("Null is never
//     explicitly set") — a claim issue #190 found empirically FALSE:
//     observed 2026-07-23 against dev.azure.com/seciq (GHAzDO-unlicensed),
//     codeQLEnabled, dependencyScanningInjectionEnabled, dependabotEnabled,
//     and autofixEnabled were all literally null in the raw response when
//     codeSecurityEnabled reads false — not merely undocumented-but-never-
//     actually-null the way the doc claims, genuinely null on the wire, for
//     every one of those four fields (this struct decodes the first two of
//     them; the other two go unused, dropped silently by encoding/json like
//     every other field this project doesn't read). The plain-bool decode
//     stays correct anyway: encoding/json silently leaves a bool field at
//     its zero value (false) when the JSON value is null, which is exactly
//     the fallback every caller of these three fields wants — "genuinely
//     null" reads the same as "not enabled" for every purpose C05/C06 have,
//     so a pointer's extra nil-vs-false distinction has no caller that
//     would ever need it. Contrast secretProtectionFeatures below, where a
//     real caller (C04) DOES need to tell null apart from a confirmed
//     false.
//   - secretProtectionFeatures' two boolean fields decode as *bool instead
//     (found in review): unlike the codeSecurityFeatures trio,
//     Microsoft's own reference states blockPushes specifically "will be
//     null" whenever includeAllProperties isn't sent on the request — a
//     REAL, load-bearing null this package must be able to represent
//     rather than silently read as "explicitly disabled," which
//     FetchRepoEnablement (see its own doc comment) now avoids anyway by
//     always sending includeAllProperties=true, but a *bool here is the
//     honest representation regardless of what any future caller's
//     request shape ends up being.
type repoEnablementRaw struct {
	CodeSecurityFeatures struct {
		CodeQLEnabled                      bool `json:"codeQLEnabled"`
		DependencyScanningInjectionEnabled bool `json:"dependencyScanningInjectionEnabled"`
		CodeSecurityEnabled                bool `json:"codeSecurityEnabled"`
	} `json:"codeSecurityFeatures"`
	SecretProtectionFeatures struct {
		SecretProtectionEnabled *bool `json:"secretProtectionEnabled"`
		BlockPushes             *bool `json:"blockPushes"`
	} `json:"secretProtectionFeatures"`
}

// FetchRepoEnablement reads GHAzDO's per-repository Advanced Security
// enablement state via GET
// https://advsec.dev.azure.com/{organization}/{project}/_apis/management/repositories/{repository}/enablement?includeAllProperties=true&api-version=7.2-preview.3
// (Repo Enablement - Get, scope vso.advsec) — repositoryID accepts either
// the repository's name or its GUID (Microsoft's own reference: "The name
// or ID of the repository"), the same as every other ADO Git-repository
// path parameter this project has verified.
//
// includeAllProperties=true is always sent, unconditionally (found in
// review, addendum to the original C05 work): Microsoft's own reference
// says blockPushes reads null without it, and C04's own secrets-hygiene
// checks need that field populated. Every existing caller (C05, which
// only reads codeSecurityFeatures fields) is unaffected by always sending
// it — this parameter only adds secretProtectionFeatures.blockPushes to
// the response, it doesn't remove or change anything C05 already reads.
//
// A non-2xx response comes back as *azuredevops.StatusError unchanged, not
// specially interpreted here: azuredevops.IsAdvSecGated is the named
// predicate a caller applies to a 403/404 failure — but "GHAzDO isn't
// licensed for this org/project" is NOT what either code means for this
// endpoint (issue #190): S9's live run (2026-07-23, dev.azure.com/seciq,
// GHAzDO-unlicensed) found this endpoint returns HTTP 200 with every
// enablement flag false/null for an unlicensed org/project, not a 403 or
// 404 at all — see repoEnablementRaw's own doc comment for the same
// finding stated against the response body directly. A 403 reaching a
// caller here means the token lacks the vso.advsec scope; what actually
// produces a 404 remains genuinely unconfirmed [fixture-verify: no
// recorded response covers it] — see IsAdvSecGated's own doc comment.
func FetchRepoEnablement(ctx context.Context, client *azuredevops.Client, project, repositoryID string) (RepoEnablementInfo, error) {
	path := fmt.Sprintf("/%s/%s/_apis/management/repositories/%s/enablement", client.Org(), project, repositoryID)
	query := url.Values{"api-version": {"7.2-preview.3"}, "includeAllProperties": {"true"}}

	var raw repoEnablementRaw
	if err := azuredevops.GetJSONObject(ctx, client, azuredevops.HostAdvSec, path, query, &raw); err != nil {
		return RepoEnablementInfo{}, err
	}
	return RepoEnablementInfo{
		CodeQLEnabled:                      raw.CodeSecurityFeatures.CodeQLEnabled,
		DependencyScanningInjectionEnabled: raw.CodeSecurityFeatures.DependencyScanningInjectionEnabled,
		CodeSecurityEnabled:                raw.CodeSecurityFeatures.CodeSecurityEnabled,
		SecretProtectionEnabled:            raw.SecretProtectionFeatures.SecretProtectionEnabled,
		BlockPushes:                        raw.SecretProtectionFeatures.BlockPushes,
	}, nil
}
