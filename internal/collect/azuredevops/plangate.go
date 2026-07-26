package azuredevops

import "net/http"

// IsAdvSecGated is a named predicate a collector calls when it has decided,
// for a *specific* Advanced Security (HostAdvSec) endpoint, that a 403/404
// response is worth treating specially — mirroring how
// internal/collect/github's IsPlanGated names GitHub's 402/404 plan-gating
// without collectors hand-rolling the check at each call site. GHAzDO
// (GitHub Advanced Security for Azure DevOps) is licensed per active
// committer with no free tier, so most orgs this tool scans lack it.
//
// "This feature isn't licensed for this org" — this predicate's original
// documented purpose — turned out NOT to be what a 403/404 means here, at
// least not for this predicate's only current caller (secretshygiene's
// org-level enablement check, C04.org.security-defaults): S9's live run
// (2026-07-23, dev.azure.com/seciq, GHAzDO-unlicensed) found
// GET advsec.dev.azure.com/{org}/_apis/management/enablement returns HTTP
// 200 with every flag false/null for an unlicensed org — not a 403 or 404
// at all (see pipelinehistory.FetchRepoEnablement's own doc comment for the
// repo-level endpoint's identical finding). That's narrower than it first
// looks (issue #225 review): S9's own scan PAT already carried vso.advsec,
// so a missing-scope 403 was never actually reachable in that run — what's
// confirmed is only that licensing ISN'T the cause of a 403/404 here. "The
// token lacks the vso.advsec scope" is the most likely remaining
// explanation for a 403 reaching this predicate, not an observed fact;
// other permission causes (tenant conditional access, an IP allow-list,
// project-level denial, an org policy restricting PAT access) can't be
// excluded from the response alone. What actually produces a 404 for an
// advsec endpoint remains genuinely unconfirmed [fixture-verify: no
// recorded response covers it]. Every
// advsec-backed check in this epic still treats a gated response as an
// honest not-checkable rather than guessing further, so this predicate's
// mechanical behavior (covering both codes) is unchanged — only the story
// it told about what causes them has been corrected (issue #190).
func IsAdvSecGated(statusCode int) bool {
	return statusCode == http.StatusForbidden || statusCode == http.StatusNotFound
}

// IsAuditGated is a named predicate a collector calls when it has decided,
// for a *specific* Audit (HostAudit) endpoint, that a response means "this
// org isn't Entra-backed, so audit logging isn't available" rather than
// "the resource doesn't exist." The Audit Log REST API only exists for
// Azure AD (Entra ID)-backed organizations — an MSA-backed org (the common
// case for a personal or demo org) hits this path.
//
// The exact status code an MSA-backed org's audit endpoint returns is
// finalized empirically against a recorded response in issue #154 (S8);
// this conservatively covers both codes ADO generally uses for
// forbidden-vs-absent until then.
func IsAuditGated(statusCode int) bool {
	return statusCode == http.StatusForbidden || statusCode == http.StatusNotFound
}
