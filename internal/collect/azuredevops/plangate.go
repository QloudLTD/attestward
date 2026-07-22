package azuredevops

import "net/http"

// IsAdvSecGated is a named predicate a collector calls when it has decided,
// for a *specific* Advanced Security (HostAdvSec) endpoint, that a response
// means "this feature isn't licensed for this org" rather than "the
// resource doesn't exist" — mirroring how internal/collect/github's
// IsPlanGated names GitHub's 402/404 plan-gating without collectors
// hand-rolling the check at each call site. GHAzDO (GitHub Advanced
// Security for Azure DevOps) is licensed per active committer with no free
// tier, so most orgs this tool scans will hit this path, not a real alert.
//
// Whether an unlicensed org's advsec endpoints actually return 403 or 404
// is an open [fixture-verify] item (issue #34) — this conservatively covers
// both codes ADO generally uses for forbidden-vs-absent until that's
// confirmed against a recorded response and finalized in issue #155 (S9):
// that empirical check needs the live demo org with GHAzDO licensing,
// which is S9's territory (gated on the epic's owner decisions), not
// something any single collector story can settle on its own.
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
