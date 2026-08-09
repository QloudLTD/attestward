package github

import "net/http"

// IsPlanGated is a named predicate a collector calls when it has decided,
// for a *specific* endpoint, that a 402/404 response means "this feature
// isn't available on the org's plan" rather than "the resource doesn't
// exist" — e.g. the org audit-log API (issue #21/C09) 404s on non-Enterprise
// plans. It is deliberately not applied automatically to every 404: many
// endpoints' 404 genuinely means "not configured" and should map to
// verified-fail (e.g. no branch protection ruleset exists), not
// not-checkable. Interpreting a status code is the calling collector's
// semantic judgment; this only names the two codes GitHub actually uses for
// plan-gating so collectors don't hand-roll `== 402 || == 404` at each call
// site.
func IsPlanGated(statusCode int) bool {
	return statusCode == http.StatusPaymentRequired || statusCode == http.StatusNotFound
}
