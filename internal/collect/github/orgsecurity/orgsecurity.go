// Package orgsecurity implements C01 org-security: org-level access-control
// posture (SSDF PO.5, PS.1) — the "secure environment" foundation the CISA
// form's first cluster asks the signer to attest to.
package orgsecurity

import (
	"context"
	"fmt"
	"net/http"

	ghgithub "github.com/google/go-github/v75/github"

	"gitlab.com/sioakeim/attestward/internal/collect"
	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// collectorID follows the "C01.<name>" convention filterCollectors (see
// cmd/attestward/scan.go) matches --check prefixes against — a bare
// "org-security" would make --check C01 (the flag's own documented example)
// match nothing.
const collectorID = "C01.org-security"

var checkTitles = map[string]string{
	"C01.org.2fa-required":              "Org requires two-factor authentication",
	"C01.org.members-without-2fa":       "Count of members without two-factor authentication",
	"C01.org.default-repo-permission":   "Default repository permission for members",
	"C01.org.members-can-create-public": "Whether members can create public repositories",
}

var checkRemediations = map[string]string{
	"C01.org.2fa-required": "Org Settings -> Authentication security -> check \"Require two-factor " +
		"authentication for everyone in the [org] organization\". Any member without 2FA enabled will be " +
		"removed from the org when this is turned on, so resolve C01.org.members-without-2fa first.",
	"C01.org.members-without-2fa": "Org People page -> filter by \"Two-factor authentication: Disabled\" -> " +
		"have each flagged member enable 2FA under their own Settings -> Password and authentication, or " +
		"remove/suspend members who won't comply. Then enable C01.org.2fa-required so new members can't " +
		"rejoin without it.",
	"C01.org.default-repo-permission": "Org Settings -> Member privileges -> Base permissions -> set to " +
		"\"Read\" or \"No permission\" so members don't get write access to every repo by default.",
	"C01.org.members-can-create-public": "Org Settings -> Member privileges -> Repository creation -> " +
		"uncheck \"Public\" so members can't create public repositories without an explicit visibility " +
		"change reviewed separately.",
}

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce — none of these four checks can produce `partial`,
// since each reduces to a single boolean org-level field (see the
// check*() functions below); self-attested doesn't apply to an
// API-verified collector at all.
var checkRubrics = map[string]map[model.Status]string{
	"C01.org.2fa-required": {
		model.StatusVerifiedPass: "the org's `two_factor_requirement_enabled` field is true",
		model.StatusVerifiedFail: "the org's `two_factor_requirement_enabled` field is false",
		model.StatusNotCheckable: "the org couldn't be read (403/404/other API error), or its API response " +
			"omitted `two_factor_requirement_enabled`",
	},
	"C01.org.members-without-2fa": {
		model.StatusVerifiedPass: "GET /orgs/{org}/members?filter=2fa_disabled returned zero members",
		model.StatusVerifiedFail: "GET /orgs/{org}/members?filter=2fa_disabled returned one or more members " +
			"(the count is recorded in Facts; member names/logins are deliberately never recorded — see the " +
			"collector's own doc comment)",
		model.StatusNotCheckable: "the members list couldn't be read (403/404/other API error)",
	},
	"C01.org.default-repo-permission": {
		model.StatusVerifiedPass: "the org's `default_repository_permission` field is \"read\" or \"none\"",
		model.StatusVerifiedFail: "the org's `default_repository_permission` field is \"write\" or \"admin\" — " +
			"the two permissive values in GitHub's documented enum. A fail names a value actually observed; " +
			"an unrecognised value is not-checkable, not a fail.",
		model.StatusNotCheckable: "the org couldn't be read (403/404/other API error), its API response " +
			"omitted `default_repository_permission`, or that field held a value outside GitHub's documented " +
			"enum, which cannot be judged restrictive or permissive without guessing",
	},
	"C01.org.members-can-create-public": {
		model.StatusVerifiedPass: "the org's `members_can_create_public_repositories` field is false",
		model.StatusVerifiedFail: "the org's `members_can_create_public_repositories` field is true",
		model.StatusNotCheckable: "the org couldn't be read (403/404/other API error), or its API response " +
			"omitted `members_can_create_public_repositories`",
	},
}

// checkEndpoints lists which REST endpoint(s) actually back each check's
// status — three of the four checks share one org GET (fetched once by
// Collect and reused, see its own doc comment); members-without-2fa makes
// its own separate, paginated call with a server-side filter that changes
// what the endpoint actually returns, so the query parameter is part of
// the endpoint description (see CheckMeta.Endpoints' own doc comment).
var checkEndpoints = map[string][]string{
	"C01.org.2fa-required":              {"GET /orgs/{org}"},
	"C01.org.members-without-2fa":       {"GET /orgs/{org}/members?filter=2fa_disabled"},
	"C01.org.default-repo-permission":   {"GET /orgs/{org}"},
	"C01.org.members-can-create-public": {"GET /orgs/{org}"},
}

const fixtureRef = "internal/collect/github/orgsecurity/orgsecurity_test.go"

func init() {
	for id, title := range checkTitles {
		collect.Register(collect.CheckMeta{
			ID:          id,
			Platform:    "github",
			Title:       title,
			Collector:   collectorID,
			TokenScope:  "read:org",
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			FixtureRef:  fixtureRef,
		})
	}
}

// Collector implements C01 org-security.
type Collector struct {
	client *ghcollect.Client
}

// New returns a C01 collector using client for all API calls. Give each
// collector instance its own Client (never share one across concurrently-run
// collectors, including the orchestrator's own preflight/repo-listing
// calls) — Client.Provenance() reflects every call made through it, and
// this collector attributes provenance to individual CheckResults by
// diffing that log around each call, which only stays correct if nothing
// else is issuing calls through the same client concurrently.
func New(client *ghcollect.Client) *Collector {
	return &Collector{client: client}
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. It never returns a non-nil error
// for an org-level API failure (permission-gated, org doesn't exist, or is
// a user account rather than an org) — those become not-checkable results
// for each of the four specific check IDs, so the rollup engine can still
// resolve them against mappings/ssdf-800-218.yaml's checks[] lists. A
// generic collector-level error here would instead synthesize one
// not-checkable result keyed by the *collector* ID ("C01.org-security"),
// which matches no task's checks[] entry and would silently vanish from the
// rollup.
//
// When the orchestrator already knows (from preflight) that scope.Org is a
// personal user account, every check short-circuits straight to that
// specific not-checkable reason without attempting Organizations.Get at
// all — issue #102: this collector's checks structurally can never
// succeed against a user account, so there's no reason to make (and pay
// the rate-limit/latency cost of) a doomed API call just to rediscover
// that.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	if scope.AccountType == collect.AccountTypeUser {
		return allNotCheckable(scope, ghcollect.UserAccountNotCheckableReason(scope.Org), []model.Provenance{}), nil
	}

	start := len(c.client.Provenance())
	org, resp, err := c.client.REST.Organizations.Get(ctx, scope.Org)
	if err != nil {
		// The org.Get call itself still produced a provenance entry (the
		// 403/404 response is real, auditable evidence backing the reason
		// below) — attach it rather than claiming these not-checkable
		// results have no evidence at all.
		return allNotCheckable(scope, notCheckableReason(resp, err, scope.Org), tailProvenance(c.client.Provenance(), start)), nil
	}
	orgProvenance := tailProvenance(c.client.Provenance(), start)

	results := []model.CheckResult{
		check2FARequired(scope, org, orgProvenance),
		checkDefaultRepoPermission(scope, org, orgProvenance),
		checkMembersCanCreatePublic(scope, org, orgProvenance),
		c.checkMembersWithout2FA(ctx, scope, start+len(orgProvenance)),
	}
	return results, nil
}

// allNotCheckable produces a not-checkable result for all four checks, each
// keyed by its real, specific check ID — see the Collect doc comment for
// why this matters.
func allNotCheckable(scope collect.Scope, reason string, prov []model.Provenance) []model.CheckResult {
	out := make([]model.CheckResult, 0, len(checkTitles))
	for id, title := range checkTitles {
		out = append(out, model.CheckResult{
			CheckID:    id,
			Title:      title,
			Status:     model.StatusNotCheckable,
			Reason:     reason,
			Scope:      model.ScopeRef{Org: scope.Org},
			Provenance: prov,
		})
	}
	return out
}

func notCheckableReason(resp *ghgithub.Response, err error, org string) string {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to read org %s (requires at least read:org)", org)
		case http.StatusNotFound:
			return fmt.Sprintf("%s not found, or is a user account rather than an organization", org)
		}
	}
	return fmt.Sprintf("could not query org %s: %v", org, err)
}

func check2FARequired(scope collect.Scope, org *ghgithub.Organization, prov []model.Provenance) model.CheckResult {
	const id = "C01.org.2fa-required"
	if org.TwoFactorRequirementEnabled == nil {
		return notCheckableResult(id, scope, "the org API response did not include two_factor_requirement_enabled", prov)
	}
	enabled := *org.TwoFactorRequirementEnabled
	status, reason := model.StatusVerifiedFail, "org does not require two-factor authentication for members"
	if enabled {
		status, reason = model.StatusVerifiedPass, "org requires two-factor authentication for members"
	}
	return model.CheckResult{
		CheckID:    id,
		Title:      checkTitles[id],
		Status:     status,
		Reason:     reason,
		Scope:      model.ScopeRef{Org: scope.Org},
		Provenance: prov,
		Facts:      map[string]any{"two_factor_requirement_enabled": enabled},
	}
}

func checkDefaultRepoPermission(scope collect.Scope, org *ghgithub.Organization, prov []model.Provenance) model.CheckResult {
	const id = "C01.org.default-repo-permission"
	if org.DefaultRepoPermission == nil {
		return notCheckableResult(id, scope, "the org API response did not include default_repository_permission", prov)
	}
	perm := *org.DefaultRepoPermission

	// GitHub's documented values are "none", "read", "write" and "admin".
	// Anything else is not-checkable rather than a fail.
	//
	// This used to fail on any unrecognised value, so an empty string or a
	// future GitHub setting produced verified-fail with a reason implying a
	// permissive default that was never observed. That is conservative for the
	// reader but still an unsupported claim in a signed attestation, and it
	// tells a producer to fix something that may not be broken — the same
	// complaint the tier-gating work exists to avoid. Refusing to guess has to
	// hold in both directions or it is just a preference for one error.
	var status model.Status
	var reason string
	switch perm {
	case "none", "read":
		status = model.StatusVerifiedPass
		reason = fmt.Sprintf("default repository permission is %q", perm)
	case "write", "admin":
		status = model.StatusVerifiedFail
		reason = fmt.Sprintf("default repository permission is %q, want \"read\" or \"none\"", perm)
	default:
		return notCheckableResult(id, scope,
			fmt.Sprintf("the org reported default_repository_permission %q, which this build does not recognise; "+
				"whether it is restrictive cannot be determined without guessing", perm), prov)
	}
	return model.CheckResult{
		CheckID:    id,
		Title:      checkTitles[id],
		Status:     status,
		Reason:     reason,
		Scope:      model.ScopeRef{Org: scope.Org},
		Provenance: prov,
		Facts:      map[string]any{"default_repository_permission": perm},
	}
}

func checkMembersCanCreatePublic(scope collect.Scope, org *ghgithub.Organization, prov []model.Provenance) model.CheckResult {
	const id = "C01.org.members-can-create-public"
	if org.MembersCanCreatePublicRepos == nil {
		return notCheckableResult(id, scope, "the org API response did not include members_can_create_public_repositories", prov)
	}
	canCreate := *org.MembersCanCreatePublicRepos
	status, reason := model.StatusVerifiedPass, "members cannot create public repositories"
	if canCreate {
		status, reason = model.StatusVerifiedFail, "members can create public repositories (potential leak vector)"
	}
	return model.CheckResult{
		CheckID:    id,
		Title:      checkTitles[id],
		Status:     status,
		Reason:     reason,
		Scope:      model.ScopeRef{Org: scope.Org},
		Provenance: prov,
		Facts:      map[string]any{"members_can_create_public_repositories": canCreate},
	}
}

// checkMembersWithout2FA counts (never lists — the org's member roster may
// be sensitive, and an evidence pack may be shared with agencies) members
// lacking two-factor authentication. skipProvenance is how many of the
// collector's provenance entries were already recorded (by the org.Get
// call) before this check started, so it can slice off only the entries
// its own paginated calls add.
func (c *Collector) checkMembersWithout2FA(ctx context.Context, scope collect.Scope, skipProvenance int) model.CheckResult {
	const id = "C01.org.members-without-2fa"
	count := 0
	opts := &ghgithub.ListMembersOptions{
		Filter:      "2fa_disabled",
		ListOptions: ghgithub.ListOptions{PerPage: 100},
	}

	for {
		members, resp, err := c.client.REST.Organizations.ListMembers(ctx, scope.Org, opts)
		if err != nil {
			return notCheckableResult(id, scope, notCheckableReason(resp, err, scope.Org), tailProvenance(c.client.Provenance(), skipProvenance))
		}
		count += len(members)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	prov := tailProvenance(c.client.Provenance(), skipProvenance)
	status, reason := model.StatusVerifiedPass, "all org members have two-factor authentication enabled"
	if count > 0 {
		status = model.StatusVerifiedFail
		reason = fmt.Sprintf("%d org member(s) do not have two-factor authentication enabled", count)
	}
	return model.CheckResult{
		CheckID:    id,
		Title:      checkTitles[id],
		Status:     status,
		Reason:     reason,
		Scope:      model.ScopeRef{Org: scope.Org},
		Provenance: prov,
		// Count only — never member names/logins (privacy: the evidence
		// pack may be shared with agencies).
		Facts: map[string]any{"members_without_2fa_count": count},
	}
}

func notCheckableResult(id string, scope collect.Scope, reason string, prov []model.Provenance) model.CheckResult {
	return model.CheckResult{
		CheckID:    id,
		Title:      checkTitles[id],
		Status:     model.StatusNotCheckable,
		Reason:     reason,
		Scope:      model.ScopeRef{Org: scope.Org},
		Provenance: prov,
	}
}

// tailProvenance returns the entries of prov after the first skip of them,
// as a non-nil slice (schema invariant: Provenance must never be nil).
func tailProvenance(prov []model.Provenance, skip int) []model.Provenance {
	if skip >= len(prov) {
		return []model.Provenance{}
	}
	return prov[skip:]
}
