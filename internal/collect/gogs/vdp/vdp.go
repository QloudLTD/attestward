// Package vdp implements C10 vdp for a self-hosted Gogs instance — the
// Gogs twin of internal/collect/github/vdp and its Azure DevOps sibling,
// under the same four check IDs.
//
// Two of the four are genuinely verifiable here, and two never can be.
// That split is the honest shape of this platform, not a gap in this
// collector:
//
//   - C10.vdp.security-md and C10.vdp.intake-channel read repo content
//     through the contents API, which Gogs serves in full. These are real,
//     API-verified observations.
//   - C10.vdp.private-reporting is always not-checkable: Gogs has no
//     private-vulnerability-reporting feature to enable or disable, so
//     there is nothing to observe. Reporting verified-fail here would
//     assert that a producer failed to turn on something that does not
//     exist.
//   - C10.vdp.security-policy-org is always not-checkable: Gogs has no
//     org-wide default policy mechanism (no equivalent of GitHub's special
//     `.github` repo), so a per-repo absence is the only kind of absence
//     that can exist.
//
// This is the first collector on this platform, and it was chosen first
// precisely because it depends on nothing Gogs lacks.
package vdp

import (
	"context"
	"fmt"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gogscollect "gitlab.com/sioakeim/attestward/internal/collect/gogs"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const collectorID = "C10.vdp"

const (
	securityMDID        = "C10.vdp.security-md"
	intakeChannelID     = "C10.vdp.intake-channel"
	privateReportingID  = "C10.vdp.private-reporting"
	securityPolicyOrgID = "C10.vdp.security-policy-org"
)

// platform is the registry key this package registers under — the same
// value cmd/attestward's platformGogs carries, and what CheckResult.Scope
// stamps so a pack reader can tell a Gogs result from a GitHub one with
// the same check ID.
const platform = "gogs"

var checkTitles = map[string]string{
	securityMDID:        "A SECURITY.md resolves for this repo",
	intakeChannelID:     "SECURITY.md advertises an actionable intake channel",
	privateReportingID:  "Private vulnerability reporting is enabled",
	securityPolicyOrgID: "The org has an org-wide default security policy",
}

var checkIDs = []string{securityMDID, intakeChannelID, privateReportingID, securityPolicyOrgID}

var checkRemediations = map[string]string{
	securityMDID: "Add a SECURITY.md to the repo — at the root, under docs/, or at .github/SECURITY.md — " +
		"describing how to report a vulnerability. Gogs does not surface the file anywhere in its UI, so " +
		"link to it from the repo's README or description as well, or reporters will not find it.",
	intakeChannelID: "If no SECURITY.md exists at all, add one first (see C10.vdp.security-md). If it " +
		"exists but this still fails, make the intake channel concrete: an email address or a URL " +
		"(a reporting form, an issue tracker, a bug-bounty page) — not general prose like \"we take " +
		"security seriously.\"",
	privateReportingID: "Gogs has no private vulnerability reporting feature, so there is nothing to " +
		"enable. If confidential intake matters for this repo, provide an out-of-band channel (a monitored " +
		"security email address, or a form) and name it in SECURITY.md, where C10.vdp.intake-channel will " +
		"see it.",
	securityPolicyOrgID: "Gogs has no org-wide default security policy mechanism. Add a SECURITY.md to " +
		"each repo that needs one; there is no single place that covers them all.",
}

// checkRubrics gives each check its own concrete meaning for every status
// it can actually produce. The two always-not-checkable checks list only
// that status, because they genuinely cannot produce another: their reason
// is a fixed fact about the platform, not an outcome of this scan.
var checkRubrics = map[string]map[model.Status]string{
	securityMDID: {
		model.StatusVerifiedPass: "GET /repos/{owner}/{repo}/contents/{path} returned a base64-encoded file " +
			"at one of `.github/SECURITY.md`, `SECURITY.md` or `docs/SECURITY.md`, tried in that order",
		model.StatusVerifiedFail: "all three candidate paths returned 404 — the policy is genuinely absent " +
			"from the repo. Note that a repo that does not exist, or that the token cannot see, 404s the " +
			"same way; the scan's repo resolution is what distinguishes those, not this check",
		model.StatusNotCheckable: sharedResolveErrRubric,
	},
	intakeChannelID: {
		model.StatusVerifiedPass: "a SECURITY.md resolved (see C10.vdp.security-md) and its content matches " +
			"at least one of two signals: an email address or an `http(s)://` URL",
		model.StatusPartial: "a SECURITY.md resolved but matched neither signal — the file exists and does " +
			"not tell a reporter how to reach the producer",
		model.StatusVerifiedFail: "no SECURITY.md exists to advertise a channel at all — shares " +
			"C10.vdp.security-md's own fail condition, since there is nothing to inspect",
		model.StatusNotCheckable: sharedResolveErrRubric,
	},
	privateReportingID: {
		model.StatusNotCheckable: "always. Gogs has no private-vulnerability-reporting feature, so there " +
			"is no setting to read and no API call is made for this check. This is a fixed fact about the " +
			"platform, not an outcome of the scan — it reads identically for every repo on every instance",
	},
	securityPolicyOrgID: {
		model.StatusNotCheckable: "always. Gogs has no org-wide default security policy mechanism — no " +
			"equivalent of GitHub's special `.github` repo — so there is nothing to look for. A per-repo " +
			"policy (C10.vdp.security-md) is the only kind that can exist here",
	},
}

// sharedResolveErrRubric is shared by security-md and intake-channel:
// both are computed from the same resolveSecurityMD call, so a resolution
// failure reaches both identically. A 404 at any one candidate path is
// never this cause — that just means the next path is tried.
const sharedResolveErrRubric = "resolving SECURITY.md failed with a genuine API error — an auth failure, " +
	"a 5xx that survived retry, a body this collector could not decode, or content in an unexpected " +
	"encoding; never asserted as a confirmed absence"

var checkEndpoints = map[string][]string{
	securityMDID:    {"GET /repos/{owner}/{repo}/contents/{path}"},
	intakeChannelID: {"GET /repos/{owner}/{repo}/contents/{path}"},
	// Deliberately empty for both: no API call backs either check.
	// CheckMeta.Endpoints documents what a check's own result depends on,
	// and an empty list is the honest value for a result that is a fixed
	// platform fact — see C09.audit.log-streaming on GitHub for the same
	// shape.
	privateReportingID:  nil,
	securityPolicyOrgID: nil,
}

const fixtureRef = "internal/collect/gogs/vdp/vdp_test.go"

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:        id,
			Platform:  platform,
			Title:     checkTitles[id],
			Collector: collectorID,
			TokenScope: "any Gogs personal access token that can read the repo. Gogs tokens are not " +
				"scopable — every token carries the full permissions of the account that issued it — so " +
				"least privilege here means using an account with read-only access to the repos in scope, " +
				"not narrowing the token itself",
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			FixtureRef:  fixtureRef,
		})
	}
}

// Collector implements C10 vdp against a Gogs instance.
type Collector struct {
	baseURL string
	token   string

	// newClient builds one Client per repo, so each repo's provenance is
	// exactly the calls made for that repo — the same isolation the
	// GitHub twin gets from a per-repo Client. Overridden in tests to
	// terminate the transport chain in a fixture.
	newClient func() (*gogscollect.Client, error)
}

// New builds the collector against the Gogs instance at baseURL,
// authenticated with token.
func New(baseURL, token string) *Collector {
	c := &Collector{baseURL: baseURL, token: token}
	c.newClient = func() (*gogscollect.Client, error) { return gogscollect.NewClient(baseURL, token) }
	return c
}

// NewForTest builds a collector whose per-repo Clients terminate in the
// caller's transport (typically gogsfixture.New()), exercising the real
// auth, provenance and retry layers.
func NewForTest(baseURL, token string, newClient func() (*gogscollect.Client, error)) *Collector {
	return &Collector{baseURL: baseURL, token: token, newClient: newClient}
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. It never returns a non-nil
// top-level error for a per-repo API failure: one unreachable repo must
// not cost the scan every other repo's evidence, so failures become
// not-checkable results carrying the error in their Reason.
//
// Repos are processed sequentially, matching the Azure DevOps twin — this
// platform has no ForEachRepo helper, and a Gogs instance is typically a
// single self-hosted server where fanning out buys throughput at the cost
// of hammering something one team runs.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	var all []model.CheckResult

	for _, repo := range scope.Repos {
		if err := ctx.Err(); err != nil {
			reason := fmt.Sprintf("scan canceled before this repo's checks ran: %v", err)
			all = append(all,
				notCheckableResult(securityMDID, scope.Org, repo, reason, nil),
				notCheckableResult(intakeChannelID, scope.Org, repo, reason, nil),
				// The two platform-fact checks are unaffected: their
				// reason was never contingent on a call that could be
				// canceled, and rewriting it here would replace a true
				// statement about Gogs with a true statement about this
				// scan, losing the one a reader needs.
				checkPrivateReporting(scope.Org, repo),
				checkSecurityPolicyOrg(scope.Org, repo),
			)
			continue
		}

		client, err := c.newClient()
		if err != nil {
			reason := fmt.Sprintf("could not build a client for this repo: %v", err)
			all = append(all,
				notCheckableResult(securityMDID, scope.Org, repo, reason, nil),
				notCheckableResult(intakeChannelID, scope.Org, repo, reason, nil),
				checkPrivateReporting(scope.Org, repo),
				checkSecurityPolicyOrg(scope.Org, repo),
			)
			continue
		}
		all = append(all, collectRepo(ctx, client, scope.Org, repo)...)
	}
	return all, nil
}

// collectRepo resolves SECURITY.md once — security-md and intake-channel
// both read that single result, so they can never disagree about what was
// found — and reports the two platform-fact checks without any call.
func collectRepo(ctx context.Context, client *gogscollect.Client, org, repo string) []model.CheckResult {
	resolved, resolveErr := resolveSecurityMD(ctx, client, org, repo)
	prov := client.Provenance()

	return []model.CheckResult{
		checkSecurityMD(org, repo, resolved, resolveErr, prov),
		checkIntakeChannel(org, repo, resolved, resolveErr, prov),
		checkPrivateReporting(org, repo),
		checkSecurityPolicyOrg(org, repo),
	}
}

func scopeRef(org, repo string) model.ScopeRef {
	return model.ScopeRef{Org: org, Repo: repo, Platform: platform}
}

func notCheckableResult(id, org, repo, reason string, prov []model.Provenance) model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	return model.CheckResult{
		CheckID:    id,
		Title:      checkTitles[id],
		Status:     model.StatusNotCheckable,
		Reason:     reason,
		Scope:      scopeRef(org, repo),
		Provenance: prov,
	}
}

// checkSecurityMD reports whether a policy file resolved. Absence at every
// candidate path is a confirmed observation (verified-fail), because each
// path answered 404 — not because a call failed.
func checkSecurityMD(org, repo string, resolved resolvedSecurityMD, resolveErr error, prov []model.Provenance) model.CheckResult {
	const id = securityMDID
	if resolveErr != nil {
		return notCheckableResult(id, org, repo, fmt.Sprintf("could not resolve SECURITY.md: %v", resolveErr), prov)
	}
	if !resolved.Found {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason:     "no SECURITY.md found at .github/SECURITY.md, SECURITY.md or docs/SECURITY.md in this repo",
			Scope:      scopeRef(org, repo),
			Provenance: prov,
		}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
		Reason:     fmt.Sprintf("SECURITY.md resolved at %s", resolved.Path),
		Scope:      scopeRef(org, repo),
		Provenance: prov,
		Facts:      map[string]any{"resolved_path": resolved.Path},
	}
}

// checkIntakeChannel judges whatever checkSecurityMD already resolved. A
// policy file with neither signal is capped at partial rather than passing:
// it exists, and it does not tell a reporter how to reach anyone.
func checkIntakeChannel(org, repo string, resolved resolvedSecurityMD, resolveErr error, prov []model.Provenance) model.CheckResult {
	const id = intakeChannelID
	if resolveErr != nil {
		return notCheckableResult(id, org, repo, fmt.Sprintf("could not resolve SECURITY.md: %v", resolveErr), prov)
	}
	if !resolved.Found {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason:     "no SECURITY.md exists in this repo, so no intake channel is advertised",
			Scope:      scopeRef(org, repo),
			Provenance: prov,
		}
	}

	matches := findIntakeChannelMatches(resolved.Content)
	if len(matches) == 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusPartial,
			Reason: fmt.Sprintf("SECURITY.md at %s contains neither an email address nor a URL, so it does not "+
				"give a reporter a way to reach the producer", resolved.Path),
			Scope:      scopeRef(org, repo),
			Provenance: prov,
			Facts:      map[string]any{"resolved_path": resolved.Path, "intake_signals": []string{}},
		}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
		Reason:     fmt.Sprintf("SECURITY.md at %s advertises an intake channel (%s)", resolved.Path, describeMatches(matches)),
		Scope:      scopeRef(org, repo),
		Provenance: prov,
		Facts:      map[string]any{"resolved_path": resolved.Path, "intake_signals": matches},
	}
}

// checkPrivateReporting is a fixed platform fact, identical for every repo
// on every instance: Gogs has no such feature. It makes no API call, so it
// carries no provenance — a provenance entry would imply this collector
// asked the instance something it never asked.
func checkPrivateReporting(org, repo string) model.CheckResult {
	const id = privateReportingID
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "Gogs has no private vulnerability reporting feature, so there is no setting to read. This is " +
			"a property of the platform, not a finding about this repo — confidential intake, if it exists, " +
			"is an out-of-band channel this tool cannot observe",
		Scope:      scopeRef(org, repo),
		Provenance: []model.Provenance{},
	}
}

// checkSecurityPolicyOrg is the second fixed platform fact. It is reported
// per repo rather than once per org so that a Gogs pack has the same result
// cardinality as a GitHub one — a reader comparing the two must not have to
// wonder whether a missing row means "not applicable" or "the scan stopped
// early".
func checkSecurityPolicyOrg(org, repo string) model.CheckResult {
	const id = securityPolicyOrgID
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "Gogs has no org-wide default security policy mechanism — no equivalent of GitHub's special " +
			".github repo — so there is nothing to look for. Only a per-repo policy can exist here (see " +
			"C10.vdp.security-md)",
		Scope:      scopeRef(org, repo),
		Provenance: []model.Provenance{},
	}
}
