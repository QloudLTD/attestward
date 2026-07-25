// Package vdp implements Azure DevOps's C10 vdp — the ADO counterpart to
// internal/collect/github/vdp — under the same four check IDs (issue #34's
// check-identity model — same ID, per-platform everything else;
// collect.Register panics on a Collector-string mismatch across platforms,
// so Collector below matches the GitHub twin's "C10.vdp" exactly).
//
// C10.vdp.security-md and C10.vdp.intake-channel are a genuine repo-content
// convention check, not a platform one: Azure DevOps has no documented
// community-health-file search order the way GitHub does (see resolve.go's
// own doc comment for the two-path chain this collector actually walks)
// and no org-wide-default mechanism to fall back to, so both checks are
// narrower here than their GitHub twins — no ".github/" first path, no
// org-".github"-repo fallback.
//
// C10.vdp.private-reporting and C10.vdp.security-policy-org are both
// not-checkable always, by design, with no API call of their own — the
// same shape as internal/collect/azuredevops/orgsecurity's
// C01.org.members-without-2fa/C01.org.default-repo-permission, or this
// project's own internal/collect/github/auditlogging's
// C09.audit.log-streaming: no endpoint or platform mechanism exists for
// either question at all (Azure DevOps has no private-vulnerability-
// reporting feature, and no ".github"-repo-style org-default convention),
// so there is nothing for a future version of this collector to "start
// calling."
package vdp

import (
	"context"
	"fmt"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/model"
)

// collectorID must equal the GitHub twin's Collector string exactly — see
// the package doc comment.
const collectorID = "C10.vdp"

const (
	securityMDID        = "C10.vdp.security-md"
	intakeChannelID     = "C10.vdp.intake-channel"
	privateReportingID  = "C10.vdp.private-reporting"
	securityPolicyOrgID = "C10.vdp.security-policy-org"
)

// checkTitles is allowed to differ from the GitHub twin's wording (epic
// #34 open decision 4: same ID, per-platform Title) — kept close to the
// GitHub twin's own phrasing here since the underlying question (does a
// resolvable SECURITY.md exist, does it advertise a channel, is there a
// platform reporting feature, is there an org-wide default) is identical
// in spirit even where Azure DevOps's answer differs.
var checkTitles = map[string]string{
	securityMDID:        "A SECURITY.md resolves for this repo",
	intakeChannelID:     "SECURITY.md advertises an actionable intake channel",
	privateReportingID:  "A private-vulnerability-reporting mechanism is enabled",
	securityPolicyOrgID: "The org has an org-wide default security policy",
}

var repoCheckIDs = []string{securityMDID, intakeChannelID, privateReportingID}

var checkIDs = append(append([]string{}, repoCheckIDs...), securityPolicyOrgID)

var checkRemediations = map[string]string{
	securityMDID: "Add a SECURITY.md at the repo root or under docs/ describing how to report a " +
		"vulnerability. Azure DevOps has no org-wide-default mechanism to add it to instead (see " +
		"C10.vdp.security-policy-org) — it must live in this repo.",
	intakeChannelID: "If no SECURITY.md exists at all, add one first (see C10.vdp.security-md). If it " +
		"exists but this still fails, make the intake channel concrete and actionable: an email address, " +
		"or a URL (e.g. a reporting form or bug-bounty page) — not just general prose like \"we take " +
		"security seriously.\"",
	privateReportingID: "No remediation applicable via this tool: Azure DevOps has no private-vulnerability-" +
		"reporting feature or API surface at all, unlike GitHub's dedicated feature — there is nothing to " +
		"enable. If the producer has an out-of-band private reporting channel (e.g. a security@ mailbox), " +
		"advertise it in SECURITY.md (see C10.vdp.intake-channel) and/or document it in the self-attestation " +
		"questionnaire.",
	securityPolicyOrgID: "No remediation applicable via this tool: Azure DevOps has no \".github\"-repo-style " +
		"org-wide-default mechanism — there is no project/repo this tool could check as a fallback. Add a " +
		"SECURITY.md to each repo individually (see C10.vdp.security-md), or document an org-wide policy " +
		"elsewhere and reference it in the self-attestation questionnaire.",
}

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce. Like the GitHub twin, this collector has no single
// shared upstream not-checkable gate across ALL checks: Collect never
// early-returns, so C10.vdp.private-reporting's fixed not-checkable result
// is produced regardless of whether SECURITY.md resolution succeeded.
// securityMDID and intakeChannelID DO share a not-checkable cause with each
// other, since both read the same resolveSecurityMD result — see
// sharedSecurityMDResolveErrRubric.
var checkRubrics = map[string]map[model.Status]string{
	securityMDID: {
		model.StatusVerifiedPass: "SECURITY.md resolved at one of two candidate repo-content paths — " +
			"/SECURITY.md (repo root) or /docs/SECURITY.md, tried in that order — a repo-content convention " +
			"this collector checks for, not a platform-enforced one: Azure DevOps documents no " +
			"community-health-file search order the way GitHub does, and has no org-wide-default mechanism " +
			"to fall back to (see C10.vdp.security-policy-org)",
		model.StatusVerifiedFail: "no SECURITY.md resolved at either candidate path (/SECURITY.md or " +
			"/docs/SECURITY.md) — includes the case where the repository itself doesn't exist or isn't " +
			"visible to this token, which a 404 at both paths can't distinguish from a genuinely missing file",
		model.StatusNotCheckable: sharedSecurityMDResolveErrRubric,
	},
	intakeChannelID: {
		model.StatusVerifiedPass: "SECURITY.md resolved (see C10.vdp.security-md) and its content matches " +
			"at least one of two signals: an email address or an http(s):// URL — narrower than the GitHub " +
			"twin's three signals, since Azure DevOps has no private-vulnerability-reporting feature whose " +
			"mention could count as a third (see C10.vdp.private-reporting)",
		model.StatusPartial: "SECURITY.md resolved, but neither intake-channel signal was found in its " +
			"content — the file exists but doesn't tell a reporter how to actually reach the producer",
		model.StatusVerifiedFail: "no SECURITY.md exists to advertise an intake channel at all — shares " +
			"C10.vdp.security-md's own fail condition, since there's nothing to inspect for a channel",
		model.StatusNotCheckable: sharedSecurityMDResolveErrRubric,
	},
	privateReportingID: {
		model.StatusNotCheckable: "always — Azure DevOps has no private-vulnerability-reporting feature or " +
			"API surface at all, unlike GitHub's dedicated feature and endpoint; there is nothing this tool " +
			"could ever call to verify it",
	},
	securityPolicyOrgID: {
		model.StatusNotCheckable: "always — Azure DevOps has no \".github\"-repo-style org-wide-default " +
			"convention or mechanism; there is no project/repo this tool could check as a fallback the way " +
			"GitHub's own \".github\" special repo works",
	},
}

// sharedSecurityMDResolveErrRubric is shared by security-md and
// intake-channel: both are computed from the SAME resolveSecurityMD call,
// so a resolution failure (a genuine API error, not a 404 at one candidate
// path — that just means "try the next path") reaches both checks
// identically.
const sharedSecurityMDResolveErrRubric = "resolving SECURITY.md failed with a genuine API error — " +
	"permission denied, a malformed response, or another failure; a plain 404 at one candidate path is " +
	"never this cause, since that just means the next path is tried"

// checkEndpoints strings are host-first ("GET <host>/{org}/...") — the same
// convention every other ADO collector's Endpoints entries use (issue #179;
// this package and auditlogging's were the only two path-first-with-a-host-
// parenthetical holdouts). See resolve.go's own doc comment for the
// $format=json/candidate-path detail this used to spell out inline — dropped
// here to match the majority convention's other Items-Get callers
// (repoprotection/sasthistory/scahistory/provenance), which leave that same
// operational detail to their own doc comments rather than the Endpoints
// string.
var checkEndpoints = map[string][]string{
	securityMDID: {
		"GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/items",
	},
	intakeChannelID: {
		"GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/items",
	},
	// privateReportingID and securityPolicyOrgID are deliberately nil: both
	// make no API call at all — see checkRubrics' own doc comment.
	privateReportingID:  nil,
	securityPolicyOrgID: nil,
}

const fixtureRef = "internal/collect/azuredevops/vdp/vdp_test.go"

func init() {
	for _, id := range []string{securityMDID, intakeChannelID} {
		collect.Register(collect.CheckMeta{
			ID:          id,
			Platform:    "azuredevops",
			Title:       checkTitles[id],
			Collector:   collectorID,
			TokenScope:  "vso.code",
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			FixtureRef:  fixtureRef,
		})
	}
	collect.Register(collect.CheckMeta{
		ID:        privateReportingID,
		Platform:  "azuredevops",
		Title:     checkTitles[privateReportingID],
		Collector: collectorID,
		TokenScope: "none — this check makes no API call of its own; Azure DevOps has no " +
			"private-vulnerability-reporting feature to query (see its own doc comment)",
		Remediation: checkRemediations[privateReportingID],
		Rubric:      checkRubrics[privateReportingID],
		Endpoints:   checkEndpoints[privateReportingID],
		FixtureRef:  fixtureRef,
	})
	collect.Register(collect.CheckMeta{
		ID:        securityPolicyOrgID,
		Platform:  "azuredevops",
		Title:     checkTitles[securityPolicyOrgID],
		Collector: collectorID,
		TokenScope: "none — this check makes no API call of its own; Azure DevOps has no " +
			"\".github\"-repo-style org-default mechanism to query (see its own doc comment)",
		Remediation: checkRemediations[securityPolicyOrgID],
		Rubric:      checkRubrics[securityPolicyOrgID],
		Endpoints:   checkEndpoints[securityPolicyOrgID],
		FixtureRef:  fixtureRef,
	})
}

// Collector implements C10 vdp for Azure DevOps.
type Collector struct {
	org, pat string

	// newClientForTest overrides how each per-repo Client is constructed —
	// see internal/collect/github/secretshygiene.Collector's identical
	// field for why a per-repo collector needs this rather than a single
	// pre-built Client: each repo's own Client keeps Client.Provenance()
	// scoped to that repo's calls alone.
	newClientForTest func(org, pat string) *azuredevops.Client
}

// New returns a C10 collector authenticated with pat against org. Unlike
// C01 org-security and C09 audit-logging (issue #34's first two ADO
// collectors, both org-scoped, sharing one Client across their sequential
// calls), C10 is per-repo, so New takes (org, pat) rather than a
// pre-built *azuredevops.Client — each repo gets its own fresh Client
// inside Collect, the same reasoning the GitHub twin's own per-repo
// collectors document.
func New(org, pat string) *Collector {
	return &Collector{org: org, pat: pat}
}

func (c *Collector) newClient() *azuredevops.Client {
	if c.newClientForTest != nil {
		return c.newClientForTest(c.org, c.pat)
	}
	return azuredevops.NewClient(c.org, c.pat)
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. It never returns a non-nil
// top-level error for a per-repo API failure — see C01 org-security's
// Collect doc comment for why that matters for the rollup.
//
// Repos are processed sequentially, not fanned out concurrently the way
// the GitHub twin's own ForEachRepo does: internal/collect/azuredevops has
// no ForEachRepo-equivalent helper yet (this is the epic's first
// per-repo-scoped ADO collector), and adding one to the shared foundation
// package for a single caller was judged out of scope for this PR —
// sequential processing is simpler and, since it never needs
// concurrent-goroutine provenance isolation, still fully correct; only
// throughput on a large repo count differs from the GitHub side.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	all := []model.CheckResult{checkSecurityPolicyOrg(scope.Org)}

	for _, repo := range scope.Repos {
		if ctx.Err() != nil {
			// Only the two checks that actually depend on an API call
			// (which never ran) get the cancellation reason —
			// privateReporting's own fixed, evidence-free reason holds
			// regardless of cancellation, the same invariant it has in
			// the normal path (see checkPrivateReporting's own doc
			// comment): it never depended on ctx or any API call to
			// begin with, so "the scan was canceled" is never true of
			// what it reports.
			reason := fmt.Sprintf("scan canceled before this repo's checks ran: %v", ctx.Err())
			all = append(all,
				notCheckableResult(securityMDID, scope.Org, repo, reason, []model.Provenance{}),
				notCheckableResult(intakeChannelID, scope.Org, repo, reason, []model.Provenance{}),
				checkPrivateReporting(scope.Org, repo),
			)
			continue
		}
		client := c.newClient()
		all = append(all, collectRepo(ctx, client, scope.Org, scope.Project, repo)...)
	}
	return all, nil
}

// collectRepo resolves SECURITY.md once (shared by security-md and
// intake-channel, which both need it) and reports private-reporting as
// its own fixed, evidence-free result — no API call, so no provenance
// snapshot-diffing needed for it, unlike the GitHub twin's real
// IsPrivateReportingEnabled call.
func collectRepo(ctx context.Context, client *azuredevops.Client, org, project, repo string) []model.CheckResult {
	resolved, resolveErr := resolveSecurityMD(ctx, client, project, repo)
	prov := client.Provenance()

	securityMD := checkSecurityMD(org, repo, resolved, resolveErr, prov)
	intakeChannel := checkIntakeChannel(org, repo, resolved, resolveErr, prov)
	privateReporting := checkPrivateReporting(org, repo)

	return []model.CheckResult{securityMD, intakeChannel, privateReporting}
}

func notCheckableResult(id, org, repo, reason string, prov []model.Provenance) model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
	}
}

// checkSecurityMD reports whether a SECURITY.md resolved anywhere in the
// two-path chain (see resolve.go). Absence everywhere is a real, confirmed
// gap (verified-fail), not an unknown — see the check's own Rubric for the
// one caveat (a nonexistent repo 404s the same way).
func checkSecurityMD(org, repo string, resolved resolvedSecurityMD, resolveErr error, prov []model.Provenance) model.CheckResult {
	const id = securityMDID
	if resolveErr != nil {
		return notCheckableResult(id, org, repo, fmt.Sprintf("could not resolve SECURITY.md: %v", resolveErr), prov)
	}
	if !resolved.Found {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: "no SECURITY.md found at either candidate location (repo root or docs/) in this repo",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
		Reason: fmt.Sprintf("SECURITY.md resolved at %s", resolved.Path),
		Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"resolved_path": resolved.Path},
	}
}

// checkIntakeChannel applies findIntakeChannelMatches to whatever
// checkSecurityMD already resolved — a SECURITY.md with neither signal
// (e.g. "we take security seriously" and nothing else) is a real,
// confirmed gap capped at partial, not a pass: the file exists but doesn't
// actually tell a reporter how to reach the producer.
func checkIntakeChannel(org, repo string, resolved resolvedSecurityMD, resolveErr error, prov []model.Provenance) model.CheckResult {
	const id = intakeChannelID
	if resolveErr != nil {
		return notCheckableResult(id, org, repo, fmt.Sprintf("could not resolve SECURITY.md: %v", resolveErr), prov)
	}
	if !resolved.Found {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: "no SECURITY.md exists to advertise an intake channel",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	matches := findIntakeChannelMatches(resolved.Content)
	if len(matches) == 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusPartial,
			Reason: "SECURITY.md exists but no actionable intake channel (email or URL) was found — content may be too vague to act on",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"resolved_path": resolved.Path},
		}
	}

	types := make([]string, 0, len(matches))
	factMatches := make([]map[string]any, 0, len(matches))
	for _, m := range matches {
		types = append(types, m.Type)
		factMatches = append(factMatches, map[string]any{"type": m.Type, "snippet": m.Snippet})
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
		Reason: fmt.Sprintf("SECURITY.md advertises an intake channel (%v)", types),
		Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"resolved_path": resolved.Path, "matches": factMatches},
	}
}

// checkPrivateReporting always returns not-checkable with no API call at
// all: Azure DevOps has no private-vulnerability-reporting feature or
// endpoint to query — see the package doc comment. Its Reason states that
// platform fact directly rather than echoing the Rubric's "always —"
// framing verbatim (that hedge belongs in registry metadata, not a
// runtime Reason written into a signed evidence pack — matching
// internal/collect/azuredevops/orgsecurity's identical convention for its
// own always-not-checkable checks). Callers must get this exact result
// regardless of ctx state: it never depended on ctx or any API call, so
// Collect's cancellation path also calls this directly rather than
// substituting a generic "scan canceled" reason.
func checkPrivateReporting(org, repo string) model.CheckResult {
	const id = privateReportingID
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "Azure DevOps has no private-vulnerability-reporting feature or API surface at all, unlike GitHub's dedicated feature and endpoint — there is nothing this tool could ever call to verify it",
		Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: []model.Provenance{},
	}
}

// checkSecurityPolicyOrg always returns not-checkable with no API call at
// all: Azure DevOps has no ".github"-repo-style org-wide-default mechanism
// — see the package doc comment. Org-level, not per-repo, mirroring the
// GitHub twin's own architecture (its version checks the org's own
// .github repo once, not per scanned repo). Its Reason states that
// platform fact directly rather than echoing the Rubric's "always —"
// framing verbatim — same convention as checkPrivateReporting above.
func checkSecurityPolicyOrg(org string) model.CheckResult {
	const id = securityPolicyOrgID
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "Azure DevOps has no \".github\"-repo-style org-wide-default convention or mechanism — there is no project/repo this tool could check as a fallback the way GitHub's own \".github\" special repo works",
		Scope:  model.ScopeRef{Org: org}, Provenance: []model.Provenance{},
	}
}
