// Package vdp implements C10 vdp for GitLab — the GitLab counterpart to
// internal/collect/azuredevops/vdp — under the same four check IDs
// (collect.Register panics on a Collector-string mismatch across
// platforms, so Collector below matches every twin's "C10.vdp" exactly).
//
// C10.vdp.security-md and C10.vdp.intake-channel are, like the Azure DevOps
// twin, a genuine repo-content convention check, not a platform one: GitLab
// documents no community-health-file search order the way GitHub does (see
// resolve.go's own doc comment for the two-path chain this collector
// actually walks) and no org-wide-default mechanism to fall back to, so
// both are narrower here than their GitHub twins — no ".github/" first
// path, no org-wide-default-repo fallback.
//
// C10.vdp.private-reporting and C10.vdp.security-policy-org are both
// not-checkable always, by design, with no API call of their own — the
// same judgment call the Azure DevOps twin already made, for the identical
// reason: GitLab has no built-in, per-project structured vulnerability-
// intake feature comparable to GitHub's private vulnerability reporting
// (a Security-tab form that creates a draft security advisory, exposed via
// its own REST endpoint), and no ".github"-repo-style org-wide-default
// convention. Neither claim is something this build reads and finds
// disabled — there is nothing for either question to ever call.
package vdp

import (
	"context"
	"fmt"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const platform = "gitlab"

// collectorID must equal every twin's Collector string exactly — see the
// package doc comment.
const collectorID = "C10.vdp"

const (
	securityMDID        = "C10.vdp.security-md"
	intakeChannelID     = "C10.vdp.intake-channel"
	privateReportingID  = "C10.vdp.private-reporting"
	securityPolicyOrgID = "C10.vdp.security-policy-org"
)

// checkTitles deliberately does NOT reuse GitHub's title for
// privateReportingID ("GitHub private vulnerability reporting is
// enabled") — the table this replaced in gitlab/unsupported carried that
// exact GitHub-specific title unchanged onto the GitLab platform, which
// is wrong regardless of what the check reports. Matches the Azure
// DevOps twin's own platform-neutral title instead.
var checkTitles = map[string]string{
	securityMDID:        "A SECURITY.md resolves for this repo",
	intakeChannelID:     "SECURITY.md advertises an actionable intake channel",
	privateReportingID:  "A private-vulnerability-reporting mechanism is enabled",
	securityPolicyOrgID: "The org has an org-wide default security policy",
}

var checkRemediations = map[string]string{
	securityMDID: "Add a SECURITY.md at the project root or under docs/ describing how to report a " +
		"vulnerability. GitLab has no org-wide-default mechanism to add it to instead (see " +
		"C10.vdp.security-policy-org) — it must live in this project.",
	intakeChannelID: "If no SECURITY.md exists at all, add one first (see C10.vdp.security-md). If it " +
		"exists but this still fails, make the intake channel concrete and actionable: an email address, " +
		"or a URL (e.g. a reporting form or bug-bounty page) — not just general prose like \"we take " +
		"security seriously.\"",
	privateReportingID: "No remediation applicable via this tool: GitLab has no built-in, per-project " +
		"structured vulnerability-intake feature comparable to GitHub's private vulnerability reporting — " +
		"there is nothing to enable. If the producer has an out-of-band private reporting channel (e.g. a " +
		"security@ mailbox), advertise it in SECURITY.md (see C10.vdp.intake-channel) and/or document it " +
		"in the self-attestation questionnaire.",
	securityPolicyOrgID: "No remediation applicable via this tool: GitLab has no \".github\"-repo-style " +
		"org-wide-default mechanism — there is no project this tool could check as a fallback. Add a " +
		"SECURITY.md to each project individually (see C10.vdp.security-md), or document an org-wide " +
		"policy elsewhere and reference it in the self-attestation questionnaire.",
}

// sharedSecurityMDResolveErrRubric is shared by security-md and
// intake-channel: both are computed from the SAME resolveSecurityMD call,
// so a resolution failure reaches both identically.
const sharedSecurityMDResolveErrRubric = "reading the project (for its default branch) or resolving " +
	"SECURITY.md within it failed with a genuine API error — permission denied, a malformed response, or " +
	"another failure; a plain 404 at one candidate SECURITY.md path is never this cause on its own, since " +
	"that just means the next path is tried"

var checkRubrics = map[string]map[model.Status]string{
	securityMDID: {
		model.StatusVerifiedPass: "SECURITY.md resolved at one of two candidate paths — SECURITY.md (repo " +
			"root) or docs/SECURITY.md, tried in that order — a repo-content convention this collector " +
			"checks for, not a platform-enforced one: GitLab documents no community-health-file search " +
			"order the way GitHub does, and has no org-wide-default mechanism to fall back to (see " +
			"C10.vdp.security-policy-org)",
		model.StatusVerifiedFail: "the project itself was readable, but no SECURITY.md resolved at either " +
			"candidate path within it",
		model.StatusNotCheckable: sharedSecurityMDResolveErrRubric + ". This also covers a missing or " +
			"invisible project: unlike the Azure DevOps twin, which addresses the repo directly and so " +
			"folds that case into verified-fail, this collector reads the project first to find its default " +
			"branch, so a 404 there is a read failure, not a confirmed absence of the file",
	},
	intakeChannelID: {
		model.StatusVerifiedPass: "SECURITY.md resolved (see C10.vdp.security-md) and its content matches " +
			"at least one of two signals: an email address or an http(s):// URL — narrower than the GitHub " +
			"twin's three signals, since GitLab has no private-vulnerability-reporting feature whose " +
			"mention could count as a third (see C10.vdp.private-reporting)",
		model.StatusPartial: "SECURITY.md resolved, but neither intake-channel signal was found in its " +
			"content — the file exists but doesn't tell a reporter how to actually reach the producer",
		model.StatusVerifiedFail: "no SECURITY.md exists to advertise an intake channel at all — shares " +
			"C10.vdp.security-md's own fail condition, since there's nothing to inspect for a channel",
		model.StatusNotCheckable: sharedSecurityMDResolveErrRubric,
	},
	privateReportingID: {
		model.StatusNotCheckable: "always — GitLab has no built-in, per-project structured vulnerability-" +
			"intake feature comparable to GitHub's private vulnerability reporting; there is nothing this " +
			"tool could ever call to verify it",
	},
	securityPolicyOrgID: {
		model.StatusNotCheckable: "always — GitLab has no \".github\"-repo-style org-wide-default " +
			"convention or mechanism; there is no project this tool could check as a fallback the way " +
			"GitHub's own \".github\" special repo works",
	},
}

var checkEndpoints = map[string][]string{
	securityMDID:    {"GET /projects/{id}/repository/files/{file_path}"},
	intakeChannelID: {"GET /projects/{id}/repository/files/{file_path}"},
	// privateReportingID and securityPolicyOrgID are deliberately nil: both
	// make no API call at all — see checkRubrics' own doc comment.
	privateReportingID:  nil,
	securityPolicyOrgID: nil,
}

const fixtureRef = "internal/collect/gitlab/vdp/vdp_test.go"

func init() {
	for _, id := range []string{securityMDID, intakeChannelID} {
		collect.Register(collect.CheckMeta{
			ID: id, Platform: platform, Title: checkTitles[id], Collector: collectorID,
			TokenScope:  "read_api (Reporter or above on the project)",
			Remediation: checkRemediations[id], Rubric: checkRubrics[id],
			Endpoints: checkEndpoints[id], FixtureRef: fixtureRef,
		})
	}
	collect.Register(collect.CheckMeta{
		ID: privateReportingID, Platform: platform, Title: checkTitles[privateReportingID], Collector: collectorID,
		TokenScope: "none — this check makes no API call of its own; GitLab has no private-vulnerability-" +
			"reporting feature to query (see its own doc comment)",
		Remediation: checkRemediations[privateReportingID], Rubric: checkRubrics[privateReportingID],
		Endpoints: checkEndpoints[privateReportingID], FixtureRef: fixtureRef,
	})
	collect.Register(collect.CheckMeta{
		ID: securityPolicyOrgID, Platform: platform, Title: checkTitles[securityPolicyOrgID], Collector: collectorID,
		TokenScope: "none — this check makes no API call of its own; GitLab has no \".github\"-repo-style " +
			"org-default mechanism to query (see its own doc comment)",
		Remediation: checkRemediations[securityPolicyOrgID], Rubric: checkRubrics[securityPolicyOrgID],
		Endpoints: checkEndpoints[securityPolicyOrgID], FixtureRef: fixtureRef,
	})
}

// Collector implements C10 vdp for GitLab.
type Collector struct {
	baseURL, token string
	newClient      func() (*gitlabcollect.Client, error)
}

// New builds the collector against a live GitLab instance.
func New(baseURL, token string) *Collector {
	c := &Collector{baseURL: baseURL, token: token}
	c.newClient = func() (*gitlabcollect.Client, error) { return gitlabcollect.NewClient(baseURL, token) }
	return c
}

// NewForTest builds the collector against an arbitrary base URL and
// round-tripper, so tests exercise the same client production assembles.
func NewForTest(baseURL, token string, newClient func() (*gitlabcollect.Client, error)) *Collector {
	return &Collector{baseURL: baseURL, token: token, newClient: newClient}
}

// ID returns the collector identifier recorded on every result it emits.
func (c *Collector) ID() string { return collectorID }

// Collect emits C10.vdp.security-policy-org once per scan (org-level, not
// per-repo — GitLab has no mechanism it could ever depend on, matching the
// Azure DevOps twin's identical architecture) and the three per-repo
// checks once per repo in scope.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	all := []model.CheckResult{checkSecurityPolicyOrg(scope.Org)}
	for _, repo := range scope.Repos {
		all = append(all, c.collectRepo(ctx, scope.Org, repo)...)
	}
	return all, nil
}

// collectRepo reads the project once (for its default branch, which
// resolveSecurityMD needs as ref), resolves SECURITY.md once (shared by
// security-md and intake-channel), and reports private-reporting as its
// own fixed, evidence-free result.
//
// It builds its own client per repo rather than sharing one across
// scope.Repos. Client.Provenance() is cumulative over every call ever made
// through that client instance, so a shared one attributed an earlier repo's
// API calls to a later repo's CheckResult.Provenance — evidence citing a
// project the result is not about (issue #15, the same defect as #14). Same
// convention as internal/collect/gitlab/repoprotection and .../secretshygiene.
func (c *Collector) collectRepo(ctx context.Context, org, repo string) []model.CheckResult {
	client, err := c.newClient()
	if err != nil {
		reason := fmt.Sprintf("could not build a GitLab client: %v", err)
		return []model.CheckResult{
			notCheckableResult(securityMDID, org, repo, reason, nil),
			notCheckableResult(intakeChannelID, org, repo, reason, nil),
			checkPrivateReporting(org, repo),
		}
	}

	id := projectID(org, repo)
	var proj struct {
		DefaultBranch string `json:"default_branch"`
	}
	projErr := gitlabcollect.GetJSON(ctx, client, "/projects/"+id, nil, &proj)
	prov := client.Provenance()

	var resolved resolvedSecurityMD
	var resolveErr error
	if projErr != nil {
		resolveErr = fmt.Errorf("could not read the project to find its default branch: %w", projErr)
	} else {
		resolved, resolveErr = resolveSecurityMD(ctx, client, id, proj.DefaultBranch)
		prov = client.Provenance()
	}

	return []model.CheckResult{
		checkSecurityMD(org, repo, resolved, resolveErr, prov),
		checkIntakeChannel(org, repo, resolved, resolveErr, prov),
		checkPrivateReporting(org, repo),
	}
}

func notCheckableResult(id, org, repo, reason string, prov []model.Provenance) model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
	}
}

func checkSecurityMD(org, repo string, resolved resolvedSecurityMD, resolveErr error, prov []model.Provenance) model.CheckResult {
	const id = securityMDID
	if resolveErr != nil {
		return notCheckableResult(id, org, repo, fmt.Sprintf("could not resolve SECURITY.md: %v", resolveErr), prov)
	}
	if !resolved.Found {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: "no SECURITY.md found at either candidate location (repo root or docs/) in this project",
			Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
		Reason: fmt.Sprintf("SECURITY.md resolved at %s", resolved.Path),
		Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		Facts: map[string]any{"resolved_path": resolved.Path},
	}
}

func checkIntakeChannel(org, repo string, resolved resolvedSecurityMD, resolveErr error, prov []model.Provenance) model.CheckResult {
	const id = intakeChannelID
	if resolveErr != nil {
		return notCheckableResult(id, org, repo, fmt.Sprintf("could not resolve SECURITY.md: %v", resolveErr), prov)
	}
	if !resolved.Found {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: "no SECURITY.md exists to advertise an intake channel",
			Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		}
	}

	matches := findIntakeChannelMatches(resolved.Content)
	if len(matches) == 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusPartial,
			Reason: "SECURITY.md exists but no actionable intake channel (email or URL) was found — " +
				"content may be too vague to act on",
			Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
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
		Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		Facts: map[string]any{"resolved_path": resolved.Path, "matches": factMatches},
	}
}

// checkPrivateReporting always returns not-checkable with no API call at
// all — see the package doc comment.
func checkPrivateReporting(org, repo string) model.CheckResult {
	const id = privateReportingID
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "GitLab has no built-in, per-project structured vulnerability-intake feature comparable to " +
			"GitHub's private vulnerability reporting — there is nothing this tool could ever call to verify it",
		Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: []model.Provenance{},
	}
}

// checkSecurityPolicyOrg always returns not-checkable with no API call at
// all — see the package doc comment. Org-level, not per-repo.
func checkSecurityPolicyOrg(org string) model.CheckResult {
	const id = securityPolicyOrgID
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "GitLab has no \".github\"-repo-style org-wide-default convention or mechanism — there is " +
			"no project this tool could check as a fallback the way GitHub's own \".github\" special repo works",
		Scope: model.ScopeRef{Org: org, Platform: platform}, Provenance: []model.Provenance{},
	}
}

func projectID(org, repo string) string {
	return escapePath(org) + "%2F" + escapePath(repo)
}

func escapePath(s string) string {
	out := make([]byte, 0, len(s)+8)
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			out = append(out, '%', '2', 'F')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}
