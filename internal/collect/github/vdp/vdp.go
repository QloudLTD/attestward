// Package vdp implements C10 vdp: whether the vulnerability-disclosure
// surface exists and is actionable — a resolved SECURITY.md (following
// GitHub's own repo → org-.github fallback chain), whether it advertises
// an actionable intake channel (email, URL, or a GitHub
// private-vulnerability-reporting mention) rather than vague prose,
// whether GitHub's private vulnerability reporting feature is actually
// enabled, and whether the org has an org-wide default policy (SSDF
// RV.1.1, RV.1.3). Triage SLAs and remediation timelines are not
// API-verifiable and are deliberately left to the self-attestation
// questionnaire (issue #23) — see each check's Reason for what it does
// and doesn't claim.
package vdp

import (
	"context"
	"fmt"
	"net/http"

	ghgithub "github.com/google/go-github/v75/github"

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/model"
)

const collectorID = "C10.vdp"

const (
	securityMDID        = "C10.vdp.security-md"
	intakeChannelID     = "C10.vdp.intake-channel"
	privateReportingID  = "C10.vdp.private-reporting"
	securityPolicyOrgID = "C10.vdp.security-policy-org"
)

var checkTitles = map[string]string{
	securityMDID:        "A SECURITY.md resolves for this repo",
	intakeChannelID:     "SECURITY.md advertises an actionable intake channel",
	privateReportingID:  "GitHub private vulnerability reporting is enabled",
	securityPolicyOrgID: "The org has an org-wide default security policy",
}

var repoCheckIDs = []string{securityMDID, intakeChannelID, privateReportingID}

var checkIDs = append(append([]string{}, repoCheckIDs...), securityPolicyOrgID)

func init() {
	for _, id := range repoCheckIDs {
		collect.Register(collect.CheckMeta{
			ID:        id,
			Title:     checkTitles[id],
			Collector: collectorID,
			TokenScope: "public_repo/repo (classic) or Contents: read-only (fine-grained) for SECURITY.md content — " +
				"private-reporting additionally needs whatever category gates that endpoint; exact fine-grained " +
				"category unverified, see C05's TokenScope for the same kind of hedge",
		})
	}
	collect.Register(collect.CheckMeta{
		ID:        securityPolicyOrgID,
		Title:     checkTitles[securityPolicyOrgID],
		Collector: collectorID,
		TokenScope: "public_repo/repo (classic) or Contents: read-only (fine-grained), against the org's own " +
			"\".github\" repo if one exists",
	})
}

// Collector implements C10 vdp.
type Collector struct {
	token string

	// newClientForTest overrides how each Client is constructed — see
	// secretshygiene.Collector's identical field for why.
	newClientForTest func(token string) *ghcollect.Client
}

// New returns a C10 collector authenticated with token.
func New(token string) *Collector {
	return &Collector{token: token}
}

func (c *Collector) newClient() *ghcollect.Client {
	if c.newClientForTest != nil {
		return c.newClientForTest(c.token)
	}
	return ghcollect.NewClient(c.token)
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. It never returns a non-nil
// top-level error for a per-repo API failure — see org-security's Collect
// doc comment for why that matters for the rollup.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	orgResult := checkSecurityPolicyOrg(ctx, c.newClient(), scope.Org)

	repoResults := ghcollect.ForEachRepo(ctx, scope.Repos, ghcollect.DefaultConcurrency, func(ctx context.Context, repo string) ([]model.CheckResult, error) {
		client := c.newClient()
		return collectRepo(ctx, client, scope.Org, repo), nil
	})

	all := []model.CheckResult{orgResult}
	for _, r := range repoResults {
		if r.Err != nil {
			all = append(all, allRepoNotCheckable(scope.Org, r.Repo, fmt.Sprintf("scan canceled before this repo's checks ran: %v", r.Err), []model.Provenance{})...)
			continue
		}
		all = append(all, r.Value...)
	}
	return all, nil
}

// collectRepo resolves SECURITY.md once (shared by security-md and
// intake-channel, which both need it) and checks private-reporting
// independently — a completely separate API call unrelated to SECURITY.md
// resolution, so its own failure must never block the other two, and vice
// versa. Provenance is attributed per group via snapshot-diff, matching
// secretshygiene's identical two-call pattern.
func collectRepo(ctx context.Context, client *ghcollect.Client, org, repo string) []model.CheckResult {
	resolved, resolveErr := resolveSecurityMD(ctx, client, org, repo)
	securityMDProv := client.Provenance()

	securityMD := checkSecurityMD(org, repo, resolved, resolveErr, securityMDProv)
	intakeChannel := checkIntakeChannel(org, repo, resolved, resolveErr, securityMDProv)

	enabled, prResp, prErr := client.REST.Repositories.IsPrivateReportingEnabled(ctx, org, repo)
	privateReportingProv := tailProvenance(client.Provenance(), len(securityMDProv))
	privateReporting := checkPrivateReporting(org, repo, enabled, prResp, prErr, privateReportingProv)

	return []model.CheckResult{securityMD, intakeChannel, privateReporting}
}

// tailProvenance returns the entries of prov after the first skip of
// them, as a non-nil slice — same helper as org-security's/secretshygiene's.
func tailProvenance(prov []model.Provenance, skip int) []model.Provenance {
	if skip >= len(prov) {
		return []model.Provenance{}
	}
	return prov[skip:]
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

func allRepoNotCheckable(org, repo, reason string, prov []model.Provenance) []model.CheckResult {
	out := make([]model.CheckResult, 0, len(repoCheckIDs))
	for _, id := range repoCheckIDs {
		out = append(out, notCheckableResult(id, org, repo, reason, prov))
	}
	return out
}

// checkSecurityMD reports whether a SECURITY.md resolved anywhere in
// GitHub's documented fallback chain — see resolveSecurityMD. Absence
// everywhere is a real, confirmed gap (verified-fail), not an unknown:
// GitHub's Contents API reliably distinguishes "not found" from "can't
// tell", and resolveErr carries the latter case separately.
func checkSecurityMD(org, repo string, resolved resolvedSecurityMD, resolveErr error, prov []model.Provenance) model.CheckResult {
	const id = securityMDID
	if resolveErr != nil {
		return notCheckableResult(id, org, repo, fmt.Sprintf("could not resolve SECURITY.md: %v", resolveErr), prov)
	}
	if !resolved.Found {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: "no SECURITY.md found at any of the standard locations (.github/, repo root, docs/) in this repo or the org's .github repo",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	fromOrgFallback := resolved.Repo != org+"/"+repo
	reason := fmt.Sprintf("SECURITY.md resolved at %s in %s", resolved.Path, resolved.Repo)
	if fromOrgFallback {
		reason += " (org-wide default; this repo has none of its own)"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"resolved_path": resolved.Path, "resolved_repo": resolved.Repo, "from_org_fallback": fromOrgFallback},
	}
}

// checkIntakeChannel applies findIntakeChannelMatches to whatever
// checkSecurityMD already resolved — a SECURITY.md with none of the three
// signals (e.g. "we take security seriously" and nothing else) is a real,
// confirmed gap capped at partial, not a pass: the file exists but
// doesn't actually tell a reporter how to reach the producer, per issue
// #22's own rubric wording.
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
			Reason: "SECURITY.md exists but no actionable intake channel (email, URL, or a GitHub private-vulnerability-reporting mention) was found — content may be too vague to act on",
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

// checkPrivateReporting treats a 402/404 as plan-gated rather than a
// confirmed "disabled" answer — live-verified during this issue's
// research that a private repo (no GHAS) 404s on this endpoint while
// every tested public repo returns 200 with an explicit boolean,
// mirroring C04.secrets-hygiene's own established private-repo/GHAS gate
// for a near-identical feature. GitHub's own docs only document 200/422
// for this endpoint, so this 404 behavior isn't independently confirmed
// against GitHub's docs the way most of this collector's other claims
// are — hedged as not-checkable rather than asserted as verified-fail,
// consistent with this codebase's "never assert on an ambiguous signal"
// pattern (e.g. C09's IsPlanGated treatment).
func checkPrivateReporting(org, repo string, enabled bool, resp *ghgithub.Response, err error, prov []model.Provenance) model.CheckResult {
	const id = privateReportingID
	if err == nil {
		status := model.StatusVerifiedFail
		reason := "private vulnerability reporting is not enabled"
		if enabled {
			status = model.StatusVerifiedPass
			reason = "private vulnerability reporting is enabled"
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
			Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	reason := fmt.Sprintf("could not query private-vulnerability-reporting status for %s/%s: %v", org, repo, err)
	switch {
	case resp != nil && ghcollect.IsPlanGated(resp.StatusCode):
		reason = fmt.Sprintf(
			"private-vulnerability-reporting status returned %d — this repo's plan may not include the feature "+
				"(observed on private repos without GHAS, mirroring C04's secret-scanning plan gate) or it may not "+
				"be visible to this token; GitHub's docs don't confirm this status code for this endpoint, so this "+
				"is reported as not-checkable rather than a confirmed disabled state", resp.StatusCode)
	case resp != nil && resp.StatusCode == http.StatusForbidden:
		reason = fmt.Sprintf("token lacks permission to read private-vulnerability-reporting status on %s/%s", org, repo)
	}
	return notCheckableResult(id, org, repo, reason, prov)
}

// checkSecurityPolicyOrg checks the org's own ".github" repo (GitHub's
// org-wide default community-health-file repo) for a resolved SECURITY.md.
// The org having no .github repo at all is genuinely different from
// having one with no SECURITY.md: the former means no org-wide default
// mechanism exists at all (not-checkable — most orgs never create one,
// and that absence isn't itself a vulnerability-disclosure gap), while
// the latter is a real, confirmed gap (the mechanism exists but wasn't
// populated) — so this checks the repo's own existence first, separately
// from resolveSecurityMDInRepo's own 404-means-"try next path" handling,
// which can't distinguish those two cases on its own.
func checkSecurityPolicyOrg(ctx context.Context, client *ghcollect.Client, org string) model.CheckResult {
	const id = securityPolicyOrgID
	_, resp, err := client.REST.Repositories.Get(ctx, org, ".github")
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return notCheckableResult(id, org, "", fmt.Sprintf("%s has no .github repo — no org-wide default community-health-file mechanism exists", org), client.Provenance())
		}
		return notCheckableResult(id, org, "", fmt.Sprintf("could not query %s/.github: %v", org, err), client.Provenance())
	}

	resolved, resolveErr := resolveSecurityMDInRepo(ctx, client, org, ".github")
	prov := client.Provenance()
	if resolveErr != nil {
		return notCheckableResult(id, org, "", fmt.Sprintf("could not resolve SECURITY.md in %s/.github: %v", org, resolveErr), prov)
	}
	if !resolved.Found {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: fmt.Sprintf("%s/.github exists but has no SECURITY.md at any of the standard locations", org),
			Scope:  model.ScopeRef{Org: org}, Provenance: prov,
		}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
		Reason: fmt.Sprintf("%s/.github has a SECURITY.md at %s, serving as the org-wide default", org, resolved.Path),
		Scope:  model.ScopeRef{Org: org}, Provenance: prov,
		Facts: map[string]any{"resolved_path": resolved.Path},
	}
}
