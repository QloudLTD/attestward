// Package secretshygiene implements C04 secrets-hygiene: secret scanning,
// push protection, Dependabot alerts, and GitHub Advanced Security (GHAS)
// posture (SSDF PO.5.1, PW.4.4).
//
// Plan-awareness is this collector's central design constraint (per the
// issue it was built against): secret scanning became free for public
// repos in 2024, but private repos still require a GHAS license. This
// collector must never report verified-fail for a feature the org's plan
// doesn't let it enable — see evalGHASGatedFeature.
package secretshygiene

import (
	"context"
	"fmt"
	"net/http"

	ghgithub "github.com/google/go-github/v75/github"

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/model"
)

const collectorID = "C04.secrets-hygiene"

var checkTitles = map[string]string{
	"C04.secrets.scanning-enabled":  "Secret scanning is active",
	"C04.secrets.push-protection":   "Secret scanning push protection is active",
	"C04.deps.dependabot-alerts":    "Dependabot vulnerability alerts are enabled",
	"C04.secrets.advanced-security": "GitHub Advanced Security is enabled where applicable",
	"C04.org.security-defaults":     "Org enables secret/dependency security features by default for new repos",
}

// repoCheckIDs are the four per-repo checks, in a fixed order — see
// repoprotection/envseparation's identical rationale (an evidence pack
// should diff cleanly across runs of the same scan).
var repoCheckIDs = []string{
	"C04.secrets.scanning-enabled",
	"C04.secrets.push-protection",
	"C04.deps.dependabot-alerts",
	"C04.secrets.advanced-security",
}

var allCheckIDs = append(append([]string{}, repoCheckIDs...), "C04.org.security-defaults")

var checkRemediations = map[string]string{
	"C04.secrets.scanning-enabled": "Repo Settings -> Code security -> enable \"Secret scanning\". Free " +
		"for public repos; on a private repo it needs a GitHub Advanced Security license, or (since " +
		"GitHub's 2025 GHAS unbundling) a standalone GitHub Secret Protection license.",
	"C04.secrets.push-protection": "Repo Settings -> Code security -> under Secret scanning, enable " +
		"\"Push protection\" so commits containing a detected secret are blocked before they land.",
	"C04.deps.dependabot-alerts": "Repo Settings -> Code security -> enable \"Dependabot alerts\".",
	"C04.secrets.advanced-security": "Repo Settings -> Code security -> enable \"GitHub Advanced " +
		"Security\" (requires a GHAS license on private repos; public repos get the equivalent features " +
		"free without it). Since GitHub's 2025 GHAS unbundling, secret scanning and push protection can " +
		"also be licensed and enabled independently via standalone Secret Protection, without this flag.",
	"C04.org.security-defaults": "Org Settings -> Code security -> enable secret scanning, push " +
		"protection, Dependabot alerts, AND Advanced Security \"for new repositories\" — all four must " +
		"be on for this check to pass — so every repo created going forward starts with them on, instead " +
		"of relying on each repo owner to enable them individually.",
}

func init() {
	for _, id := range allCheckIDs {
		collect.Register(collect.CheckMeta{
			ID:          id,
			Title:       checkTitles[id],
			Collector:   collectorID,
			TokenScope:  "repo (classic); fine-grained equivalent requires repo admin-level read access (security_and_analysis and vulnerability-alerts are both admin-only visible) — exact fine-grained permission category not independently verified against GitHub's docs, unlike the other entries in this table; org check additionally needs org owner or security manager",
			Remediation: checkRemediations[id],
		})
	}
}

// Collector implements C04 secrets-hygiene.
type Collector struct {
	token string

	// newClientForTest overrides how each Client is constructed — see
	// repoprotection.Collector's identical field for why.
	newClientForTest func(token string) *ghcollect.Client
}

// New returns a C04 collector authenticated with token. Like repoprotection
// and envseparation, per-repo checks fan out via ForEachRepo's concurrent
// worker pool, so each repo constructs its own Client. The org-level check
// (C04.org.security-defaults) additionally gets its own dedicated Client,
// separate from any per-repo one, for the same provenance-isolation reason.
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
// top-level error for an API failure — see org-security's Collect doc
// comment for why that matters for the rollup.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	orgResult := checkOrgSecurityDefaults(ctx, c.newClient(), scope.Org)

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

// collectRepo resolves secrets-hygiene posture for one repo and emits the
// four per-repo CheckResults. It never returns an error; every failure
// becomes a not-checkable result for the affected check(s).
//
// Two independent calls happen per repo (Repositories.Get, then
// GetVulnerabilityAlerts), so provenance is attributed per call via
// snapshot-diff rather than sharing one combined list across all four
// checks — scanning/push-protection/advanced-security depend only on the
// repo fetch, and dependabot-alerts depends only on the second call;
// giving either group the other's provenance would misrepresent what
// evidence actually backs each claim.
func collectRepo(ctx context.Context, client *ghcollect.Client, org, repo string) []model.CheckResult {
	repository, resp, err := client.REST.Repositories.Get(ctx, org, repo)
	if err != nil {
		return allRepoNotCheckable(org, repo, notCheckableReason(resp, err, org, repo), client.Provenance())
	}
	repoProv := client.Provenance()

	isPrivate := repository.GetPrivate()
	sa := repository.SecurityAndAnalysis

	scanning := checkSecretScanning(org, repo, sa, isPrivate, repoProv)
	pushProtection := checkPushProtection(org, repo, sa, isPrivate, repoProv)
	advSecurity := checkAdvancedSecurity(org, repo, sa, isPrivate, repoProv)

	depEnabled, depResp, depErr := client.REST.Repositories.GetVulnerabilityAlerts(ctx, org, repo)
	depProv := tailProvenance(client.Provenance(), len(repoProv))
	dependabot := checkDependabotAlerts(org, repo, depEnabled, depResp, depErr, depProv)

	return []model.CheckResult{scanning, pushProtection, dependabot, advSecurity}
}

// tailProvenance returns the entries of prov after the first skip of them,
// as a non-nil slice (schema invariant: Provenance must never be nil) —
// same helper as org-security's.
func tailProvenance(prov []model.Provenance, skip int) []model.Provenance {
	if skip >= len(prov) {
		return []model.Provenance{}
	}
	return prov[skip:]
}

func notCheckableReason(resp *ghgithub.Response, err error, org, repo string) string {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to read %s/%s", org, repo)
		case http.StatusNotFound:
			return fmt.Sprintf("%s/%s not found, or not visible to this token", org, repo)
		}
	}
	return fmt.Sprintf("could not query %s/%s: %v", org, repo, err)
}

// vulnerabilityAlertsNotCheckableReason is deliberately distinct from
// notCheckableReason: by the time this call runs, Repositories.Get on the
// same repo has already succeeded, so a generic "token lacks permission to
// read %s/%s" would be misleading (the token demonstrably can read the
// repo) — the actual gap is that reading vulnerability-alerts status
// specifically needs admin-level access to the repo.
func vulnerabilityAlertsNotCheckableReason(resp *ghgithub.Response, err error, org, repo string) string {
	if resp != nil && resp.StatusCode == http.StatusForbidden {
		return fmt.Sprintf("token lacks admin-level access to read vulnerability-alerts status on %s/%s", org, repo)
	}
	return fmt.Sprintf("could not query vulnerability-alerts status for %s/%s: %v", org, repo, err)
}

func orgNotCheckableReason(resp *ghgithub.Response, err error, org string) string {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to read org %s", org)
		case http.StatusNotFound:
			return fmt.Sprintf("%s not found, or is a user account rather than an organization", org)
		}
	}
	return fmt.Sprintf("could not query org %s: %v", org, err)
}

func allRepoNotCheckable(org, repo, reason string, prov []model.Provenance) []model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	out := make([]model.CheckResult, 0, len(repoCheckIDs))
	for _, id := range repoCheckIDs {
		out = append(out, model.CheckResult{
			CheckID:    id,
			Title:      checkTitles[id],
			Status:     model.StatusNotCheckable,
			Reason:     reason,
			Scope:      model.ScopeRef{Org: org, Repo: repo},
			Provenance: prov,
		})
	}
	return out
}
