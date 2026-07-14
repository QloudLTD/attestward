// Package envseparation implements C03 env-separation: whether deployments
// to production-like environments flow through separated, protected GitHub
// Environments (SSDF PO.5.1) — the environment-separation control the CISA
// form's secure-environments cluster asks the signer to attest to.
//
// v0.1 checks the presence of a deployment-branch-policy restriction (does
// one exist at all) but not its detail (which branches/tags it actually
// allows) — the per-env sub-resource
// (`GET .../environments/{env}/deployment-branch-policies`) that would
// answer "which branches" isn't called; ListEnvironments' own
// deployment_branch_policy.protected_branches/custom_branch_policies flags
// already answer the boolean this check asks ("not all branches"), and
// that's this check's whole scope.
package envseparation

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	ghgithub "github.com/google/go-github/v75/github"

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/model"
)

const collectorID = "C03.env-separation"

var checkTitles = map[string]string{
	"C03.env.exists":             "A production-like environment exists",
	"C03.env.protection-rules":   "Production-like environments have at least one protection rule",
	"C03.env.required-reviewers": "Production-like environments require reviewer approval before deployment",
	"C03.env.branch-policy":      "Production-like environments restrict which branches/tags can deploy",
}

var checkIDs = []string{
	"C03.env.exists",
	"C03.env.protection-rules",
	"C03.env.required-reviewers",
	"C03.env.branch-policy",
}

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:         id,
			Title:      checkTitles[id],
			Collector:  collectorID,
			TokenScope: "repo (classic) or Actions: read-only (fine-grained)",
		})
	}
}

// Collector implements C03 env-separation.
type Collector struct {
	token string

	// newClientForTest overrides how each repo's Client is constructed —
	// see repoprotection.Collector's identical field for why.
	newClientForTest func(token string) *ghcollect.Client
}

// New returns a C03 collector authenticated with token. Like repoprotection
// (and unlike org-security), this fans out per-repo via ForEachRepo's
// concurrent worker pool, so each repo constructs its own Client rather
// than sharing one across concurrently-processed repos — see
// repoprotection.New's doc comment for the full reasoning, which applies
// identically here.
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
	repoResults := ghcollect.ForEachRepo(ctx, scope.Repos, ghcollect.DefaultConcurrency, func(ctx context.Context, repo string) ([]model.CheckResult, error) {
		client := c.newClient()
		return collectRepo(ctx, client, scope.Org, repo), nil
	})

	var all []model.CheckResult
	for _, r := range repoResults {
		if r.Err != nil {
			all = append(all, allNotCheckable(scope.Org, r.Repo, fmt.Sprintf("scan canceled before this repo's checks ran: %v", r.Err), []model.Provenance{})...)
			continue
		}
		all = append(all, r.Value...)
	}
	if all == nil {
		all = []model.CheckResult{}
	}
	return all, nil
}

// collectRepo resolves env-separation posture for one repo and emits all
// four CheckResults. It never returns an error; every failure becomes a
// not-checkable result for the affected check(s).
func collectRepo(ctx context.Context, client *ghcollect.Client, org, repo string) []model.CheckResult {
	var envs []*ghgithub.Environment
	opts := &ghgithub.EnvironmentListOptions{ListOptions: ghgithub.ListOptions{PerPage: 100}}
	for {
		resp, httpResp, err := client.REST.Repositories.ListEnvironments(ctx, org, repo, opts)
		if err != nil {
			return allNotCheckable(org, repo, notCheckableReason(httpResp, err, org, repo), client.Provenance())
		}
		if resp != nil {
			envs = append(envs, resp.Environments...)
		}
		if httpResp.NextPage == 0 {
			break
		}
		opts.Page = httpResp.NextPage
	}
	prov := client.Provenance()

	if len(envs) == 0 {
		return allNotCheckable(org, repo, "no environments configured", prov)
	}

	allNames := envNames(envs)
	prodEnvs := prodLikeEnvs(envs)
	if len(prodEnvs) == 0 {
		return allPartialNoProdEnv(org, repo, allNames, prov)
	}

	return []model.CheckResult{
		checkExists(org, repo, allNames, prodEnvs, prov),
		checkProtectionRules(org, repo, prodEnvs, prov),
		checkRequiredReviewers(org, repo, prodEnvs, prov),
		checkBranchPolicy(org, repo, prodEnvs, prov),
	}
}

// prodLikeEnvName is the heuristic the issue this collector was built
// against specifies: name matches "prod*"/"production" case-insensitively.
// A case-insensitive "prod" prefix match covers both forms (and common
// variants like "prod-us-east") in one rule.
func prodLikeEnvName(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "prod")
}

func envNames(envs []*ghgithub.Environment) []string {
	names := make([]string, 0, len(envs))
	for _, e := range envs {
		names = append(names, e.GetName())
	}
	return names
}

func prodLikeEnvs(envs []*ghgithub.Environment) []*ghgithub.Environment {
	var out []*ghgithub.Environment
	for _, e := range envs {
		if prodLikeEnvName(e.GetName()) {
			out = append(out, e)
		}
	}
	return out
}

func notCheckableReason(resp *ghgithub.Response, err error, org, repo string) string {
	if resp != nil {
		switch {
		case resp.StatusCode == http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to read environments on %s/%s", org, repo)
		case ghcollect.IsPlanGated(resp.StatusCode):
			return fmt.Sprintf("environments API not available for %s/%s (plan-gated feature, or repository not found)", org, repo)
		}
	}
	return fmt.Sprintf("could not query environments for %s/%s: %v", org, repo, err)
}

func allNotCheckable(org, repo, reason string, prov []model.Provenance) []model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	out := make([]model.CheckResult, 0, len(checkIDs))
	for _, id := range checkIDs {
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

// allPartialNoProdEnv is the "envs exist but none production-like by
// heuristic" case: a human reviewer, not the heuristic, should decide
// whether one of these environments is actually production — so every
// check reports partial (an affirmative "something exists but is
// ambiguous", not an honest "nothing to evaluate" not-checkable, and not a
// fabricated pass/fail against a guessed target).
func allPartialNoProdEnv(org, repo string, allNames []string, prov []model.Provenance) []model.CheckResult {
	reason := fmt.Sprintf("%d environment(s) exist but none match the production-like naming heuristic (prod*/production, case-insensitive) — a human reviewer should judge whether one of them is production", len(allNames))
	out := make([]model.CheckResult, 0, len(checkIDs))
	for _, id := range checkIDs {
		out = append(out, model.CheckResult{
			CheckID:    id,
			Title:      checkTitles[id],
			Status:     model.StatusPartial,
			Reason:     reason,
			Scope:      model.ScopeRef{Org: org, Repo: repo},
			Provenance: prov,
			Facts:      map[string]any{"all_environment_names": allNames},
		})
	}
	return out
}
