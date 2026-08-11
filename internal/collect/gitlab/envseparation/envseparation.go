// Package envseparation implements C03 env-separation for GitLab: whether
// deployments to production-like environments flow through separated,
// protected GitLab Environments (SSDF PO.5.1).
//
// Three of its four checks are real. Before this package existed, all four
// were registered through internal/collect/gitlab/unsupported with one
// shared reason: "Protected environments... are a paid-tier feature. This
// build reads neither yet." That was wrong, not just imprecise — verified
// live against gitlab.com/sioakeim/attestward (2026-08-11), contrary to
// docs.gitlab.com's own "Premium, Ultimate" tier badge on the Protected
// Environments API page: GET and POST /projects/:id/protected_environments
// both succeeded on this Free-tier project, including a real approval_rules
// entry (required_approvals: 1) returned back unchanged in the response.
// Whatever the billing tier badge says, the REST API a collector actually
// reads accepts and returns this data on Free.
//
// This deliberately does NOT try to prove the approval rule is enforced at
// deploy time (a real deployment created directly via the Deployments API
// went straight to status "running" with pending_approval_count 0, despite
// the rule existing — though that may just mean the Deployments API's
// create-a-record endpoint bypasses the pipeline-level approval gate
// entirely, tier aside; it was inconclusive either way). No check anywhere
// in this codebase asserts live enforcement — C02 repo-protection doesn't
// push a bad commit to prove a branch rule blocks it, either. Every check
// here reads configuration state, matching that established convention.
//
// The fourth check, branch-policy, stays always-not-checkable — but now for
// a platform-gap reason, not the old wrong tier one. GitLab's Protected
// Environments model restricts WHO may deploy (deploy_access_levels) and how
// many approvals are required (approval_rules); unlike GitHub's
// deployment_branch_policy or Azure DevOps's Branch control check, it has no
// per-environment mechanism restricting WHICH branch/tag may deploy at all.
// That restriction lives in each deploy job's own `rules:` in
// .gitlab-ci.yml, which is per-job CI configuration, not an
// environment-scoped API this check could read.
package envseparation

import (
	"context"
	"fmt"
	"strings"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const platform = "gitlab"
const collectorID = "C03.env-separation"

const (
	idExists            = "C03.env.exists"
	idProtectionRules   = "C03.env.protection-rules"
	idRequiredReviewers = "C03.env.required-reviewers"
	idBranchPolicy      = "C03.env.branch-policy"
)

var checkIDs = []string{idExists, idProtectionRules, idRequiredReviewers, idBranchPolicy}

// stateDependentCheckIDs excludes branch-policy deliberately. Its own rubric
// documents exactly one status, not-checkable, unconditionally — it has no
// data source in any environment state, unlike the other three, whose
// not-checkable-ness (and, in allPartialNoProdEnv's case, partial-ness)
// genuinely depends on what the API returned. Looping branch-policy through
// these environment-state-driven helpers would emit a status — partial —
// its own registered rubric never documents.
var stateDependentCheckIDs = []string{idExists, idProtectionRules, idRequiredReviewers}

var checkTitles = map[string]string{
	idExists:            "A production-like environment exists",
	idProtectionRules:   "Production-like environments have at least one protection rule",
	idRequiredReviewers: "Production-like environments require reviewer approval before deployment",
	idBranchPolicy:      "Production-like environments restrict which branches/tags can deploy",
}

var checkRemediations = map[string]string{
	idExists: "Project → Deployments → Environments → New environment → name it \"production\" (or any " +
		"prod*/production variant — this check's name heuristic is case-insensitive) so deployments can " +
		"be routed through it.",
	idProtectionRules: "Project → Settings → CI/CD → Protected environments → protect the production-like " +
		"environment, restricting at least who may deploy to it (Allowed to Deploy).",
	idRequiredReviewers: "Project → Settings → CI/CD → Protected environments → protect the production-like " +
		"environment and add an Approval rule requiring at least one approval.",
	idBranchPolicy: "No remediation applicable via this tool: GitLab has no per-environment branch-" +
		"restriction mechanism — restrict which branch/tag may deploy in the deploy job's own `rules:` in " +
		".gitlab-ci.yml instead, and document that control in the self-attestation questionnaire.",
}

const sharedNotCheckableRubric = "the environments list, or the protected-environments list, couldn't be " +
	"read (403/404/other API error), or the project has zero environments configured at all"

const sharedPartialRubric = "one or more environments exist, but none match the production-like naming " +
	"heuristic (`prod`* prefix, case-insensitive) — a human reviewer should judge whether one of them is " +
	"actually production before this check can evaluate anything"

var checkRubrics = map[string]map[model.Status]string{
	idExists: {
		model.StatusVerifiedPass: "at least one environment's name matches the production-like heuristic " +
			"(`prod`* prefix, case-insensitive)",
		model.StatusPartial:      sharedPartialRubric,
		model.StatusNotCheckable: sharedNotCheckableRubric,
	},
	idProtectionRules: {
		model.StatusVerifiedPass: "every production-like environment has a matching protected_environments " +
			"entry (any protection at all — GitLab requires at least deploy_access_levels to protect one, " +
			"so a matching entry's mere existence is the \"any type\" signal, mirroring the GitHub twin's " +
			"identical framing)",
		model.StatusVerifiedFail: "at least one production-like environment has no matching " +
			"protected_environments entry",
		model.StatusPartial:      sharedPartialRubric,
		model.StatusNotCheckable: sharedNotCheckableRubric,
	},
	idRequiredReviewers: {
		model.StatusVerifiedPass: "every production-like environment's protected_environments entry has at " +
			"least one approval_rules entry with required_approvals >= 1",
		model.StatusVerifiedFail: "at least one production-like environment has no protected_environments " +
			"entry, or one with no approval_rules entry requiring at least one approval",
		model.StatusPartial:      sharedPartialRubric,
		model.StatusNotCheckable: sharedNotCheckableRubric,
	},
	idBranchPolicy: {
		model.StatusNotCheckable: "always — GitLab has no per-environment branch-restriction mechanism; " +
			"which branch or tag may deploy is controlled by each deploy job's own `rules:` in " +
			".gitlab-ci.yml, which is per-job pipeline configuration this check does not read, not an " +
			"environment-scoped API result",
	},
}

var checkEndpoints = map[string][]string{
	idExists:            {"GET /projects/{id}/environments"},
	idProtectionRules:   {"GET /projects/{id}/environments", "GET /projects/{id}/protected_environments"},
	idRequiredReviewers: {"GET /projects/{id}/environments", "GET /projects/{id}/protected_environments"},
	idBranchPolicy:      nil,
}

const fixtureRef = "internal/collect/gitlab/envseparation/envseparation_test.go"

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID: id, Platform: platform, Title: checkTitles[id], Collector: collectorID,
			TokenScope:  "read_api (Reporter or above on the project)",
			Remediation: checkRemediations[id], Rubric: checkRubrics[id],
			Endpoints: checkEndpoints[id], FixtureRef: fixtureRef,
		})
	}
}

// environment is the subset of GitLab's Environments response this needs.
type environment struct {
	Name string `json:"name"`
}

// protectedEnvironment is the subset of GitLab's Protected Environments
// response this needs, verified 2026-08-11 against a live protected
// environment created (and deleted) on this project.
type protectedEnvironment struct {
	Name          string         `json:"name"`
	ApprovalRules []approvalRule `json:"approval_rules"`
}

type approvalRule struct {
	RequiredApprovals int `json:"required_approvals"`
}

// Collector implements C03 env-separation for GitLab.
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

// Collect reads each repo's environments and, for any production-like one,
// its protected-environments config, and returns all four checks per repo.
// A read failure yields not-checkable results rather than an error, so one
// unreadable project cannot fail a whole scan.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	client, err := c.newClient()
	if err != nil {
		reason := fmt.Sprintf("could not build a GitLab client: %v", err)
		var out []model.CheckResult
		for _, repo := range scope.Repos {
			out = append(out, allNotCheckable(scope.Org, repo, reason, nil)...)
		}
		return out, nil
	}

	var all []model.CheckResult
	for _, repo := range scope.Repos {
		all = append(all, collectRepo(ctx, client, scope.Org, repo)...)
	}
	return all, nil
}

func collectRepo(ctx context.Context, client *gitlabcollect.Client, org, repo string) []model.CheckResult {
	id := projectID(org, repo)

	envs, err := gitlabcollect.GetJSONPaged[environment](ctx, client, "/projects/"+id+"/environments", nil)
	prov := client.Provenance()
	if err != nil {
		return allNotCheckable(org, repo, fmt.Sprintf("could not read environments: %v", err), prov)
	}
	if len(envs) == 0 {
		return allNotCheckable(org, repo, "no environments configured", prov)
	}

	allNames := envNames(envs)
	prodNames := prodLikeNames(allNames)
	if len(prodNames) == 0 {
		return allPartialNoProdEnv(org, repo, allNames, prov)
	}

	protected, err := gitlabcollect.GetJSONPaged[protectedEnvironment](ctx, client, "/projects/"+id+"/protected_environments", nil)
	prov = client.Provenance()
	if err != nil {
		return allNotCheckable(org, repo, fmt.Sprintf("could not read protected environments: %v", err), prov)
	}
	byName := map[string]protectedEnvironment{}
	for _, pe := range protected {
		byName[pe.Name] = pe
	}

	return []model.CheckResult{
		checkExists(org, repo, prodNames, prov),
		checkProtectionRules(org, repo, prodNames, byName, prov),
		checkRequiredReviewers(org, repo, prodNames, byName, prov),
		branchPolicyResult(org, repo),
	}
}

func checkExists(org, repo string, prodNames []string, prov []model.Provenance) model.CheckResult {
	return model.CheckResult{
		CheckID: idExists, Title: checkTitles[idExists], Status: model.StatusVerifiedPass,
		Reason: fmt.Sprintf("production-like environment(s) found: %v", prodNames),
		Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		Facts: map[string]any{"production_like_environments": prodNames},
	}
}

func checkProtectionRules(org, repo string, prodNames []string, byName map[string]protectedEnvironment, prov []model.Provenance) model.CheckResult {
	var unprotected []string
	for _, name := range prodNames {
		if _, ok := byName[name]; !ok {
			unprotected = append(unprotected, name)
		}
	}
	if len(unprotected) > 0 {
		return model.CheckResult{
			CheckID: idProtectionRules, Title: checkTitles[idProtectionRules], Status: model.StatusVerifiedFail,
			Reason: fmt.Sprintf("no protected_environments entry for: %v", unprotected),
			Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
			Facts: map[string]any{"unprotected_environments": unprotected},
		}
	}
	return model.CheckResult{
		CheckID: idProtectionRules, Title: checkTitles[idProtectionRules], Status: model.StatusVerifiedPass,
		Reason: fmt.Sprintf("every production-like environment is protected: %v", prodNames),
		Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		Facts: map[string]any{"production_like_environments": prodNames},
	}
}

func checkRequiredReviewers(org, repo string, prodNames []string, byName map[string]protectedEnvironment, prov []model.Provenance) model.CheckResult {
	var missing []string
	for _, name := range prodNames {
		pe, ok := byName[name]
		if !ok || !hasRequiredApproval(pe) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return model.CheckResult{
			CheckID: idRequiredReviewers, Title: checkTitles[idRequiredReviewers], Status: model.StatusVerifiedFail,
			Reason: fmt.Sprintf("no approval rule requiring at least one approval for: %v", missing),
			Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
			Facts: map[string]any{"missing_required_reviewers": missing},
		}
	}
	return model.CheckResult{
		CheckID: idRequiredReviewers, Title: checkTitles[idRequiredReviewers], Status: model.StatusVerifiedPass,
		Reason: fmt.Sprintf("every production-like environment requires at least one approval: %v", prodNames),
		Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		Facts: map[string]any{"production_like_environments": prodNames},
	}
}

func hasRequiredApproval(pe protectedEnvironment) bool {
	for _, r := range pe.ApprovalRules {
		if r.RequiredApprovals >= 1 {
			return true
		}
	}
	return false
}

func branchPolicyResult(org, repo string) model.CheckResult {
	return notCheckableAlways(idBranchPolicy, org, repo, checkRubrics[idBranchPolicy][model.StatusNotCheckable], nil)
}

func notCheckableAlways(id, org, repo, reason string, prov []model.Provenance) model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
	}
}

func allNotCheckable(org, repo, reason string, prov []model.Provenance) []model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	out := make([]model.CheckResult, 0, len(checkIDs))
	for _, id := range stateDependentCheckIDs {
		out = append(out, model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: reason,
			Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		})
	}
	// branch-policy's own not-checkable reason is unconditional and never the
	// caller-supplied reason above — see its own doc comment.
	out = append(out, branchPolicyResult(org, repo))
	return out
}

// allPartialNoProdEnv mirrors the GitHub twin's identical judgment call for
// the three state-dependent checks: environments exist but none match the
// naming heuristic, so a human reviewer, not the heuristic, should decide
// whether one of them is actually production. branch-policy is NOT included
// in that partial state — its own registered rubric documents only
// not-checkable, unconditionally, so it keeps reporting that here too rather
// than a status nothing declared it could produce.
func allPartialNoProdEnv(org, repo string, allNames []string, prov []model.Provenance) []model.CheckResult {
	reason := fmt.Sprintf("%d environment(s) exist but none match the production-like naming heuristic "+
		"(prod*/production, case-insensitive) — a human reviewer should judge whether one of them is production",
		len(allNames))
	out := make([]model.CheckResult, 0, len(checkIDs))
	for _, id := range stateDependentCheckIDs {
		out = append(out, model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusPartial, Reason: reason,
			Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
			Facts: map[string]any{"all_environment_names": allNames},
		})
	}
	// branch-policy's rubric documents only not-checkable — it has no data
	// source in this state either, so it does not become partial just
	// because its three siblings did.
	out = append(out, branchPolicyResult(org, repo))
	return out
}

func prodLikeName(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "prod")
}

func envNames(envs []environment) []string {
	out := make([]string, 0, len(envs))
	for _, e := range envs {
		out = append(out, e.Name)
	}
	return out
}

func prodLikeNames(names []string) []string {
	var out []string
	for _, n := range names {
		if prodLikeName(n) {
			out = append(out, n)
		}
	}
	return out
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
