package envseparation

import (
	"fmt"

	ghgithub "github.com/google/go-github/v75/github"

	"gitlab.com/sioakeim/attestward/internal/model"
)

// GitHub's environments API represents each protection rule as one entry in
// an untyped list, tagged by a "type" string — go-github doesn't expose
// named constants for these, so they're named here from GitHub's own REST
// API documentation for environment protection rules.
const protectionRuleTypeRequiredReviewers = "required_reviewers"

func checkExists(org, repo string, allNames []string, prodEnvs []*ghgithub.Environment, prov []model.Provenance) model.CheckResult {
	const id = "C03.env.exists"
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
		Reason: fmt.Sprintf("%d production-like environment(s) found among %d total", len(prodEnvs), len(allNames)),
		Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"all_environment_names":        allNames,
			"production_like_environments": envNames(prodEnvs),
			"production_like_heuristic":    "name matches prod*/production, case-insensitive",
		},
	}
}

func checkProtectionRules(org, repo string, prodEnvs []*ghgithub.Environment, prov []model.Provenance) model.CheckResult {
	const id = "C03.env.protection-rules"
	var withoutRules []string
	for _, e := range prodEnvs {
		if len(e.ProtectionRules) == 0 {
			withoutRules = append(withoutRules, e.GetName())
		}
	}
	status, reason := model.StatusVerifiedPass, "every production-like environment has at least one protection rule"
	if len(withoutRules) > 0 {
		status = model.StatusVerifiedFail
		reason = fmt.Sprintf("environment(s) with no protection rules: %v", withoutRules)
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"production_like_environments":    envNames(prodEnvs),
			"environments_without_protection": withoutRules,
		},
	}
}

func checkRequiredReviewers(org, repo string, prodEnvs []*ghgithub.Environment, prov []model.Provenance) model.CheckResult {
	const id = "C03.env.required-reviewers"
	var withoutReviewers []string
	for _, e := range prodEnvs {
		if !hasRequiredReviewers(e) {
			withoutReviewers = append(withoutReviewers, e.GetName())
		}
	}
	status, reason := model.StatusVerifiedPass, "every production-like environment requires reviewer approval"
	if len(withoutReviewers) > 0 {
		status = model.StatusVerifiedFail
		reason = fmt.Sprintf("environment(s) without required reviewers: %v", withoutReviewers)
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"production_like_environments":            envNames(prodEnvs),
			"environments_without_required_reviewers": withoutReviewers,
		},
	}
}

func hasRequiredReviewers(e *ghgithub.Environment) bool {
	for _, rule := range e.ProtectionRules {
		if rule.Type != nil && *rule.Type == protectionRuleTypeRequiredReviewers && len(rule.Reviewers) > 0 {
			return true
		}
	}
	return false
}

func checkBranchPolicy(org, repo string, prodEnvs []*ghgithub.Environment, prov []model.Provenance) model.CheckResult {
	const id = "C03.env.branch-policy"
	var withoutPolicy []string
	for _, e := range prodEnvs {
		if !hasBranchPolicy(e) {
			withoutPolicy = append(withoutPolicy, e.GetName())
		}
	}
	status, reason := model.StatusVerifiedPass, "every production-like environment restricts which branches/tags can deploy"
	if len(withoutPolicy) > 0 {
		status = model.StatusVerifiedFail
		reason = fmt.Sprintf("environment(s) that allow deployment from any branch: %v", withoutPolicy)
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"production_like_environments":     envNames(prodEnvs),
			"environments_allowing_any_branch": withoutPolicy,
		},
	}
}

func hasBranchPolicy(e *ghgithub.Environment) bool {
	p := e.DeploymentBranchPolicy
	if p == nil {
		return false
	}
	return p.GetProtectedBranches() || p.GetCustomBranchPolicies()
}
