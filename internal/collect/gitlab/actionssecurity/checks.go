package actionssecurity

import (
	"fmt"
	"strings"

	"gitlab.com/sioakeim/attestward/internal/model"
)

const (
	idPinned           = "C08.actions.pinned"
	idTokenPermissions = "C08.actions.token-permissions"
	idPRTarget         = "C08.actions.pull-request-target"
	idOIDC             = "C08.actions.oidc-vs-secrets"
	idSelfHosted       = "C08.actions.self-hosted"
)

func result(id, org, repo string, status model.Status, reason string, prov []model.Provenance, facts map[string]any) model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope:      model.ScopeRef{Org: org, Repo: repo, Platform: platform},
		Provenance: prov, Facts: facts,
	}
}

func notCheckable(id, org, repo, reason string, prov []model.Provenance, facts map[string]any) model.CheckResult {
	return result(id, org, repo, model.StatusNotCheckable, reason, prov, facts)
}

// ciConfigUnavailableReason explains why the CI configuration could not be
// used as evidence, for the two checks that depend on it. The lint API
// answers 200 with valid=false for a project that simply has no CI
// configuration AND for one whose configuration exists but has an include
// that would not resolve, so the errors GitLab returned are quoted rather
// than paraphrased into a guess about which case this is.
func ciConfigUnavailableReason(lint ciLintRaw, lintErr error) string {
	if lintErr != nil {
		return fmt.Sprintf("could not lint the project's CI configuration: %v", lintErr)
	}
	detail := "GitLab reported no detail"
	if len(lint.Errors) > 0 {
		detail = strings.Join(lint.Errors, "; ")
	}
	return "GitLab could not resolve this project's CI configuration, so its includes are unknown — " +
		"either the project has no CI configuration, or an included file failed to resolve: " + detail
}

// -----------------------------------------------------------------------
// C08.actions.pinned
// -----------------------------------------------------------------------

// checkPinned is the GitLab counterpart of the GitHub check's "is every
// third-party action pinned to a commit SHA" question, asked of GitLab CI's
// own supply-chain mechanism: `include:`. It evaluates every include GitLab
// itself resolved, transitively, which is why it reads the CI Lint API
// rather than the raw .gitlab-ci.yml — an unpinned include pulled in by an
// included file is this project's exposure just as much as one written in
// its own config, and the raw file cannot see it.
func checkPinned(org, repo string, lint ciLintRaw, lintErr error, prov []model.Provenance) model.CheckResult {
	if lintErr != nil || lint.Includes == nil {
		return notCheckable(idPinned, org, repo, ciConfigUnavailableReason(lint, lintErr), prov, nil)
	}

	findings := classifyIncludes(*lint.Includes)
	var unpinned, unknown []includeFinding
	evaluated := 0
	for _, f := range findings {
		switch f.Class {
		case classPinnable:
			evaluated++
			if !f.Pinned {
				unpinned = append(unpinned, f)
			}
		case classUnknown:
			unknown = append(unknown, f)
		case classNotPinnable:
		}
	}

	facts := map[string]any{
		"includes":           includeFindingsToFacts(findings),
		"unpinned_includes":  includeFindingsToFacts(unpinned),
		"unrecognized_types": includeFindingsToFacts(unknown),
		"evaluated_count":    evaluated,
	}

	switch {
	case len(unpinned) > 0:
		return result(idPinned, org, repo, model.StatusVerifiedFail,
			fmt.Sprintf("%d included external CI configuration file(s) are not pinned to a full commit SHA", len(unpinned)),
			prov, facts)
	case len(unknown) > 0:
		return result(idPinned, org, repo, model.StatusPartial,
			fmt.Sprintf("every include this build recognizes is pinned to a full commit SHA, but %d include(s) "+
				"use a type this build does not classify — their pinning was not evaluated (see "+
				"Facts.unrecognized_types)", len(unknown)),
			prov, facts)
	case evaluated == 0:
		return result(idPinned, org, repo, model.StatusVerifiedPass,
			"this project's CI configuration includes no external file that carries a ref or version to pin",
			prov, facts)
	default:
		return result(idPinned, org, repo, model.StatusVerifiedPass,
			fmt.Sprintf("all %d included external CI configuration file(s) are pinned to a full commit SHA", evaluated),
			prov, facts)
	}
}

// -----------------------------------------------------------------------
// C08.actions.token-permissions
// -----------------------------------------------------------------------

// checkTokenPermissions answers the least-privilege-CI-token question with
// the control GitLab actually has. It is deliberately NOT presented as an
// equivalent of GitHub's per-workflow `permissions:` block — see the package
// doc comment for why no such equivalent exists on GitLab and what
// inbound_enabled does instead.
//
// allowlistProjects/allowlistGroups are context facts only. They are read
// through separate endpoints that can fail independently of the scope
// setting itself, and a failure there is tolerated rather than made fatal —
// the same treatment GitHub's own token-permissions check gives its
// repo-default-permissions context fact.
func checkTokenPermissions(org, repo string, scope jobTokenScopeRaw, scopeErr error, allowlistProjects, allowlistGroups int, allowlistKnown bool, prov []model.Provenance) model.CheckResult {
	if scopeErr != nil {
		return notCheckable(idTokenPermissions, org, repo,
			fmt.Sprintf("could not read this project's CI/CD job token scope (a 403 here commonly means the "+
				"token lacks the Maintainer role, which GitLab requires for this endpoint): %v", scopeErr), prov, nil)
	}

	facts := map[string]any{"inbound_enabled": scope.InboundEnabled}
	if allowlistKnown {
		facts["allowlist_project_count"] = allowlistProjects
		facts["allowlist_group_count"] = allowlistGroups
	}

	if !scope.InboundEnabled {
		return result(idTokenPermissions, org, repo, model.StatusVerifiedFail,
			"this project's CI/CD job token allowlist is disabled — a job token from ANY project on the "+
				"instance can be used to access this project's API and resources",
			prov, facts)
	}
	return result(idTokenPermissions, org, repo, model.StatusVerifiedPass,
		"this project's CI/CD job token allowlist is enabled — only jobs from allowlisted projects and "+
			"groups can use a job token against this project",
		prov, facts)
}

// -----------------------------------------------------------------------
// C08.actions.pull-request-target
// -----------------------------------------------------------------------

// checkForkPipelinesInParent is the GitLab-native form of the risk GitHub's
// pull_request_target check exists for: a contributor's fork branch running
// in the upstream project's privileged context. See the package doc comment
// for why it has no verified-fail outcome and why it is not called a
// pull_request_target equivalent.
func checkForkPipelinesInParent(org, repo string, proj projectRaw, projErr error, prov []model.Provenance) model.CheckResult {
	if projErr != nil {
		return notCheckable(idPRTarget, org, repo, fmt.Sprintf("could not read the project: %v", projErr), prov, nil)
	}
	if proj.AllowForkPipelinesInParent == nil {
		return notCheckable(idPRTarget, org, repo,
			"the project payload did not include ci_allow_fork_pipelines_to_run_in_parent_project — GitLab "+
				"omits that field for a caller below the Maintainer role, and an absent field cannot be read "+
				"as the setting being off",
			prov, map[string]any{"visibility": proj.Visibility})
	}

	allowed := *proj.AllowForkPipelinesInParent
	facts := map[string]any{
		"visibility": proj.Visibility,
		"ci_allow_fork_pipelines_to_run_in_parent_project": allowed,
	}

	switch {
	case !allowed:
		return result(idPRTarget, org, repo, model.StatusVerifiedPass,
			"merge requests from forks cannot run a pipeline in this project's context — their pipelines run "+
				"in the fork, with the fork's own CI/CD variables and runners",
			prov, facts)
	case proj.Visibility != "public":
		return result(idPRTarget, org, repo, model.StatusVerifiedPass,
			fmt.Sprintf("fork merge request pipelines may run in this project's context, but the project is %s "+
				"rather than public — forking it requires access already granted, so the untrusted outside "+
				"contributor this check is about does not apply", proj.Visibility),
			prov, facts)
	default:
		return result(idPRTarget, org, repo, model.StatusPartial,
			"this project is public and permits a merge request from a fork to run its pipeline in this "+
				"project's context, using this project's CI/CD variables, settings and runners — a member "+
				"must still start that pipeline deliberately, so this is an exposure to review, not a "+
				"confirmed exploit path",
			prov, facts)
	}
}

// -----------------------------------------------------------------------
// C08.actions.oidc-vs-secrets
// -----------------------------------------------------------------------

// checkOIDCvsSecrets weighs two independent pieces of evidence: whether the
// merged CI configuration declares GitLab's OIDC keyword (`id_tokens:`), and
// whether the project stores a cloud credential that is long-lived by
// construction. Neither alone answers the question — a project can declare
// id_tokens for one cloud and still keep a static key for another, which is
// exactly the partial case below.
func checkOIDCvsSecrets(org, repo string, lint ciLintRaw, lintErr error, vars []variableRaw, varsErr error, prov []model.Provenance) model.CheckResult {
	if lintErr != nil || lint.Includes == nil {
		return notCheckable(idOIDC, org, repo, ciConfigUnavailableReason(lint, lintErr), prov, nil)
	}
	oidcJobs, parsed := idTokenJobs(lint.MergedYAML)
	if !parsed {
		return notCheckable(idOIDC, org, repo,
			"the merged CI configuration GitLab returned was empty or could not be parsed as YAML, so whether "+
				"any job authenticates with an id_tokens OIDC token is unknown", prov, nil)
	}
	if varsErr != nil {
		return notCheckable(idOIDC, org, repo,
			fmt.Sprintf("could not read this project's CI/CD variables, so a stored long-lived cloud "+
				"credential can be neither found nor ruled out (a 403 here commonly means the token lacks "+
				"the Maintainer role, which GitLab requires for this endpoint): %v", varsErr), prov, nil)
	}

	static := findStaticCloudCredentials(vars)
	if oidcJobs == nil {
		// An empty slice, not nil: nil marshals to JSON null, and a reader
		// of the pack should see "no jobs declare id_tokens" as an empty
		// list rather than a missing value.
		oidcJobs = []string{}
	}
	facts := map[string]any{
		"id_token_jobs":               oidcJobs,
		"static_credential_variables": staticCredentialFindingsToFacts(static),
	}

	switch {
	case len(static) > 0 && len(oidcJobs) == 0:
		return result(idOIDC, org, repo, model.StatusVerifiedFail,
			fmt.Sprintf("this project stores %d long-lived cloud credential variable(s) and no job declares an "+
				"id_tokens OIDC token — see Facts.static_credential_variables for the variable names, never "+
				"the values", len(static)),
			prov, facts)
	case len(static) > 0:
		return result(idOIDC, org, repo, model.StatusPartial,
			fmt.Sprintf("%d job(s) authenticate with an id_tokens OIDC token, but this project also still "+
				"stores %d long-lived cloud credential variable(s)", len(oidcJobs), len(static)),
			prov, facts)
	case len(oidcJobs) > 0:
		return result(idOIDC, org, repo, model.StatusVerifiedPass,
			fmt.Sprintf("%d job(s) authenticate with an id_tokens OIDC token and this project stores no "+
				"long-lived cloud credential variable", len(oidcJobs)),
			prov, facts)
	default:
		return notCheckable(idOIDC, org, repo,
			"no cloud authentication of either kind was detected: no job declares an id_tokens OIDC token, "+
				"and no project-level CI/CD variable holds a recognized long-lived cloud credential — so "+
				"there is no cloud deployment here to judge",
			prov, facts)
	}
}

// -----------------------------------------------------------------------
// C08.actions.self-hosted
// -----------------------------------------------------------------------

func runnerFindingsToFacts(runners []runnerRaw) []map[string]any {
	out := make([]map[string]any, 0, len(runners))
	for _, r := range runners {
		out = append(out, map[string]any{"id": r.ID, "description": r.Description, "runner_type": r.RunnerType})
	}
	return out
}

// checkSelfHosted asks whether this project's own runners can be reached by
// a fork's merge request. Like its GitHub twin it has no verified-fail
// outcome: runner exposure is capped at partial by design.
func checkSelfHosted(org, repo string, proj projectRaw, projErr error, runners []runnerRaw, runnersErr error, prov []model.Provenance) model.CheckResult {
	if projErr != nil {
		return notCheckable(idSelfHosted, org, repo, fmt.Sprintf("could not read the project: %v", projErr), prov, nil)
	}
	if runnersErr != nil {
		return notCheckable(idSelfHosted, org, repo,
			fmt.Sprintf("could not list this project's project- and group-registered runners (a 403 here "+
				"commonly means the token lacks the Maintainer or Auditor role, which GitLab requires for "+
				"this endpoint): %v", runnersErr), prov, nil)
	}

	facts := map[string]any{
		"visibility":           proj.Visibility,
		"self_managed_runners": runnerFindingsToFacts(runners),
	}
	if len(runners) == 0 {
		return result(idSelfHosted, org, repo, model.StatusVerifiedPass,
			"no project- or group-registered runner is attached to this project, so there is no self-managed "+
				"runner for a fork's merge request to reach",
			prov, facts)
	}

	if proj.AllowForkPipelinesInParent == nil {
		return notCheckable(idSelfHosted, org, repo,
			fmt.Sprintf("%d project- or group-registered runner(s) are attached, but the project payload did "+
				"not include ci_allow_fork_pipelines_to_run_in_parent_project — GitLab omits that field for a "+
				"caller below the Maintainer role, and whether a fork's merge request can reach those runners "+
				"cannot be answered without it", len(runners)),
			prov, facts)
	}
	allowed := *proj.AllowForkPipelinesInParent
	facts["ci_allow_fork_pipelines_to_run_in_parent_project"] = allowed

	switch {
	case !allowed:
		return result(idSelfHosted, org, repo, model.StatusVerifiedPass,
			fmt.Sprintf("%d project- or group-registered runner(s) are attached, but merge requests from forks "+
				"cannot run a pipeline in this project's context, so a fork's code never reaches them", len(runners)),
			prov, facts)
	case proj.Visibility != "public":
		return result(idSelfHosted, org, repo, model.StatusVerifiedPass,
			fmt.Sprintf("%d project- or group-registered runner(s) are attached and fork merge request "+
				"pipelines may run in this project's context, but the project is %s rather than public — "+
				"forking it requires access already granted", len(runners), proj.Visibility),
			prov, facts)
	default:
		return result(idSelfHosted, org, repo, model.StatusPartial,
			fmt.Sprintf("%d project- or group-registered runner(s) are attached to a public project that "+
				"permits fork merge request pipelines to run in its own context — a fork's code is a "+
				"potential path to those machines", len(runners)),
			prov, facts)
	}
}
