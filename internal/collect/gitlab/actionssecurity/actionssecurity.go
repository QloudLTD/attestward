// Package actionssecurity implements C08 actions-security for GitLab — the
// GitLab counterpart of internal/collect/github/actionssecurity, under the
// same five check IDs (collect.Register panics on a Collector-string
// mismatch across platforms, so collectorID below matches every twin's
// "C08.actions-security" exactly).
//
// All five checks are real here. None of the five is a literal port,
// because none of the GitHub mechanisms they name — GITHUB_TOKEN
// permissions blocks, the pull_request_target trigger, `uses:` action
// references, `runs-on: self-hosted` — exists on GitLab at all. Each was
// re-derived from the RISK the GitHub check exists to catch, and the titles
// are GitLab's own vocabulary rather than GitHub's, the same correction
// internal/collect/gitlab/vdp made to the private-reporting title it
// inherited.
//
// # What each check became, and what it deliberately does not claim
//
// C08.actions.pinned is the closest to a direct port. GitLab CI's
// third-party supply chain is the `include:` keyword, and GET
// /projects/:id/ci/lint reports every include GitLab resolved — transitively
// (a template that itself includes another appears too), honouring the
// project's ci_config_path, and, crucially, with the ref AS WRITTEN in
// extra.ref rather than only the commit it resolved to. Parsing the raw
// .gitlab-ci.yml would have seen only the top-level include: block and
// missed everything an included file pulls in.
//
// C08.actions.token-permissions is NOT a GitLab equivalent of GitHub's
// per-workflow `permissions:` block, and must not be read as one: GitLab
// has no keyword that scopes down what a job's own CI_JOB_TOKEN may do. Its
// least-privilege control for that token is the opposite direction — the
// project's inbound job token allowlist, which decides which OTHER projects'
// jobs may use a job token against this one. docs.gitlab.com describes
// inbound_enabled as whether "the allowlist for project access is active. If
// disabled, all projects have access." That is a real, free-tier,
// least-privilege property with a real fail state, so this check reports it
// and says plainly, in its title and rubric, that this is the property being
// reported.
//
// C08.actions.pull-request-target keeps the ID but not the concept. GitLab
// has no trigger that runs the target project's privileged CI against a
// contributor's code the way pull_request_target does; merge request
// pipelines from a fork "are created and run in the fork (source) project,
// not the parent (target) project" and use "the fork project's CI/CD
// configuration, resources, and project CI/CD variables" (docs.gitlab.com).
// The one mechanism that puts a fork's branch into the upstream project's
// context is the project setting
// ci_allow_fork_pipelines_to_run_in_parent_project, and that is what this
// check reads. It has no verified-fail outcome by design: GitLab requires a
// parent-project member with at least the Developer role to start such a
// pipeline deliberately, after accepting a warning, so the setting being on
// is an exposure to review rather than the automatic exploit path
// pull_request_target opens.
//
// C08.actions.self-hosted asks the same question its GitHub twin does — can
// an outside contributor's change reach machines this project runs itself —
// against GitLab's runner model, and also has no verified-fail outcome. It
// reads the project- and group-registered runners attached to the project
// and combines them with the same fork-pipeline setting, because on GitLab
// that setting IS the control: with it off, a fork's merge request pipeline
// runs in the fork and never acquires this project's runners. ⚠ Its blind
// spot is instance runners on a self-managed GitLab: those are operator-run
// machines that this check does not flag, because nothing in the API
// distinguishes them from GitLab.com's own hosted fleet, which is not a
// finding. It is honest on GitLab.com and understates on a self-managed
// instance.
//
// C08.actions.oidc-vs-secrets has no single anchor to read the way its
// GitHub twin does, because a GitLab job is a shell script rather than a
// declarative `uses:` step — there is no "the official AWS login action was
// configured with role-to-assume" to find. It weighs two independent
// signals instead: GitLab's own OIDC keyword `id_tokens:` in the merged CI
// configuration, and project-level CI/CD variables whose exact names are the
// documented environment variables a cloud SDK reads a long-lived credential
// from (see staticCloudCredentialVariables). A project showing neither is
// not-checkable, not a pass — "no cloud deployment detected" is not a
// security property, the same judgment the GitHub twin makes.
//
// # Verified live
//
// Every endpoint and every response shape relied on here was exercised live
// on 2026-08-13 against gitlab.com, using gitlab.com/sioakeim/attestward-
// scratch (a public Free-tier project with one project-registered runner)
// and gitlab.com/sioakeim/attestward. Specifically confirmed:
//
//   - GET /projects/:id/ci/lint answers 200 UNAUTHENTICATED on a public
//     project, so this check needs no elevated role, and 404 for a project
//     the caller cannot see.
//   - Its `includes` array reports extra.ref as written ("main", a full SHA,
//     or "HEAD" when ref: was omitted), and covers nested includes.
//   - `includes` is null — not [] — when GitLab could not resolve the
//     configuration, including for a project with no .gitlab-ci.yml at all;
//     [] with a populated merged_yaml is returned for a config that is
//     invalid for an unrelated (job-level) reason, so a job error does not
//     cost this collector its evidence.
//   - merged_yaml keeps `default: id_tokens:` and a job's own id_tokens
//     separate rather than folding one into the other.
//   - GET /projects/:id returns ci_allow_fork_pipelines_to_run_in_parent_
//     project only to a sufficiently privileged caller; unauthenticated on a
//     public project the field is simply absent. See projectRaw for why that
//     makes it a *bool.
//   - GET /projects/:id/runners paginates 125 shared instance runners for a
//     project with ONE project runner, so ?type=project_type and
//     ?type=group_type are filters this collector depends on rather than an
//     optimisation.
//   - GET /projects/:id/job_token_scope returned {"inbound_enabled":true,
//     "outbound_enabled":false} and 401s unauthenticated. ⚠ Turning
//     inbound_enabled OFF on GitLab.com is refused: PATCH answered 400 "Job
//     token scope cannot be disabled for this project because it is enforced
//     for the instance." So on GitLab.com that check's pass is the
//     instance's doing rather than the producer's, and its fail is
//     effectively unreachable — real only on a self-managed instance whose
//     administrator has not enforced it. Its rubric says so.
//
// The end-to-end collector was then run against both projects through the
// real CLI, and again after deliberately putting attestward-scratch into
// every failing state at once (fork pipelines permitted, an unpinned
// `include: project: ref: main`, and a stored AWS_SECRET_ACCESS_KEY),
// reproducing verified-fail on pinned and oidc-vs-secrets and partial on
// both fork checks against the live API. Every one of those changes was
// reverted afterwards.
//
// # Scope limits stated rather than implied
//
// Like internal/collect/gitlab/secretshygiene, the OIDC check reads only the
// project's OWN CI/CD variables — a long-lived cloud credential inherited
// from a group- or instance-level variable is invisible to it, and its
// rubric says so rather than leaving a reader to assume the Settings > CI/CD
// > Variables page was covered in full.
package actionssecurity

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
const collectorID = "C08.actions-security"

var checkIDs = []string{idPinned, idTokenPermissions, idPRTarget, idOIDC, idSelfHosted}

// checkTitles deliberately reuses none of the GitHub titles. Every one of
// them names a GitHub mechanism that does not exist on GitLab
// (GITHUB_TOKEN, pull_request_target, actions, self-hosted runners), and
// carrying those onto this platform is wrong regardless of what the check
// reports — the same correction internal/collect/gitlab/vdp made.
var checkTitles = map[string]string{
	idPinned:           "Included external CI configuration is pinned to a full commit SHA",
	idTokenPermissions: "CI/CD job token access to this project is restricted to an allowlist",
	idPRTarget:         "Fork merge requests cannot run pipelines in this project's context",
	idOIDC:             "Cloud authentication uses CI OIDC id_tokens rather than long-lived stored credentials",
	idSelfHosted:       "Project- and group-registered runners are not exposed to fork merge requests",
}

var checkTokenScopes = map[string]string{
	idPinned: "read_api, and less — GET /projects/{id}/ci/lint answered 200 with no token at all against a " +
		"public project in this build's own live verification. A private project needs enough access to read " +
		"it; the exact minimum role was not independently established",
	idTokenPermissions: "Maintainer or Owner role on the project — docs.gitlab.com states the job token scope " +
		"endpoints require it, and this build's verification token held Owner. A lower-privileged token's " +
		"exact response was not independently observed",
	idPRTarget: "Maintainer role on the project — ci_allow_fork_pipelines_to_run_in_parent_project is absent " +
		"from the project payload below it (confirmed live: an unauthenticated read of a public project " +
		"returned neither that field nor any other CI setting), and this check reports not-checkable rather " +
		"than reading its absence as a value",
	idOIDC: "Maintainer role on the project — GET /projects/{id}/variables requires it, and this check needs " +
		"that half of its evidence to rule a stored credential out. GET /projects/{id}/ci/lint, its other " +
		"half, needs far less",
	idSelfHosted: "Maintainer or Auditor role on the project — docs.gitlab.com states GET /projects/{id}/" +
		"runners requires \"at least the Maintainer or Auditor role for the target project\", and the same " +
		"Maintainer-gated project field C08.actions.pull-request-target depends on is needed once any runner " +
		"is found",
}

var checkRemediations = map[string]string{
	idPinned: "Pin every `include:` that names external CI configuration to a full 40-character commit SHA. " +
		"For `include: project:`, set `ref:` to the SHA rather than a branch or tag (and never omit `ref:` — " +
		"it then follows the target project's default branch). For `include: component:`, put the SHA after " +
		"the `@` instead of a catalog version or branch. A `remote:` include carries no ref at all: either " +
		"point its URL at a specific commit (the `/-/raw/<sha>/<file>` form) or, better, replace it with a " +
		"`project:` include that can be pinned properly. `local:` includes need nothing — they are already " +
		"fixed by this repository's own commit — and `template:` includes cannot be pinned at all, so " +
		"neither is evaluated.",
	idTokenPermissions: "Turn on Settings -> CI/CD -> Job token permissions -> \"Limit access to this " +
		"project\" (the API's inbound_enabled), then add only the projects and groups whose pipelines " +
		"genuinely need to reach this one. Note what this does and does not control: it governs which other " +
		"projects' jobs may use a CI_JOB_TOKEN against THIS project. GitLab has no equivalent of a per-" +
		"workflow token-permissions declaration, so there is nothing further to scope down inside " +
		".gitlab-ci.yml.",
	idPRTarget: "Set \"Run pipelines for merge requests from forks\" off in Settings -> CI/CD -> General " +
		"pipelines, or PUT ci_allow_fork_pipelines_to_run_in_parent_project=false through the Projects API. " +
		"A fork's merge request pipeline then runs in the fork, with the fork's own CI/CD variables and " +
		"runners, and can never be started against this project's. If the setting is genuinely needed, treat " +
		"starting such a pipeline as a code review: GitLab requires a member with at least the Developer " +
		"role to start it, and the fork's diff should be read before they do.",
	idOIDC: "Replace the stored cloud credential with GitLab's OIDC flow: declare an `id_tokens:` block on " +
		"the job (with the cloud's own `aud:`), exchange that token for short-lived credentials in the job " +
		"(for AWS `sts assume-role-with-web-identity`, for GCP workload identity federation, for Azure a " +
		"federated credential on the app registration), and then DELETE the long-lived variable from " +
		"Settings -> CI/CD -> Variables and revoke the underlying key at the cloud provider — leaving it in " +
		"place keeps the credential this check flags. If the variable is inherited from a group rather than " +
		"this project, this check cannot see it; remove it at the group instead.",
	idSelfHosted: "Set \"Run pipelines for merge requests from forks\" off (Settings -> CI/CD -> General " +
		"pipelines, or ci_allow_fork_pipelines_to_run_in_parent_project=false through the Projects API): a " +
		"fork's merge request pipeline then runs in the fork and never acquires this project's runners, " +
		"which clears this check without giving up the runners. Alternatives, if that setting must stay on: " +
		"mark the runner protected so it only runs jobs on protected branches and tags, or move the jobs to " +
		"GitLab-hosted runners.",
}

// sharedCIConfigNotCheckableRubric is shared by pinned and oidc-vs-secrets:
// both are computed from the SAME lint response, so a configuration that
// GitLab could not resolve reaches both identically. Kept in sync with
// ciConfigUnavailableReason.
const sharedCIConfigNotCheckableRubric = "GET /projects/{id}/ci/lint failed outright, or answered with a " +
	"null `includes` — which GitLab returns both for a project that has no CI configuration and for one " +
	"whose configuration exists but has an include that would not resolve; the errors GitLab reported are " +
	"quoted in the reason rather than guessed between"

var checkRubrics = map[string]map[model.Status]string{
	idPinned: {
		model.StatusVerifiedPass: "every include GitLab resolved that carries a ref or version — `project:` " +
			"(reported by the lint API as type \"file\", judged on extra.ref as written), `component:` " +
			"(judged on the version after the `@`) and `remote:` (judged on whether its URL path addresses a " +
			"specific commit) — is pinned to a full 40-character SHA; or there was no such include at all. " +
			"`local:` and `template:` includes are excluded from the judgment entirely: the first is already " +
			"fixed by this repository's own commit, and the second has no pinning mechanism to satisfy",
		model.StatusPartial: "every include this build recognizes is pinned, but the lint response contained " +
			"at least one include of a type this build does not classify — its pinning was not evaluated, so " +
			"a clean result over the rest is not a clean result over everything",
		model.StatusVerifiedFail: "at least one resolved include naming external CI configuration is not " +
			"pinned to a full 40-character commit SHA — a branch or tag ref, an omitted `ref:` (which the " +
			"lint API reports as \"HEAD\", following the target project's default branch), a catalog version " +
			"on a component, or a `remote:` URL that does not address a specific commit",
		model.StatusNotCheckable: sharedCIConfigNotCheckableRubric,
	},
	idTokenPermissions: {
		model.StatusVerifiedPass: "GET /projects/{id}/job_token_scope reported inbound_enabled=true — only " +
			"allowlisted projects and groups may use a CI_JOB_TOKEN against this project. This is GitLab's " +
			"least-privilege control for the job token and is NOT an equivalent of GitHub's per-workflow " +
			"permissions block: it governs which other projects reach INTO this one, and GitLab has no " +
			"keyword that scopes down what this project's own job token may do. ⚠ On GitLab.com this pass " +
			"is the INSTANCE's doing, not the producer's: turning the setting off there is refused outright " +
			"(verified live — PATCH answered 400 \"Job token scope cannot be disabled for this project " +
			"because it is enforced for the instance\"), so every GitLab.com project passes. The check " +
			"discriminates only on a self-managed instance whose administrator has not enforced it",
		model.StatusVerifiedFail: "inbound_enabled=false — docs.gitlab.com: \"If disabled, all projects have " +
			"access.\" A CI job in any project on the instance can use its job token against this project. " +
			"Reachable only on a self-managed instance; see the verified-pass entry for why GitLab.com " +
			"cannot produce it",
		model.StatusNotCheckable: "GET /projects/{id}/job_token_scope could not be read (a 403 here commonly " +
			"means the token lacks the Maintainer role GitLab requires for it). The allowlist member counts " +
			"are context facts only and are read through separate endpoints whose failure is tolerated — " +
			"they never cause this status",
	},
	idPRTarget: {
		model.StatusVerifiedPass: "ci_allow_fork_pipelines_to_run_in_parent_project is false, so a fork's " +
			"merge request pipeline always runs in the fork with the fork's own CI/CD variables and runners; " +
			"or it is true but the project is not public, so forking it already requires granted access and " +
			"the untrusted outside contributor this check is about does not arise",
		model.StatusPartial: "the project is public AND permits a fork's merge request pipeline to run in " +
			"this project's context, with this project's CI/CD variables, settings and runners. This check " +
			"has no verified-fail outcome, by design: GitLab requires a parent-project member with at least " +
			"the Developer role to start such a pipeline deliberately, after accepting a warning, so this is " +
			"an exposure to review rather than the automatic exploit path GitHub's pull_request_target opens",
		model.StatusNotCheckable: "the project could not be read; or it was read but carried no " +
			"ci_allow_fork_pipelines_to_run_in_parent_project field at all, which GitLab omits for a caller " +
			"below the Maintainer role — an absent field is not the setting being off, and is never reported " +
			"as a pass",
	},
	idOIDC: {
		model.StatusVerifiedPass: "at least one entry in the merged CI configuration declares an `id_tokens:` " +
			"block (a job, or the `default:` section jobs inherit from), and no project-level CI/CD variable " +
			"holds one of the exact names a cloud SDK reads a long-lived credential from",
		model.StatusPartial: "`id_tokens:` is declared somewhere AND a long-lived cloud credential variable " +
			"is still stored — OIDC is in use for something, but a static credential remains available to " +
			"every job",
		model.StatusVerifiedFail: "a project-level CI/CD variable holds a long-lived cloud credential and " +
			"nothing in the merged CI configuration declares `id_tokens:` at all. The offending variable " +
			"NAMES are recorded in Facts, never the values",
		model.StatusNotCheckable: sharedCIConfigNotCheckableRubric + ". Also: the merged configuration was " +
			"empty or did not parse as YAML; or GET /projects/{id}/variables could not be read, so a stored " +
			"credential could be neither found nor ruled out; or — the ordinary case for a project that does " +
			"no cloud deployment — neither signal was present at all, which is not-checkable rather than a " +
			"pass, since \"no cloud deployment detected\" is not a security property. ⚠ This reads only the " +
			"project's OWN CI/CD variables: a credential inherited from a group- or instance-level variable " +
			"is invisible to it",
	},
	idSelfHosted: {
		model.StatusVerifiedPass: "no project- or group-registered runner is attached to the project, so " +
			"there is nothing self-managed for a fork to reach; or one or more are attached but " +
			"ci_allow_fork_pipelines_to_run_in_parent_project is false, so a fork's merge request pipeline " +
			"runs in the fork and never acquires them; or they are attached and fork pipelines are permitted " +
			"but the project is not public. ⚠ Instance-registered runners are never counted: on GitLab.com " +
			"they are GitLab's own hosted fleet, and nothing in the API distinguishes those from the " +
			"operator-run instance runners of a self-managed GitLab — so on a self-managed instance this " +
			"check understates",
		model.StatusPartial: "one or more project- or group-registered runners are attached to a public " +
			"project that permits fork merge request pipelines to run in its own context. Like its GitHub " +
			"twin this check has no verified-fail outcome: runner exposure is only ever capped at partial",
		model.StatusNotCheckable: "the project could not be read; or GET /projects/{id}/runners could not be " +
			"listed (a 403 here commonly means the token lacks the Maintainer or Auditor role GitLab " +
			"requires for it); or runners WERE found but the project carried no " +
			"ci_allow_fork_pipelines_to_run_in_parent_project field, which GitLab omits below the Maintainer " +
			"role — with runners present, that setting is what decides the answer, so its absence is not a pass",
	},
}

var checkEndpoints = map[string][]string{
	idPinned:           {"GET /projects/{id}/ci/lint"},
	idTokenPermissions: {"GET /projects/{id}/job_token_scope"},
	idPRTarget:         {"GET /projects/{id}"},
	idOIDC:             {"GET /projects/{id}/ci/lint", "GET /projects/{id}/variables"},
	idSelfHosted:       {"GET /projects/{id}", "GET /projects/{id}/runners"},
}

const fixtureRef = "internal/collect/gitlab/actionssecurity/actionssecurity_test.go"

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID: id, Platform: platform, Title: checkTitles[id], Collector: collectorID,
			TokenScope:  checkTokenScopes[id],
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			FixtureRef:  fixtureRef,
		})
	}
}

// Collector implements C08 actions-security for GitLab.
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

// Collect emits all five checks once per project in scope.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	var out []model.CheckResult
	for _, repo := range scope.Repos {
		out = append(out, c.collectRepo(ctx, scope.Org, repo)...)
	}
	return out, nil
}

// collectRepo gathers each check's own evidence and hands each check only
// the provenance of the calls its own Status actually depends on, rather
// than the whole repo's — see the segment closure below.
//
// A client is built fresh per repo, not once for the whole scope, avoiding
// the cross-repo Provenance() bleed a shared client produces (issue #14) —
// the same convention every other gitlab collector uses.
func (c *Collector) collectRepo(ctx context.Context, org, repo string) []model.CheckResult {
	client, err := c.newClient()
	if err != nil {
		return allNotCheckable(org, repo, fmt.Sprintf("could not build a GitLab client: %v", err), nil)
	}

	// segment returns the provenance entries recorded since the previous
	// call to it, so a check's Provenance lists the calls behind its own
	// Status and no others — the convention internal/collect/github/
	// actionssecurity established for the same reason. prevLen starts at 0
	// rather than len(client.Provenance()) because the client is fresh
	// here, so the first segment includes the first call's own entry.
	prevLen := 0
	segment := func() []model.Provenance {
		all := client.Provenance()
		seg := append([]model.Provenance{}, all[prevLen:]...)
		prevLen = len(all)
		return seg
	}

	id := projectID(org, repo)

	proj, projErr := fetchProject(ctx, client, id)
	projProv := segment()

	lint, lintErr := fetchCILint(ctx, client, id)
	lintProv := segment()

	scope, scopeErr := fetchJobTokenScope(ctx, client, id)
	allowlistProjects, allowlistGroups, allowlistKnown := fetchAllowlistCounts(ctx, client, id)
	scopeProv := segment()

	runners, runnersErr := fetchSelfManagedRunners(ctx, client, id)
	runnersProv := segment()

	vars, varsErr := fetchVariables(ctx, client, id)
	varsProv := segment()

	return []model.CheckResult{
		checkPinned(org, repo, lint, lintErr, lintProv),
		checkTokenPermissions(org, repo, scope, scopeErr, allowlistProjects, allowlistGroups, allowlistKnown, scopeProv),
		checkForkPipelinesInParent(org, repo, proj, projErr, projProv),
		checkOIDCvsSecrets(org, repo, lint, lintErr, vars, varsErr, concatProv(lintProv, varsProv)),
		checkSelfHosted(org, repo, proj, projErr, runners, runnersErr, concatProv(projProv, runnersProv)),
	}
}

// fetchAllowlistCounts reads the two job token allowlists purely as context
// facts for C08.actions.token-permissions. A failure is tolerated rather
// than fatal — the setting those lists qualify has already been read by
// then, and losing the qualifier is not a reason to stop reporting the
// setting. Same treatment the GitHub twin gives its own context fact.
//
// ⚠ The project allowlist always contains the project itself (confirmed
// live), so a count of 1 means "nothing else allowlisted", not "empty".
func fetchAllowlistCounts(ctx context.Context, client *gitlabcollect.Client, projID string) (projects, groups int, known bool) {
	type idOnly struct {
		ID int `json:"id"`
	}
	projectEntries, err := gitlabcollect.GetJSONPaged[idOnly](ctx, client, "/projects/"+projID+"/job_token_scope/allowlist", nil)
	if err != nil {
		return 0, 0, false
	}
	groupEntries, err := gitlabcollect.GetJSONPaged[idOnly](ctx, client, "/projects/"+projID+"/job_token_scope/groups_allowlist", nil)
	if err != nil {
		return 0, 0, false
	}
	return len(projectEntries), len(groupEntries), true
}

func allNotCheckable(org, repo, reason string, prov []model.Provenance) []model.CheckResult {
	out := make([]model.CheckResult, 0, len(checkIDs))
	for _, id := range checkIDs {
		out = append(out, notCheckable(id, org, repo, reason, prov, nil))
	}
	return out
}

func concatProv(segments ...[]model.Provenance) []model.Provenance {
	out := []model.Provenance{}
	for _, s := range segments {
		out = append(out, s...)
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
