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
// The approval rule is stored and readable on Free, but it is NOT enforced
// at deploy time there. Settled live 2026-08-13 (issue #12) on a Free
// namespace: a real .gitlab-ci.yml job with `environment: name: production`
// was pushed at a protected environment carrying an approval_rules entry
// with required_approvals 1. The job went pending → running → success and
// the deployment reached status "success" with pending_approval_count 0 and
// approvals []. Decisively, that deployment's own approval_summary listed
// the rule with deployment_approvals: [] — GitLab tracked the requirement
// against the deployment and then let it finish having satisfied none of
// it. So the earlier inconclusive Deployments-API probe was not an artifact
// of that endpoint; the gate simply does not fire on Free. There is also no
// alternative config form to try: POSTing the older required_approval_count
// is rejected outright (422, "deprecated and shouldn't be used"), so
// approval_rules — what this check reads — is the only mechanism there is.
//
// The check still reports verified-pass on the stored rule, because reading
// configuration state is what every check in this codebase does — C02
// repo-protection doesn't push a bad commit to prove a branch rule blocks
// it, either. But this is the one place we know config and enforcement come
// apart for an entire tier, so the rubric, reason and remediation are all
// worded to claim the stored configuration and nothing more. Don't
// "simplify" them back into language that asserts a deployment is gated.
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
//
// # Group-level protected environments
//
// GET /projects/:id/protected_environments returns PROJECT-level entries
// only. GitLab also protects environments at the GROUP level, and the two
// models do not address environments the same way: project-level entries are
// keyed by environment NAME, group-level entries by DEPLOYMENT TIER
// (production/staging/testing/development/other), because "a group may
// consist of many project environments that have unique names". So a project
// whose production environment is protected only at the group level has an
// empty project-level list, and reading that list alone reported it as
// unprotected — a false fail (issue #13).
//
// Both protection checks therefore consult group-level config too, and pass
// an environment protected by either. Verified live against
// gitlab.com/qloud-ltd-group (Ultimate trial, 2026-08-13); the recorded
// response is internal/collect/gitlab/gitlabfixture/testdata/
// group-protected-environments.json, decoded by this package's own struct in
// a test, and the run is written up in docs/gitlab-security-apis.md § 7.
//
// Two measured facts shape how this is read, both contrary to the obvious
// implementation:
//
//   - The API does NOT return inherited protection. A parent group's
//     protected environment applies to projects in its subgroups — GitLab's
//     docs say a subgroup "cannot override it" — but
//     GET /groups/<subgroup>/protected_environments returns [] while the
//     parent's entry is live. Querying only the project's own namespace would
//     therefore reproduce the same false fail one level down, so this walks
//     the namespace and every ancestor group path. That walk needs no
//     hierarchy discovery: scope.Org already IS the full namespace path, so
//     the ancestors are its path prefixes.
//   - A read failure must NOT become not-checkable, which is the opposite of
//     what this package does for the project-level list and of what
//     gitlabcollect.ErrTierGated's doctrine says in general. That doctrine
//     protects a check whose ONLY evidence is tier-gated. Here it is not:
//     project-level protected environments were verified working on Free
//     (above), so a fail remains entitled, actionable and correct on the
//     evidence at hand. Downgrading every unprotected project to
//     not-checkable because a Premium-only ALTERNATIVE route could not be
//     read would retire a working check for the majority Free audience. The
//     blind spot is disclosed in the Reason instead.
//
// One case is deliberately not disclosed: HTTP 404 from /groups/:path. A
// project in a personal namespace — the common Free case — has no group at
// all, and GitLab answers 404 there because group-level protection is
// structurally impossible, not because something was hidden. 403 is the
// status that means the group exists and a tier or permission gate refused
// the read, and that is what gets reported as a blind spot.
package envseparation

import (
	"context"
	"fmt"
	"net/http"
	"sort"
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
		"environment, restricting at least who may deploy to it (Allowed to Deploy). On Premium and above " +
		"this can instead be done once for the whole group at Group → Settings → CI/CD → Protected " +
		"environments, which protects by deployment tier rather than by environment name.",
	idRequiredReviewers: "Project → Settings → CI/CD → Protected environments → protect the production-like " +
		"environment and add an Approval rule requiring at least one approval. On Premium and above the " +
		"equivalent group-level rule, added at Group → Settings → CI/CD → Protected environments against " +
		"the environment's deployment tier, satisfies this check too. Note that the rule is stored and " +
		"readable on Free, but verified live that it is NOT enforced at deploy time there — a real " +
		"deployment against exactly this configuration ran unblocked. GitLab documents deploy-time " +
		"enforcement of this rule as a Premium/Ultimate feature (not independently verified here on a paid " +
		"namespace) — confirm the namespace's tier before relying on this as an operative gate.",
	idBranchPolicy: "No remediation applicable via this tool: GitLab has no per-environment branch-" +
		"restriction mechanism — restrict which branch/tag may deploy in the deploy job's own `rules:` in " +
		".gitlab-ci.yml instead, and document that control in the self-attestation questionnaire.",
}

// The qualifier "project-level" is load-bearing: a failed GROUP-level read
// deliberately does not produce not-checkable (see the package doc), so
// naming the list unqualified would describe a path that does not exist.
const sharedNotCheckableRubric = "the environments list, or the project-level protected-environments list, " +
	"couldn't be read (403/404/other API error), or the project has zero environments configured at all"

const sharedPartialRubric = "one or more environments exist, but none match the production-like naming " +
	"heuristic (`prod`* prefix, case-insensitive) — a human reviewer should judge whether one of them is " +
	"actually production before this check can evaluate anything"

// sharedGroupBlindSpotRubric is appended to both protection checks' fail
// entries. A fail is still emitted when group-level config cannot be read,
// deliberately (see the package doc), so the rubric has to say that the fail
// can rest on project-level evidence alone — otherwise a reader would take
// every fail as having ruled out both routes.
const sharedGroupBlindSpotRubric = ". Group-level config is read from the project's namespace and every " +
	"ancestor group path; if any of those reads is refused (403 — a paid-tier or permission gate) the " +
	"Reason names it and the fail rests on project-level evidence alone. A 404 is not a refusal: it means " +
	"no group exists at that path, as for a project in a personal namespace"

var checkRubrics = map[string]map[model.Status]string{
	idExists: {
		model.StatusVerifiedPass: "at least one environment's name matches the production-like heuristic " +
			"(`prod`* prefix, case-insensitive)",
		model.StatusPartial:      sharedPartialRubric,
		model.StatusNotCheckable: sharedNotCheckableRubric,
	},
	idProtectionRules: {
		model.StatusVerifiedPass: "every production-like environment is protected, by either of the two " +
			"routes GitLab offers: a matching project-level protected_environments entry (any protection at " +
			"all — GitLab requires at least deploy_access_levels to protect one, so a matching entry's mere " +
			"existence is the \"any type\" signal, mirroring the GitHub twin's identical framing), or a " +
			"group-level protected environment whose deployment tier matches the environment's own tier",
		model.StatusVerifiedFail: "at least one production-like environment has neither a matching " +
			"project-level protected_environments entry nor a group-level protected environment covering " +
			"its deployment tier" + sharedGroupBlindSpotRubric,
		model.StatusPartial:      sharedPartialRubric,
		model.StatusNotCheckable: sharedNotCheckableRubric,
	},
	idRequiredReviewers: {
		model.StatusVerifiedPass: "every production-like environment has an approval_rules entry with " +
			"required_approvals >= 1, on either its project-level protected_environments entry or a " +
			"group-level protected environment covering its deployment tier. That is the stored " +
			"configuration, not a demonstrated gate: on a Free namespace GitLab accepts, returns and even " +
			"tracks the rule against a deployment, yet lets that deployment succeed with zero approvals",
		model.StatusVerifiedFail: "at least one production-like environment is covered by no " +
			"protected_environments entry at project or group level, or only by ones whose approval_rules " +
			"require no approvals" + sharedGroupBlindSpotRubric,
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

const projectTokenScope = "read_api (Reporter or above on the project)"

// Only the two protection checks read group-level config, so only they carry
// the extra namespace requirement. Stating it on all four would tell a reader
// that branch-policy — which makes no API call at all — needs group
// visibility.
var checkTokenScopes = map[string]string{
	idExists: projectTokenScope,
	idProtectionRules: projectTokenScope + ", plus visibility of the project's namespace to read " +
		"group-level protected environments (without it the check still runs, on project-level config alone)",
	idRequiredReviewers: projectTokenScope + ", plus visibility of the project's namespace to read " +
		"group-level protected environments (without it the check still runs, on project-level config alone)",
	idBranchPolicy: projectTokenScope,
}

var protectionEndpoints = []string{
	"GET /projects/{id}/environments",
	"GET /projects/{id}/protected_environments",
	"GET /groups/{namespace}/protected_environments",
}

var checkEndpoints = map[string][]string{
	idExists:            {"GET /projects/{id}/environments"},
	idProtectionRules:   protectionEndpoints,
	idRequiredReviewers: protectionEndpoints,
	idBranchPolicy:      nil,
}

const fixtureRef = "internal/collect/gitlab/envseparation/envseparation_test.go"

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID: id, Platform: platform, Title: checkTitles[id], Collector: collectorID,
			TokenScope:  checkTokenScopes[id],
			Remediation: checkRemediations[id], Rubric: checkRubrics[id],
			Endpoints: checkEndpoints[id], FixtureRef: fixtureRef,
		})
	}
}

// environment is the subset of GitLab's Environments response this needs.
//
// Tier is the environment's deployment tier — production, staging, testing,
// development or other. It is what group-level protected environments are
// keyed by, and it is NOT the name: GitLab derives it from the name when it
// can (an environment called "production" comes back tier "production") but
// it is settable independently, so "gprd" with tier "production" is both
// normal and, by design, exactly the case group-level protection exists to
// cover. Both were created live to confirm it (2026-08-13).
type environment struct {
	Name string `json:"name"`
	Tier string `json:"tier"`
}

// protectedEnvironment is the subset of GitLab's Protected Environments
// response this needs, verified 2026-08-11 against a live protected
// environment created (and deleted) on this project.
//
// It decodes group-level entries too — their bodies are the same shape,
// confirmed against a live group-level entry (2026-08-13). The one thing
// that changes is what Name means: an environment name at project level, a
// deployment tier at group level. Callers must not mix the two up, which is
// why groupProtection below keys its map by tier explicitly.
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
	var all []model.CheckResult
	for _, repo := range scope.Repos {
		all = append(all, c.collectRepo(ctx, scope.Org, repo)...)
	}
	return all, nil
}

// collectRepo builds its own client per repo rather than sharing one across
// scope.Repos. Client.Provenance() is cumulative over every call ever made
// through that client instance, so a shared one attributed an earlier repo's
// API calls to a later repo's CheckResult.Provenance — evidence citing a
// project the result is not about (issue #14). Same convention as
// internal/collect/gitlab/repoprotection and .../secretshygiene.
func (c *Collector) collectRepo(ctx context.Context, org, repo string) []model.CheckResult {
	client, err := c.newClient()
	if err != nil {
		return allNotCheckable(org, repo, fmt.Sprintf("could not build a GitLab client: %v", err), nil)
	}

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
	prodEnvs := prodLikeEnvs(envs)
	if len(prodEnvs) == 0 {
		return allPartialNoProdEnv(org, repo, allNames, prov)
	}
	prodNames := envNames(prodEnvs)

	protected, err := gitlabcollect.GetJSONPaged[protectedEnvironment](ctx, client, "/projects/"+id+"/protected_environments", nil)
	prov = client.Provenance()
	if err != nil {
		return allNotCheckable(org, repo, fmt.Sprintf("could not read protected environments: %v", err), prov)
	}
	byName := map[string]protectedEnvironment{}
	for _, pe := range protected {
		byName[pe.Name] = pe
	}

	// Only projects already heading for a fail pay for the group-level walk.
	// If project-level config alone answers both checks with a pass, no
	// group-level entry could change that answer — group and project rules
	// compose (GitLab: "the user must be allowed in both rulesets"), so
	// group-level config can only ever turn a fail into a pass here, never
	// the reverse.
	var group groupProtection
	if needsGroupLookup(prodEnvs, byName) {
		group = readGroupProtection(ctx, client, org)
		prov = client.Provenance()
	}

	return []model.CheckResult{
		checkExists(org, repo, prodNames, prov),
		checkProtectionRules(org, repo, prodEnvs, byName, group, prov),
		checkRequiredReviewers(org, repo, prodEnvs, byName, group, prov),
		branchPolicyResult(org, repo),
	}
}

// groupProtection is what the group-level walk found: the protected
// deployment tiers it could read, and the group paths it could not.
//
// blocked is not cosmetic. It is the difference between "we looked at both
// routes and neither protects this" and "we looked at one route" — and both
// of those emit verified-fail, so without it the two are indistinguishable
// to whoever reads the pack.
type groupProtection struct {
	byTier  map[string]protectedEnvironment
	blocked []string
}

// needsGroupLookup reports whether group-level config could still change an
// answer — i.e. whether either protection check would fail on project-level
// evidence alone. It covers both checks' fail conditions, including the case
// where an environment IS protected at project level but that entry requires
// no approvals, which fails required-reviewers only.
func needsGroupLookup(prodEnvs []environment, byName map[string]protectedEnvironment) bool {
	for _, e := range prodEnvs {
		pe, ok := byName[e.Name]
		if !ok || !hasRequiredApproval(pe) {
			return true
		}
	}
	return false
}

// readGroupProtection walks the project's namespace and every ancestor group
// path, collecting group-level protected environments by deployment tier.
//
// The walk exists because the API does not return inherited protection — see
// the package doc. It needs no hierarchy discovery call: org is already the
// full namespace path, so "a/b/c" yields "a/b/c", "a/b", "a".
//
// A 404 is skipped silently (no group at that path — the personal-namespace
// case), anything else is recorded as a blind spot and the walk continues: a
// group being unreadable says nothing about whether its parent is.
func readGroupProtection(ctx context.Context, client *gitlabcollect.Client, org string) groupProtection {
	gp := groupProtection{byTier: map[string]protectedEnvironment{}}
	for _, path := range namespacePaths(org) {
		entries, err := gitlabcollect.GetJSONPaged[protectedEnvironment](ctx, client,
			"/groups/"+escapePath(path)+"/protected_environments", nil)
		if err != nil {
			if code, ok := gitlabcollect.StatusCodeOf(err); ok {
				if code == http.StatusNotFound {
					continue
				}
				gp.blocked = append(gp.blocked, fmt.Sprintf("%s: HTTP %d", path, code))
				continue
			}
			gp.blocked = append(gp.blocked, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		for _, e := range entries {
			// An entry naming no tier protects no tier. Dropping it here
			// keeps every key in byTier a real deployment tier, which is what
			// lets the lookup be a plain map read: an environment reporting
			// no tier finds nothing rather than colliding with this entry and
			// passing on it. A false PASS is the one direction this check
			// must never fail in.
			if e.Name == "" {
				continue
			}
			// Deepest group wins unless a shallower one requires approvals:
			// the rulesets compose, so an approval demanded anywhere up the
			// chain is demanded, and keeping the entry that carries it is
			// what lets required-reviewers see it.
			if existing, ok := gp.byTier[e.Name]; ok && hasRequiredApproval(existing) {
				continue
			}
			gp.byTier[e.Name] = e
		}
	}
	return gp
}

// namespacePaths returns org and each of its ancestor group paths, deepest
// first: "a/b/c" yields "a/b/c", "a/b", "a".
func namespacePaths(org string) []string {
	trimmed := strings.Trim(org, "/")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "/")
	out := make([]string, 0, len(parts))
	for i := len(parts); i > 0; i-- {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}

// groupEntryFor returns the group-level entry covering e, if any. Group-level
// protection is keyed by deployment tier and nothing else, so an environment
// reporting no tier — an older self-managed instance, say — matches nothing:
// readGroupProtection keeps empty tiers out of the map, which makes an empty
// tier a non-answer here rather than a wildcard.
func groupEntryFor(e environment, gp groupProtection) (protectedEnvironment, bool) {
	pe, ok := gp.byTier[e.Tier]
	return pe, ok
}

// blindSpotSuffix renders the disclosure appended to a fail Reason when some
// group path could not be read, so a fail never silently claims to have
// ruled out a route it never saw.
func (gp groupProtection) blindSpotSuffix() string {
	if len(gp.blocked) == 0 {
		return ""
	}
	return fmt.Sprintf("; group-level protected environments could not be read (%s), so protection "+
		"configured there is not visible to this check", strings.Join(gp.blocked, ", "))
}

// tiersOf renders the distinct deployment tiers of envs for a Reason string.
func tiersOf(envs []environment) string {
	seen := map[string]bool{}
	var out []string
	for _, e := range envs {
		tier := e.Tier
		if tier == "" {
			tier = "(none reported)"
		}
		if !seen[tier] {
			seen[tier] = true
			out = append(out, tier)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func checkExists(org, repo string, prodNames []string, prov []model.Provenance) model.CheckResult {
	return model.CheckResult{
		CheckID: idExists, Title: checkTitles[idExists], Status: model.StatusVerifiedPass,
		Reason: fmt.Sprintf("production-like environment(s) found: %v", prodNames),
		Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		Facts: map[string]any{"production_like_environments": prodNames},
	}
}

func checkProtectionRules(org, repo string, prodEnvs []environment, byName map[string]protectedEnvironment,
	gp groupProtection, prov []model.Provenance) model.CheckResult {
	var unprotected, viaGroup []string
	var unprotectedEnvs []environment
	for _, e := range prodEnvs {
		if _, ok := byName[e.Name]; ok {
			continue
		}
		if _, ok := groupEntryFor(e, gp); ok {
			viaGroup = append(viaGroup, e.Name)
			continue
		}
		unprotected = append(unprotected, e.Name)
		unprotectedEnvs = append(unprotectedEnvs, e)
	}

	prodNames := envNames(prodEnvs)
	if len(unprotected) > 0 {
		facts := map[string]any{"unprotected_environments": unprotected}
		if len(gp.blocked) > 0 {
			facts["group_level_unreadable"] = gp.blocked
		}
		return model.CheckResult{
			CheckID: idProtectionRules, Title: checkTitles[idProtectionRules], Status: model.StatusVerifiedFail,
			Reason: fmt.Sprintf("no project-level protected_environments entry for: %v, and no group-level "+
				"protected environment covering deployment tier(s): %s%s",
				unprotected, tiersOf(unprotectedEnvs), gp.blindSpotSuffix()),
			Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
			Facts: facts,
		}
	}

	facts := map[string]any{"production_like_environments": prodNames}
	if len(viaGroup) > 0 {
		facts["group_protected_environments"] = viaGroup
	}
	return model.CheckResult{
		CheckID: idProtectionRules, Title: checkTitles[idProtectionRules], Status: model.StatusVerifiedPass,
		Reason: fmt.Sprintf("every production-like environment is protected: %v%s",
			prodNames, viaGroupSuffix(viaGroup)),
		Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		Facts: facts,
	}
}

func checkRequiredReviewers(org, repo string, prodEnvs []environment, byName map[string]protectedEnvironment,
	gp groupProtection, prov []model.Provenance) model.CheckResult {
	var missing, viaGroup []string
	var missingEnvs []environment
	for _, e := range prodEnvs {
		if pe, ok := byName[e.Name]; ok && hasRequiredApproval(pe) {
			continue
		}
		if pe, ok := groupEntryFor(e, gp); ok && hasRequiredApproval(pe) {
			viaGroup = append(viaGroup, e.Name)
			continue
		}
		missing = append(missing, e.Name)
		missingEnvs = append(missingEnvs, e)
	}

	prodNames := envNames(prodEnvs)
	if len(missing) > 0 {
		facts := map[string]any{"missing_required_reviewers": missing}
		if len(gp.blocked) > 0 {
			facts["group_level_unreadable"] = gp.blocked
		}
		return model.CheckResult{
			CheckID: idRequiredReviewers, Title: checkTitles[idRequiredReviewers], Status: model.StatusVerifiedFail,
			Reason: fmt.Sprintf("no approval rule requiring at least one approval, at project level or on a "+
				"group-level protected environment covering deployment tier(s) %s, for: %v%s",
				tiersOf(missingEnvs), missing, gp.blindSpotSuffix()),
			Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
			Facts: facts,
		}
	}
	// ⚠ Deliberately conservative wording (issue #12). "requires at least one
	// approval" would assert a live gate, and on Free that assertion is
	// false — verified by a real pipeline deployment that succeeded with
	// pending_approval_count 0 against exactly this configuration (see the
	// package doc comment). State the stored rule; let the reader's tier
	// decide whether it fires. This applies equally to a pass reached via
	// group-level config (issue #13): the same unverified-enforcement gap
	// exists for that route too, since it's read from the identical
	// approval_rules shape at a different API level.
	facts := map[string]any{"production_like_environments": prodNames}
	if len(viaGroup) > 0 {
		facts["group_required_reviewers"] = viaGroup
	}
	return model.CheckResult{
		CheckID: idRequiredReviewers, Title: checkTitles[idRequiredReviewers], Status: model.StatusVerifiedPass,
		Reason: fmt.Sprintf("every production-like environment has a stored approval rule requiring at least "+
			"one approval: %v%s. That is the recorded configuration, not evidence the gate fires — verified "+
			"live on a Free namespace that it does not (a real pipeline deployment against exactly this "+
			"configuration succeeded with pending_approval_count 0); GitLab documents deploy-time enforcement "+
			"of this rule as a Premium/Ultimate feature, not verified here on a paid namespace",
			prodNames, viaGroupSuffix(viaGroup)),
		Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		Facts: facts,
	}
}

// viaGroupSuffix names the environments that passed on group-level config,
// so a pass says which of the two routes it came from rather than leaving
// the reader to guess from an empty project-level list.
func viaGroupSuffix(viaGroup []string) string {
	if len(viaGroup) == 0 {
		return ""
	}
	return fmt.Sprintf(" (%v via group-level protection of the environment's deployment tier)", viaGroup)
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

func prodLikeEnvs(envs []environment) []environment {
	var out []environment
	for _, e := range envs {
		if prodLikeName(e.Name) {
			out = append(out, e)
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
