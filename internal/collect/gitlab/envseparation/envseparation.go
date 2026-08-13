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
// A stored rule therefore reports PARTIAL, not verified-pass, and the
// rubric, reason and remediation are all worded to claim the stored
// configuration and nothing more. Don't "simplify" them back into language
// that asserts a deployment is gated, and don't restore the pass — see the
// next section for why neither is available.
//
// # Why a stored approval rule reports partial, not verified-pass
//
// Wording alone was the first fix (issue #12) and it was not enough. Status
// is what feeds TaskRollup/ClusterRollup in a signed evidence pack, and
// prose does not reach a rollup: a Free namespace, where the rule is
// confirmed not to fire, was emitting the identical verified-pass as a
// Premium/Ultimate one where it does (issue #16).
//
// The targeted fix would be to branch on the namespace's subscription tier
// and pass only where the enforcement mechanism exists. Measured live
// 2026-08-13, that tier is not readable by this collector at any privilege
// level it can assume:
//
//   - GET /namespaces/:id does carry a `plan` field, but it 404s for any
//     namespace the calling identity is not a direct MEMBER of — not 403,
//     not a redacted body. Confirmed with a broad `api`-scoped personal
//     token that owns its own namespace: gitlab-org, gitlab-com and
//     inkscape (all public, all readable through /groups/:id) each 404 by
//     path and by numeric ID.
//   - Membership of a PROJECT in that namespace does not count. A project
//     access token scoped read_api at Reporter 404s on its own project's
//     namespace, by path and by ID. So does the same token at Maintainer —
//     the role these two protection checks document — against both a Free
//     personal namespace and an Ultimate-trial group.
//   - GET /groups/:id is not an alternative route. It returns no `plan`,
//     `trial` or `trial_ends_on` field at all — not even for a group Owner
//     on a live Ultimate trial. Nor does the `namespace` sub-object of
//     GET /projects/:id.
//   - GET /namespaces (list) returns only namespaces the identity belongs
//     to, which for a project access token is the BOT's own namespace. That
//     one does carry a plan, and it read "free" for a bot whose project sits
//     in the Ultimate-trial group — a field that looks like the answer, is
//     trivially reachable, and describes the wrong namespace. Don't wire it.
//
// So this check cannot tell an entitled namespace from an unentitled one,
// and issue #16's own fallback applies: partial. That is precisely what
// partial is for — "the evidence is suggestive but not conclusive proof
// either way" (model.StatusPartial's doc) — and it matches
// C02.branch.required-reviews, which already declines to call a review
// requirement a pass when a named actor can bypass it.
//
// Two reasons not to reach instead for a conditional read that passes
// whenever the tier happens to be visible:
//
//   - It would make Status depend on WHO ran the scan rather than on the
//     posture being audited. The same project with the same config, scanned
//     by an owner's personal token and by a CI service account, would land
//     different statuses in two signed packs — and a pack's whole point is
//     to diff cleanly across runs of the same scan.
//   - Even a confirmed paid tier would buy only GitLab's DOCUMENTED
//     behaviour, and this package's own opening paragraph records that
//     documentation's tier badge being wrong about this exact API surface.
//     Issue #12 tested the negative on Free; nothing has tested the positive
//     on a paid namespace. Passing on the strength of a badge already caught
//     being wrong is not evidence.
//
// verified-fail is unaffected and stays decisive: no subscription tier makes
// an absent approval rule present.
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
// HTTP 404 from /groups/:path is NOT uniformly "no group exists" — GitLab is
// documented elsewhere in this tree (gitlabcollect.IsTierGated's own doc
// comment: "some Premium endpoints 403, some 404 to hide their existence")
// as inconsistent about which status code hides a group's existence from a
// token that can't see it. What's structurally provable, independent of
// that gap: GitLab does not allow subgroups under a personal
// namespace, so if the project's own namespace is nested ("a/b"), every
// ancestor path in the walk — including the top-level one — is provably a
// real group, and a 404 anywhere in that walk can only mean refused/hidden,
// never absent; it is disclosed as a blind spot the same as a 403. Only for
// a project directly in a single-segment namespace (the common
// personal-namespace case, where there is exactly one path to check) does a
// 404 stay genuinely ambiguous between "no group at all" and "a hidden
// top-level group" — and stays undisclosed there, rather than caveat the
// large majority of real fails on a distinction the API doesn't resolve.
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
		"the environment's deployment tier, satisfies this check too. Note that doing so moves this check " +
		"from verified-fail to partial, not to verified-pass: the rule is stored and readable on Free, but " +
		"verified live that it is NOT enforced at deploy time there — a real deployment against exactly " +
		"this configuration ran unblocked. GitLab documents deploy-time enforcement as a Premium/Ultimate " +
		"feature (not independently verified here on a paid namespace), and this check cannot read the " +
		"namespace's subscription tier to tell the two cases apart, so confirm your own tier before " +
		"relying on this as an operative gate.",
	idBranchPolicy: "No remediation applicable via this tool: GitLab has no per-environment branch-" +
		"restriction mechanism — restrict which branch/tag may deploy in the deploy job's own `rules:` in " +
		".gitlab-ci.yml instead, and document that control in the self-attestation questionnaire.",
}

// The qualifier "project-level" is load-bearing: a failed GROUP-level read
// deliberately does not produce not-checkable (see the package doc), so
// naming the list unqualified would describe a path that does not exist.
const sharedNotCheckableRubric = "the environments list, or the project-level protected-environments list, " +
	"couldn't be read (403/404/other API error), or the project has zero environments configured at all"

// existsNotCheckableRubric is deliberately NARROWER than the shared one: a
// failed protected-environments read does not reach this check, because it
// reads only the environments list and is answered before that call is made.
const existsNotCheckableRubric = "the environments list couldn't be read (403/404/other API error), or the " +
	"project has zero environments configured at all — a failed protected-environments read does NOT " +
	"reach this check, which is answered from the environments list alone"

const sharedPartialRubric = "one or more environments exist, but none match the production-like naming " +
	"heuristic (`prod`* prefix, case-insensitive) — a human reviewer should judge whether one of them is " +
	"actually production before this check can evaluate anything"

// sharedGroupBlindSpotRubric is appended to both protection checks' fail
// entries. A fail is still emitted when group-level config cannot be read,
// deliberately (see the package doc), so the rubric has to say that the fail
// can rest on project-level evidence alone — otherwise a reader would take
// every fail as having ruled out both routes.
const sharedGroupBlindSpotRubric = ". Group-level config is read from the project's namespace and every " +
	"ancestor group path; if any of those reads is refused the Reason names it and the fail rests on " +
	"project-level evidence alone — this includes both 403 (a paid-tier or permission gate) and, when the " +
	"project's namespace is nested (so every ancestor path is provably a real group), a 404, since GitLab " +
	"is not consistent about which status code hides a group's existence from a token that can't see it. " +
	"A 404 is disclosed as a refusal ONLY when the namespace is nested; for a project directly in a " +
	"single-segment namespace (the common personal-namespace case) a 404 there is genuinely ambiguous " +
	"between \"no group at all\" and \"a hidden top-level group,\" and stays silent rather than caveat the " +
	"large majority of real fails"

var checkRubrics = map[string]map[model.Status]string{
	idExists: {
		model.StatusVerifiedPass: "at least one environment's name matches the production-like heuristic " +
			"(`prod`* prefix, case-insensitive)",
		model.StatusPartial:      sharedPartialRubric,
		model.StatusNotCheckable: existsNotCheckableRubric,
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
		// No verified-pass entry, deliberately — this check cannot reach that
		// status at all (see the package doc). The shared rubric guard fails
		// in both directions, so documenting one here would be caught as a
		// false promise, and emitting one would be caught as undocumented.
		model.StatusPartial: "either of two states, both short of proof. (a) Every production-like " +
			"environment has an approval_rules entry with required_approvals >= 1, on its project-level " +
			"protected_environments entry or on a group-level protected environment covering its " +
			"deployment tier — the strongest result this check can produce, because that is the stored " +
			"configuration rather than a demonstrated gate: on a Free namespace GitLab accepts, returns " +
			"and even tracks the rule against a deployment, yet lets that deployment succeed with zero " +
			"approvals, and the namespace's subscription tier — which decides whether the rule is " +
			"enforced at all — is not readable at this check's token scope, so an entitled namespace " +
			"cannot be told apart from an unentitled one. (b) " + sharedPartialRubric,
		model.StatusVerifiedFail: "at least one production-like environment is covered by no " +
			"protected_environments entry at project or group level, or only by ones whose approval_rules " +
			"require no approvals" + sharedGroupBlindSpotRubric,
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

// The two protection checks need a strictly higher role than the Reporter the
// Environments API is happy with: GET /projects/:id/protected_environments
// returns 403 to a read_api token at Reporter and 200 at Maintainer, measured
// live 2026-08-13 (issue #17) with a Reporter/Maintainer project access token
// pair against the same project, gitlab.com/qloud-ltd-group/attestward-fixtures.
// The same pair reads GET /projects/:id/environments 200 at both roles, which
// is why exists keeps the lower scope. Documenting Reporter here bought an
// operator a token that silently degrades both checks to not-checkable rather
// than the answer the docs promise.
const protectedEnvTokenScope = "read_api (Maintainer or above on the project — " +
	"GET /projects/:id/protected_environments returns 403 at Reporter)"

// Only the two protection checks read group-level config, so only they carry
// the extra namespace requirement. Stating it on all four would tell a reader
// that branch-policy — which makes no API call at all — needs group
// visibility.
var checkTokenScopes = map[string]string{
	idExists: projectTokenScope,
	idProtectionRules: protectedEnvTokenScope + ", plus visibility of the project's namespace to read " +
		"group-level protected environments (without it the check still runs, on project-level config alone)",
	idRequiredReviewers: protectedEnvTokenScope + ", plus visibility of the project's namespace to read " +
		"group-level protected environments (without it the check still runs, on project-level config alone)",
	idBranchPolicy: "none — this check makes no API call of its own; GitLab has no per-environment " +
		"branch-restriction mechanism, so the result is a fixed fact rather than something read",
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
	// existsProv is captured here, before any further call, and is what
	// checkExists gets below — its own declared Endpoints is only GET
	// .../environments, and Provenance() is cumulative, so reusing the
	// later, wider `prov` (which grows to include protected_environments
	// and, when the group-level walk runs, every group path too) would
	// have this result cite API calls it isn't about — the same class of
	// evidence-integrity defect issue #14 fixed elsewhere in this package.
	existsProv := prov
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
		// exists is NOT swept into this failure. It reads only GET
		// .../environments, which succeeded above, and prodNames is already
		// in hand — its answer is computed, not unknown. Blanking it out
		// with its siblings would report not-checkable for the check whose
		// documented scope, Reporter, is exactly the scope that CANNOT read
		// protected environments (403; see checkTokenScopes), so the most
		// likely operator to hit this branch would lose the one check their
		// token does entitle them to (issue #17).
		return append(
			[]model.CheckResult{checkExists(org, repo, prodNames, existsProv)},
			protectionNotCheckable(org, repo,
				fmt.Sprintf("could not read protected environments: %v", err), prov)...)
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
		checkExists(org, repo, prodNames, existsProv),
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
// A 404 on a SINGLE-SEGMENT org is skipped silently — it's genuinely
// ambiguous there (a personal namespace with no group at all, vs. a
// top-level group hidden from this token the way client.go's own doc
// comment says GitLab inconsistently does: "some Premium endpoints 403,
// some 404 to hide their existence"). But when org itself is nested
// ("a/b"), GitLab does not allow subgroups under a personal namespace, so
// EVERY ancestor path in the walk — including the top-level one — is
// provably a real group; a 404 anywhere in that walk can then only mean
// refused/hidden, never absent, and must be disclosed the same as a 403.
// Getting this wrong isn't cosmetic: this MR's own rubric text tells a
// reader "no caveat means both routes were ruled out," so silently
// swallowing a disclosable 404 would make a false-fail read as complete
// when it isn't, in a tool whose output goes into a signed attestation.
// Anything else (403, 5xx, network) is always recorded as a blind spot;
// the walk always continues past a blocked path — a group being unreadable
// says nothing about whether its parent is.
func readGroupProtection(ctx context.Context, client *gitlabcollect.Client, org string) groupProtection {
	provablyGroup := strings.Contains(strings.Trim(org, "/"), "/")
	gp := groupProtection{byTier: map[string]protectedEnvironment{}}
	for _, path := range namespacePaths(org) {
		entries, err := gitlabcollect.GetJSONPaged[protectedEnvironment](ctx, client,
			"/groups/"+escapePath(path)+"/protected_environments", nil)
		if err != nil {
			if code, ok := gitlabcollect.StatusCodeOf(err); ok {
				if code == http.StatusNotFound && !provablyGroup {
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
	// ⚠ partial, NOT verified-pass, and deliberately conservative wording —
	// issues #12 (the wording) and #16 (the status). "requires at least one
	// approval" would assert a live gate, and on Free that assertion is
	// false: verified by a real pipeline deployment that succeeded with
	// pending_approval_count 0 against exactly this configuration. The
	// status has to carry that too, because Reason does not reach the
	// rollups a signed pack is read through, and the namespace's tier — the
	// one thing that would settle it — is unreadable at this check's token
	// scope. Both are argued in full in the package doc comment; don't
	// restore the pass without reading it. This applies equally to a result
	// reached via group-level config (issue #13): that route reads the
	// identical approval_rules shape at a different API level, so it carries
	// the identical unverified-enforcement gap.
	facts := map[string]any{"production_like_environments": prodNames}
	if len(viaGroup) > 0 {
		facts["group_required_reviewers"] = viaGroup
	}
	return model.CheckResult{
		CheckID: idRequiredReviewers, Title: checkTitles[idRequiredReviewers], Status: model.StatusPartial,
		Reason: fmt.Sprintf("every production-like environment has a stored approval rule requiring at least "+
			"one approval: %v%s. Reported partial rather than verified-pass: that is the recorded "+
			"configuration, not evidence the gate fires — verified live on a Free namespace that it does not "+
			"(a real pipeline deployment against exactly this configuration succeeded with "+
			"pending_approval_count 0); GitLab documents deploy-time enforcement of this rule as a "+
			"Premium/Ultimate feature, not verified here on a paid namespace, and this check's token scope "+
			"cannot read the namespace's subscription tier to tell an entitled namespace from an unentitled one",
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

// protectionNotCheckable is allNotCheckable minus exists, for the one state
// where exists is already answered and its siblings are not: the
// environments read succeeded and found a production-like environment, and
// only the protected-environments read failed. branch-policy still comes
// from branchPolicyResult, so its unconditional reason is never replaced by
// the caller's, exactly as in allNotCheckable.
func protectionNotCheckable(org, repo, reason string, prov []model.Provenance) []model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	out := make([]model.CheckResult, 0, 3)
	for _, id := range []string{idProtectionRules, idRequiredReviewers} {
		out = append(out, model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: reason,
			Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		})
	}
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
