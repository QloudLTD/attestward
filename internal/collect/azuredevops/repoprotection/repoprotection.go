// Package repoprotection implements C02 repo-protection for Azure DevOps —
// the ADO counterpart to internal/collect/github/repoprotection, and issue
// #34's flagship "branch policies ≈ branch protection" mapping.
//
// Unlike the GitHub twin, which merges two overlapping regimes (legacy
// branch protection and rulesets) per repo, ADO exposes exactly one
// surface for all six checks: GET .../{project}/_apis/policy/configurations
// (Policy Configurations - List, scope vso.code) returns every policy
// configuration in the whole PROJECT in one call, which this collector
// filters client-side to the ones scoped (via settings.scope[]) to each
// in-scope repo's default branch — either a project-wide entry
// (repositoryId==null), a repo-specific entry (repositoryId equal), an
// exact refName match, a prefix match (matchKind=="Prefix"), or a
// default-branch match (matchKind=="DefaultBranch", refName left null —
// the shape Azure DevOps's project-level "Protect the default branch of
// each repository" cross-repository policy emits; all three matchKind
// values verified against Microsoft's own documentation — see
// refNameMatches' own doc comment). A repo's default branch itself comes
// from a second
// project-scoped call, GET .../{project}/_apis/git/repositories
// (Repositories - List, also vso.code) — both calls happen exactly once
// per Collect(), not once per repo, and their provenance is shared across
// every in-scope repo's results: that's an accurate reflection of what
// backs each repo's checks, not an artifact of a shared client (contrast
// with the GitHub twin, which genuinely issues distinct per-repo API calls
// and so gives each repo its own Client for provenance isolation).
//
// Only two of the policy types Policy Configurations - List can return are
// tracked at all: Minimum approval count (fa4e907d-c16b-4a4c-9dfa-4906e5d171dd)
// and Build (0609b952-1397-4640-95ec-e00a01b2c241) — both type IDs verified
// against Microsoft's own reference sample response. C02.branch.protection-exists
// only counts a policy of one of these two types; a comment-requirement or
// work-item-linking policy existing doesn't count as "protection" for this
// check's purposes, matching issue #150's literal "tracked-type" wording.
//
// Three checks — C02.branch.admin-enforced, C02.branch.force-push-blocked,
// C02.branch.deletion-blocked — are not-checkable always, with no API call
// of their own: none of these controls are policy-configuration data at
// all in Azure DevOps. They're Git repository security-namespace
// permissions (an ACL, read via _apis/accesscontrollists, out of scope for
// v0.2 per issue #34's non-goals): "Bypass policies when completing pull
// requests" and "Bypass policies when pushing" govern admin-enforced, and
// "Force push (rewrite history, delete branches and tags)" governs both
// force-push-blocked and deletion-blocked — verified against Microsoft's
// own Git branch-permissions documentation, which is explicit that this
// single permission is also "required to delete a branch": Azure DevOps
// has no permission distinct from force-push for branch deletion at all,
// unlike GitHub's legacy protection (allow_force_pushes/allow_deletions
// are two independent fields there). These three checks' not-checkable
// reasons name the exact permission(s) a future ACL-reading story would
// need to read, the paper trail issue #150 asks for.
package repoprotection

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/model"
)

// collectorID must equal the GitHub twin's Collector string exactly — the
// registry (internal/collect/registry.go's Register) panics if two
// platforms register the same check ID under different Collector strings,
// and internal/checksref groups a check's per-platform subsections by this
// same identity.
const collectorID = "C02.repo-protection"

const (
	idProtectionExists     = "C02.branch.protection-exists"
	idRequiredReviews      = "C02.branch.required-reviews"
	idRequiredStatusChecks = "C02.branch.required-status-checks"
	idForcePushBlocked     = "C02.branch.force-push-blocked"
	idDeletionBlocked      = "C02.branch.deletion-blocked"
	idAdminEnforced        = "C02.branch.admin-enforced"
)

// checkIDs is checkTitles' keys in a fixed order, so init()'s registration
// order is deterministic — mirrors the GitHub twin's identical rationale.
var checkIDs = []string{
	idProtectionExists,
	idRequiredReviews,
	idRequiredStatusChecks,
	idForcePushBlocked,
	idDeletionBlocked,
	idAdminEnforced,
}

// policyDrivenCheckIDs is the subset of checkIDs whose status actually
// derives from policy-configuration data — used by allNotCheckablePolicyDriven
// when the upstream repositories/policy-configurations reads fail, so the
// three permanently-fixed ACL checks (which never depend on that data) are
// never mistakenly re-emitted or overwritten by that path.
var policyDrivenCheckIDs = []string{idProtectionExists, idRequiredReviews, idRequiredStatusChecks}

var checkTitles = map[string]string{
	idProtectionExists:     "Default branch has an enabled branch policy",
	idRequiredReviews:      "Default branch requires at least one approving review before merge",
	idRequiredStatusChecks: "Default branch requires build validation before merge",
	idForcePushBlocked:     "Default branch blocks force pushes",
	idDeletionBlocked:      "Default branch blocks branch deletion",
	idAdminEnforced:        "Default branch protections apply to admins (no unconditional bypass permission)",
}

var checkRemediations = map[string]string{
	idProtectionExists: "Project Settings -> Repositories -> [repo] -> Policies (or Repos -> Branches -> " +
		"... -> Branch policies) -> add a branch policy (minimum number of reviewers and/or build validation) " +
		"scoped to the default branch.",
	idRequiredReviews: "In that branch policy blade, enable \"Require a minimum number of reviewers\", set " +
		"it to at least 1, set the policy to Required (blocking, not Optional), and leave \"Allow requesters " +
		"to approve their own changes\" (creatorVoteCounts) unchecked.",
	idRequiredStatusChecks: "In that branch policy blade, add a \"Build validation\" policy pointing at the " +
		"build pipeline that must pass, and set it to Required (blocking), not Optional.",
	idForcePushBlocked: "Project Settings -> Repositories -> [repo] -> Security (or the branch's own Security " +
		"tab) -> for every group that shouldn't have it, set \"Force push (rewrite history, delete branches " +
		"and tags)\" to Deny (not just unset/inherited).",
	idDeletionBlocked: "Azure DevOps has no permission distinct from \"Force push (rewrite history, delete " +
		"branches and tags)\" for deleting a branch specifically — the same remediation as " +
		"C02.branch.force-push-blocked (set that permission to Deny) closes this gap too.",
	idAdminEnforced: "Project Settings -> Repositories -> [repo] -> Security -> for every group/user that " +
		"shouldn't be exempt (including admins), set both \"Bypass policies when completing pull requests\" " +
		"and \"Bypass policies when pushing\" to Deny (not just unset/inherited) at the repository or branch level.",
}

// sharedNotCheckableRubric is the not-checkable explanation shared by the
// three policy-driven checks — all three bottom out at the same two
// upstream reads (repositories, policy configurations), mirroring the
// GitHub twin's identical sharedNotCheckableRubric pattern.
const sharedNotCheckableRubric = "the project's repositories couldn't be read (403/404/other API error), " +
	"the named repository wasn't found in the project, the repository has no default branch (an empty " +
	"repository), or the project's policy configurations couldn't be read (403/404/other API error)"

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce. idProtectionExists is binary (pass/fail) plus
// not-checkable; idRequiredReviews and idRequiredStatusChecks can also
// produce partial; the three ACL-governed checks can only ever produce
// not-checkable — see the package doc comment for why.
var checkRubrics = map[string]map[model.Status]string{
	idProtectionExists: {
		model.StatusVerifiedPass: "at least one enabled, non-deleted policy configuration of a tracked type " +
			"(Minimum approval count, fa4e907d-c16b-4a4c-9dfa-4906e5d171dd; or Build, " +
			"0609b952-1397-4640-95ec-e00a01b2c241) is scoped, via settings.scope[], to this repo's default " +
			"branch — a project-wide entry (repositoryId==null) or a repo-specific entry (repositoryId equal) " +
			"whose refName matches exactly, as a prefix, or via matchKind==\"DefaultBranch\" (which always " +
			"matches a repo's own default branch by definition — the shape Azure DevOps's project-level " +
			"\"Protect the default branch of each repository\" cross-repository policy emits)",
		model.StatusVerifiedFail: "no enabled, non-deleted policy configuration of a tracked type is scoped to this repo's default branch",
		model.StatusNotCheckable: sharedNotCheckableRubric,
	},
	idRequiredReviews: {
		model.StatusVerifiedPass: "at least one matching, enabled, non-deleted Minimum approval count policy " +
			"(fa4e907d-c16b-4a4c-9dfa-4906e5d171dd) scoped to the default branch individually has " +
			"minimumApproverCount >= 1, isBlocking==true, and creatorVoteCounts==false — Azure DevOps enforces " +
			"every matching policy simultaneously, so one policy meeting the full bar is a genuine, " +
			"unbypassable requirement even if a separate, weaker matching policy also applies (the same " +
			"either-regime-provides-it convention the GitHub twin's effective-protection merge uses)",
		model.StatusPartial: "at least one matching Minimum approval count policy requires >=1 approver, but " +
			"no single matching policy is both blocking and free of creatorVoteCounts: either every blocking " +
			"matching policy has creatorVoteCounts==true (the PR author's own vote counts toward its own " +
			"requirement), or no matching policy is blocking at all (isBlocking==false everywhere, so the " +
			"requirement can be overridden at PR completion) — never both framed as \"overridable\" when a " +
			"blocking policy exists, since a blocking policy's own requirement can't be overridden regardless " +
			"of a weaker sibling",
		model.StatusVerifiedFail: "no enabled, non-deleted Minimum approval count policy scoped to the default branch requires >=1 approver",
		model.StatusNotCheckable: sharedNotCheckableRubric,
	},
	idRequiredStatusChecks: {
		model.StatusVerifiedPass: "at least one matching, enabled, non-deleted Build policy " +
			"(0609b952-1397-4640-95ec-e00a01b2c241) scoped to the default branch is individually blocking " +
			"(isBlocking==true) — Azure DevOps enforces every matching policy simultaneously, so one blocking " +
			"policy is a genuine requirement even if a separate, non-blocking matching policy also applies",
		model.StatusPartial: "at least one matching Build policy is scoped to the default branch, but every " +
			"matching Build policy is non-blocking (isBlocking==false) — a failing or missing build does not " +
			"block merge for any of them",
		model.StatusVerifiedFail: "no enabled, non-deleted Build policy is scoped to the default branch",
		model.StatusNotCheckable: sharedNotCheckableRubric,
	},
	idForcePushBlocked: {
		model.StatusNotCheckable: "always — Azure DevOps controls force pushes via the \"Force push (rewrite " +
			"history, delete branches and tags)\" Git repository security permission (an ACL, not policy " +
			"configuration data), out of scope for v0.2 (issue #34's non-goals); a future ACL-reading story " +
			"would read this permission bit directly",
	},
	idDeletionBlocked: {
		model.StatusNotCheckable: "always — Azure DevOps has no permission distinct from \"Force push " +
			"(rewrite history, delete branches and tags)\" for deleting a branch (confirmed against " +
			"Microsoft's own Git branch-permissions documentation, which states this one permission is also " +
			"required to delete a branch) — an ACL, not policy configuration data, out of scope for v0.2 " +
			"(issue #34's non-goals)",
	},
	idAdminEnforced: {
		model.StatusNotCheckable: "always — Azure DevOps' bypass model here is the \"Bypass policies when " +
			"completing pull requests\" and \"Bypass policies when pushing\" Git repository security " +
			"permissions (ACLs), not policy configuration data, out of scope for v0.2 (issue #34's non-goals); " +
			"a future ACL-reading story would read these permission bits directly",
	},
}

// sharedEndpoints backs all three policy-driven checks — see the package
// doc comment for why both calls are project-scoped, not per-repo, and
// happen exactly once per Collect() regardless of how many repos are in
// scope.
var sharedEndpoints = []string{
	"GET dev.azure.com/{org}/{project}/_apis/git/repositories",
	"GET dev.azure.com/{org}/{project}/_apis/policy/configurations",
}

// checkEndpoints is nil for the three ACL-governed checks: none of them
// make any API call of their own at all, so nothing backs their
// (permanently fixed) not-checkable status — see checkRubrics' own doc
// comment.
var checkEndpoints = map[string][]string{
	idProtectionExists:     sharedEndpoints,
	idRequiredReviews:      sharedEndpoints,
	idRequiredStatusChecks: sharedEndpoints,
	idForcePushBlocked:     nil,
	idDeletionBlocked:      nil,
	idAdminEnforced:        nil,
}

// checkTokenScopes documents all six checks even though three make no call
// at all (matching auditlogging's and orgsecurity's identical choice) — a
// reader digging into why a check is permanently not-checkable may still
// want to know what surface (if any) would need to exist for it to ever
// become verifiable.
var checkTokenScopes = map[string]string{
	idProtectionExists:     "vso.code (Repositories - List, Policy Configurations - List)",
	idRequiredReviews:      "vso.code (Repositories - List, Policy Configurations - List)",
	idRequiredStatusChecks: "vso.code (Repositories - List, Policy Configurations - List)",
	idForcePushBlocked: "vso.security_manage — Azure DevOps has no read-only PAT scope for security " +
		"permissions/ACLs at all (verified against Microsoft's own OAuth scopes reference: the Security " +
		"category has exactly one scope, and it's read+write+manage); reading this permission at all would " +
		"require a high-privilege scope in tension with PAT minimality, which is arguably the more honest " +
		"story than a missing read-only variant this tool simply chose not to use (see this check's Rubric)",
	idDeletionBlocked: "vso.security_manage — same scope, and the same no-read-only-variant story, as " +
		"C02.branch.force-push-blocked (see this check's Rubric)",
	idAdminEnforced: "vso.security_manage — same scope, and the same no-read-only-variant story, as " +
		"C02.branch.force-push-blocked (see this check's Rubric)",
}

const fixtureRef = "internal/collect/azuredevops/repoprotection/repoprotection_test.go"

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:          id,
			Platform:    "azuredevops",
			Title:       checkTitles[id],
			Collector:   collectorID,
			TokenScope:  checkTokenScopes[id],
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			FixtureRef:  fixtureRef,
		})
	}
}

// Collector implements C02 repo-protection for Azure DevOps.
type Collector struct {
	client *azuredevops.Client
}

// New returns a C02 collector using client for all API calls. Unlike the
// GitHub twin (which gives each repo its own Client, since it genuinely
// issues distinct per-repo calls), this collector shares one Client across
// every in-scope repo: both upstream calls (Repositories - List, Policy
// Configurations - List) are project-scoped, not per-repo, so there is
// exactly one of each regardless of how many repos scope.Repos names —
// giving each repo its own Client would just re-issue the identical two
// calls once per repo for no benefit.
func New(client *azuredevops.Client) *Collector {
	return &Collector{client: client}
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. It never returns a non-nil
// top-level error: a project-level API failure becomes a not-checkable
// result for the three policy-driven checks on every in-scope repo (the
// three ACL-governed checks are unaffected — they never depend on this
// data at all), so the rollup can still resolve every other check.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	repos, reposErr := fetchRepositories(ctx, c.client, scope.Project)
	policies, policiesErr := fetchPolicyConfigurations(ctx, c.client, scope.Project)
	prov := c.client.Provenance()

	var all []model.CheckResult
	for _, repoName := range scope.Repos {
		all = append(all, collectRepo(scope, repoName, repos, reposErr, policies, policiesErr, prov)...)
	}
	if all == nil {
		all = []model.CheckResult{}
	}
	return all, nil
}

// collectRepo resolves one repo's default branch and matching policies,
// then emits all six CheckResults for it. The three ACL-governed checks
// are computed unconditionally, before any of the early-return failure
// paths below — they carry a fixed reason regardless of whether the repo
// or policy data could be read at all, since no amount of working
// repositories/policy-configurations data would ever change their answer
// (see the package doc comment).
func collectRepo(scope collect.Scope, repoName string, repos []repositoryRaw, reposErr error, policies []policyConfigurationRaw, policiesErr error, prov []model.Provenance) []model.CheckResult {
	fixed := []model.CheckResult{
		checkAdminEnforced(scope.Org, scope.Project, repoName),
		checkForcePushBlocked(scope.Org, scope.Project, repoName),
		checkDeletionBlocked(scope.Org, scope.Project, repoName),
	}

	if reposErr != nil {
		return append(allNotCheckablePolicyDriven(scope.Org, scope.Project, repoName, apiErrorReason(reposErr, "project repositories"), prov), fixed...)
	}
	repo, found := findRepository(repos, repoName)
	if !found {
		reason := fmt.Sprintf("repository %q not found in project %q", repoName, scope.Project)
		return append(allNotCheckablePolicyDriven(scope.Org, scope.Project, repoName, reason, prov), fixed...)
	}
	if repo.DefaultBranch == "" {
		reason := fmt.Sprintf("repository %q has no default branch (empty repository?)", repoName)
		return append(allNotCheckablePolicyDriven(scope.Org, scope.Project, repoName, reason, prov), fixed...)
	}
	if policiesErr != nil {
		return append(allNotCheckablePolicyDriven(scope.Org, scope.Project, repoName, apiErrorReason(policiesErr, "project policy configurations"), prov), fixed...)
	}

	matching := matchingPolicies(policies, repo.ID, repo.DefaultBranch)
	policyResults := []model.CheckResult{
		checkProtectionExists(scope.Org, scope.Project, repoName, matching, prov),
		checkRequiredReviews(scope.Org, scope.Project, repoName, matching, prov),
		checkRequiredStatusChecks(scope.Org, scope.Project, repoName, matching, prov),
	}
	return append(policyResults, fixed...)
}

// allNotCheckablePolicyDriven produces a not-checkable result for only the
// three policy-driven checks (see policyDrivenCheckIDs' own doc comment) —
// the three ACL-governed checks are never touched by this path, since they
// have their own fixed reason regardless of this failure.
func allNotCheckablePolicyDriven(org, project, repo, reason string, prov []model.Provenance) []model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	out := make([]model.CheckResult, 0, len(policyDrivenCheckIDs))
	for _, id := range policyDrivenCheckIDs {
		out = append(out, model.CheckResult{
			CheckID:    id,
			Title:      checkTitles[id],
			Status:     model.StatusNotCheckable,
			Reason:     reason,
			Scope:      model.ScopeRef{Org: org, Project: project, Repo: repo},
			Provenance: prov,
		})
	}
	return out
}

// repositoryRaw is the subset of Azure DevOps's GitRepository shape
// (Repositories - List) this package needs. DefaultBranch is absent
// entirely (decodes to "") for a genuinely empty repository — verified
// against Microsoft's own reference sample response, which shows one
// repository with no defaultBranch field at all.
type repositoryRaw struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	DefaultBranch string `json:"defaultBranch"`
}

// fetchRepositories lists every repository in project via GET
// dev.azure.com/{org}/{project}/_apis/git/repositories (scope vso.code).
func fetchRepositories(ctx context.Context, client *azuredevops.Client, project string) ([]repositoryRaw, error) {
	path := fmt.Sprintf("/%s/%s/_apis/git/repositories", client.Org(), project)
	query := url.Values{"api-version": {"7.1"}}

	var raw []repositoryRaw
	if err := azuredevops.GetJSON(ctx, client, azuredevops.HostCore, path, query, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// findRepository looks up name in repos case-insensitively — Azure DevOps
// repository names are case-insensitive (two repos cannot differ only by
// case within the same project), and unlike GitHub's collectors, this
// package has no repoLister to canonicalize a user-supplied --repo value
// against the platform's own casing first; a case-sensitive comparison
// here would report a real, existing repo as not-checkable ("not found")
// whenever --repo was typed in different casing than the platform stored.
func findRepository(repos []repositoryRaw, name string) (repositoryRaw, bool) {
	for _, r := range repos {
		if strings.EqualFold(r.Name, name) {
			return r, true
		}
	}
	return repositoryRaw{}, false
}

// Policy type IDs this collector tracks — both verified against Microsoft's
// own Policy Configurations - List reference sample response, which shows
// each type's real displayName alongside its id: "Minimum approval count"
// and "Build" respectively.
const (
	minReviewersTypeID    = "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd"
	buildValidationTypeID = "0609b952-1397-4640-95ec-e00a01b2c241"
)

// Policy scope matchKind values. "Exact" and "Prefix" (this exact casing)
// are verified against Microsoft's own Policy Configurations - List
// reference sample response. "DefaultBranch" is a third, real value this
// package's first review pass missed entirely: Azure DevOps's project-level
// "Protect the default branch of each repository" cross-repository policy
// emits a scope entry shaped {repositoryId: null, refName: null,
// matchKind: "DefaultBranch"} — verified against Microsoft's own
// terraform-provider-azuredevops documentation, which describes all three
// match_type values and states refName ("repository_ref") "should not be
// defined" when matchKind is DefaultBranch. Treating that shape as an exact
// match against a null refName (this package's original bug) meant it
// could never match anything, producing a false verified-fail on exactly
// the org-wide best-practice setup this check exists to reward. All three
// values are compared case-insensitively anyway (see refNameMatches) as a
// defensive hedge, the same posture auditlogging's own status-field
// comparisons take against a service that doesn't always match its own
// documented casing.
const (
	matchKindPrefix        = "Prefix"
	matchKindDefaultBranch = "DefaultBranch"
)

// policyScopeRaw is one entry of a PolicyConfiguration's settings.scope[]
// array. RepositoryID is "" for a project-wide entry (Microsoft's JSON
// response carries this as a literal null, which Go's encoding/json
// already decodes a string field to "" for) — no pointer/wrapper type is
// needed to distinguish "null" from "absent" here, since both mean the
// same thing (project-wide) for this collector's purposes.
type policyScopeRaw struct {
	RepositoryID string `json:"repositoryId"`
	RefName      string `json:"refName"`
	MatchKind    string `json:"matchKind"`
}

// policySettingsRaw is the subset of a PolicyConfiguration's settings
// object this package needs. settings is documented as a generic JSON
// object whose real shape varies per policy type (e.g. a Build policy's
// settings carries buildDefinitionId, not minimumApproverCount) —
// encoding/json silently ignores whichever of MinimumApproverCount/
// CreatorVoteCounts don't apply to a given policy's actual type, which is
// fine: this package only ever reads those two fields after already
// filtering to policies whose Type.ID is minReviewersTypeID.
type policySettingsRaw struct {
	Scope                []policyScopeRaw `json:"scope"`
	MinimumApproverCount int              `json:"minimumApproverCount"`
	CreatorVoteCounts    bool             `json:"creatorVoteCounts"`
}

type policyTypeRaw struct {
	ID string `json:"id"`
}

// policyConfigurationRaw is the subset of Azure DevOps's PolicyConfiguration
// shape (Policy Configurations - List) this package needs. IsDeleted is
// absent (decodes to false) on a policy that was never soft-deleted —
// verified against Microsoft's own reference sample response, which omits
// the field entirely on two of its three example configurations.
type policyConfigurationRaw struct {
	IsEnabled  bool              `json:"isEnabled"`
	IsBlocking bool              `json:"isBlocking"`
	IsDeleted  bool              `json:"isDeleted"`
	Type       policyTypeRaw     `json:"type"`
	Settings   policySettingsRaw `json:"settings"`
}

// fetchPolicyConfigurations lists every policy configuration in project via
// GET dev.azure.com/{org}/{project}/_apis/policy/configurations (scope
// vso.code) — every policy in the whole project, not scoped to one repo;
// see the package doc comment for why filtering happens client-side.
func fetchPolicyConfigurations(ctx context.Context, client *azuredevops.Client, project string) ([]policyConfigurationRaw, error) {
	path := fmt.Sprintf("/%s/%s/_apis/policy/configurations", client.Org(), project)
	query := url.Values{"api-version": {"7.1"}}

	var raw []policyConfigurationRaw
	if err := azuredevops.GetJSON(ctx, client, azuredevops.HostCore, path, query, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// matchingPolicies filters policies to the enabled, non-deleted ones whose
// settings.scope[] applies to repositoryID's defaultBranch — the single
// client-side filter every one of this package's three policy-driven
// checks builds on.
func matchingPolicies(policies []policyConfigurationRaw, repositoryID, defaultBranch string) []policyConfigurationRaw {
	var out []policyConfigurationRaw
	for _, p := range policies {
		if !p.IsEnabled || p.IsDeleted {
			continue
		}
		if policyScopeMatches(p.Settings.Scope, repositoryID, defaultBranch) {
			out = append(out, p)
		}
	}
	return out
}

// policyScopeMatches reports whether any of scopes applies to repositoryID's
// defaultBranch: a scope entry with a non-empty RepositoryID that doesn't
// equal repositoryID is scoped to a different repo entirely and is
// skipped — this is the "policy scoped to a different repo being ignored"
// behavior issue #150's acceptance criteria calls out explicitly.
func policyScopeMatches(scopes []policyScopeRaw, repositoryID, defaultBranch string) bool {
	for _, s := range scopes {
		if s.RepositoryID != "" && s.RepositoryID != repositoryID {
			continue
		}
		if refNameMatches(s.RefName, s.MatchKind, defaultBranch) {
			return true
		}
	}
	return false
}

// refNameMatches implements all three matchKind values this package
// recognizes (see their own doc comment): "DefaultBranch" always matches —
// by definition, since this collector only ever evaluates a repo's own
// default branch, and Azure DevOps leaves refName null for this matchKind
// (there is nothing else to compare); "Prefix" requires defaultBranch to
// start with refName (e.g. refName "refs/heads/releases/" matches
// defaultBranch "refs/heads/releases/2.0"); "Exact" (and any other,
// unrecognized matchKind value) is compared verbatim — a stricter,
// fail-closed comparison than guessing at prefix/default-branch semantics
// for a value this collector doesn't recognize, so an unexpected matchKind
// never silently loosens a scope match into applying somewhere it shouldn't.
func refNameMatches(refName, matchKind, defaultBranch string) bool {
	switch {
	case strings.EqualFold(matchKind, matchKindDefaultBranch):
		return true
	case strings.EqualFold(matchKind, matchKindPrefix):
		return strings.HasPrefix(defaultBranch, refName)
	default:
		return refName == defaultBranch
	}
}

// appendUnique appends v to s if it isn't already present — small local
// helper, mirrors the GitHub twin's effective.go copy of the same pattern.
func appendUnique(s []string, v string) []string {
	for _, existing := range s {
		if existing == v {
			return s
		}
	}
	return append(s, v)
}

func checkProtectionExists(org, project, repo string, matching []policyConfigurationRaw, prov []model.Provenance) model.CheckResult {
	const id = idProtectionExists
	var trackedCount int
	var typeIDs []string
	for _, p := range matching {
		if p.Type.ID == minReviewersTypeID || p.Type.ID == buildValidationTypeID {
			trackedCount++
			typeIDs = appendUnique(typeIDs, p.Type.ID)
		}
	}

	status, reason := model.StatusVerifiedFail, "no enabled, non-deleted policy configuration of a tracked "+
		"type (minimum reviewers or build validation) is scoped to this repo's default branch"
	if trackedCount > 0 {
		status = model.StatusVerifiedPass
		reason = fmt.Sprintf("%d enabled policy configuration(s) of a tracked type are scoped to this repo's default branch", trackedCount)
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"tracked_policy_count": trackedCount, "tracked_policy_type_ids": typeIDs},
	}
}

// checkRequiredReviews finds the strongest, not the weakest, matching
// policy: Azure DevOps enforces every matching policy simultaneously, so a
// single policy that individually satisfies blocking && count>=1 &&
// !creatorVoteCounts is a genuine, unbypassable requirement regardless of
// what a separate, weaker matching policy also allows — the review that
// weaker policy would let through still has to clear the strong policy's
// own gate too. An earlier version of this function had this backwards
// (aggregating to the weakest policy, as if regimes were OR'd together
// the way GitHub's legacy-protection/ruleset merge is, rather than every
// ADO policy being an independent AND-gate) and could report partial with
// a false "can be overridden at completion" reason even when a blocking
// policy was, in fact, still fully enforced.
func checkRequiredReviews(org, project, repo string, matching []policyConfigurationRaw, prov []model.Provenance) model.CheckResult {
	const id = idRequiredReviews

	var found bool
	var maxApproverCount int
	var anyFullyBlocking bool // some matching policy is individually blocking AND creatorVoteCounts==false
	var anyBlocking bool      // some matching policy is blocking (regardless of creatorVoteCounts)
	var anyCreatorVoteCounts bool
	for _, p := range matching {
		if p.Type.ID != minReviewersTypeID || p.Settings.MinimumApproverCount < 1 {
			continue
		}
		found = true
		if p.Settings.MinimumApproverCount > maxApproverCount {
			maxApproverCount = p.Settings.MinimumApproverCount
		}
		if p.IsBlocking {
			anyBlocking = true
			if !p.Settings.CreatorVoteCounts {
				anyFullyBlocking = true
			}
		}
		if p.Settings.CreatorVoteCounts {
			anyCreatorVoteCounts = true
		}
	}

	if !found {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: "no enabled, non-deleted Minimum approval count policy scoped to the default branch requires at least 1 approver",
			Scope:  model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: prov,
		}
	}

	facts := map[string]any{
		"minimum_approver_count": maxApproverCount,
		"any_blocking_policy":    anyBlocking,
		"creator_vote_counts":    anyCreatorVoteCounts,
	}

	if anyFullyBlocking {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
			Reason: fmt.Sprintf("at least one matching Minimum approval count policy requires %d approving review(s), is blocking, and has no creator self-vote — a genuine, unbypassable requirement even if a weaker matching policy also applies", maxApproverCount),
			Scope:  model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: prov, Facts: facts,
		}
	}

	// anyFullyBlocking is false here, so every blocking policy (if any) has
	// creatorVoteCounts==true — never claim "overridable at completion"
	// when a blocking policy exists; that claim is only true when there is
	// no blocking policy at all.
	var reason string
	if anyBlocking {
		reason = "at least one matching Minimum approval count policy requires an approving review and is blocking, but every blocking matching policy has creatorVoteCounts=true — the PR author's own vote can count toward that requirement"
	} else {
		reason = fmt.Sprintf("default branch requires %d approving review(s), but every matching policy is non-blocking (isBlocking=false) — the requirement can be overridden at completion", maxApproverCount)
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusPartial,
		Reason: reason,
		Scope:  model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: prov, Facts: facts,
	}
}

// checkRequiredStatusChecks, like checkRequiredReviews, finds the
// strongest matching policy, not the weakest: one blocking Build policy is
// a genuine requirement regardless of whatever a separate, non-blocking
// matching policy also allows — Azure DevOps enforces every matching
// policy simultaneously (an AND-gate across policies), not a
// GitHub-style either-regime OR merge.
func checkRequiredStatusChecks(org, project, repo string, matching []policyConfigurationRaw, prov []model.Provenance) model.CheckResult {
	const id = idRequiredStatusChecks

	var found, anyBlocking bool
	for _, p := range matching {
		if p.Type.ID != buildValidationTypeID {
			continue
		}
		found = true
		if p.IsBlocking {
			anyBlocking = true
		}
	}

	if !found {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: "no enabled, non-deleted Build policy is scoped to the default branch",
			Scope:  model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: prov,
		}
	}

	facts := map[string]any{"any_blocking_policy": anyBlocking}
	if anyBlocking {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
			Reason: "at least one matching Build policy scoped to the default branch is blocking — a genuine requirement even if a separate, non-blocking matching policy also applies",
			Scope:  model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: prov, Facts: facts,
		}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusPartial,
		Reason: "a build validation policy is scoped to the default branch, but every matching Build policy is non-blocking (isBlocking=false) — a failing or missing build does not block merge for any of them",
		Scope:  model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: prov, Facts: facts,
	}
}

// checkAdminEnforced is not-checkable always — see the package doc comment
// for why no policy-configuration data could ever answer this.
func checkAdminEnforced(org, project, repo string) model.CheckResult {
	const id = idAdminEnforced
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "Azure DevOps' bypass model here is the \"Bypass policies when completing pull requests\" " +
			"and \"Bypass policies when pushing\" Git repository security permissions (ACLs), not policy " +
			"configuration data — out of scope for v0.2 (issue #34's non-goals)",
		Scope: model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: []model.Provenance{},
	}
}

// checkForcePushBlocked is not-checkable always — see the package doc
// comment for why no policy-configuration data could ever answer this.
func checkForcePushBlocked(org, project, repo string) model.CheckResult {
	const id = idForcePushBlocked
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "Azure DevOps controls this via the \"Force push (rewrite history, delete branches and " +
			"tags)\" Git repository security permission (an ACL, not policy configuration data) — out of " +
			"scope for v0.2 (issue #34's non-goals)",
		Scope: model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: []model.Provenance{},
	}
}

// checkDeletionBlocked is not-checkable always — Azure DevOps has no
// permission distinct from force-push for deleting a branch at all (see
// the package doc comment), so this shares its rationale with
// checkForcePushBlocked rather than naming a second, separate permission
// that doesn't exist.
func checkDeletionBlocked(org, project, repo string) model.CheckResult {
	const id = idDeletionBlocked
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "Azure DevOps has no permission distinct from \"Force push (rewrite history, delete " +
			"branches and tags)\" for deleting a branch (confirmed against Microsoft's own Git " +
			"branch-permissions documentation) — the same ACL that governs C02.branch.force-push-blocked, " +
			"not policy configuration data, out of scope for v0.2 (issue #34's non-goals)",
		Scope: model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: []model.Provenance{},
	}
}

// apiErrorReason turns a GetJSON failure into a Reason string, naming the
// exact permission/existence problem when err is a *azuredevops.StatusError
// with a 403 or 404 status — mirrors orgsecurity's identical helper (kept
// as a package-local copy rather than shared, matching this codebase's
// existing per-package duplication convention for small helpers like this).
func apiErrorReason(err error, what string) string {
	var statusErr *azuredevops.StatusError
	if errors.As(err, &statusErr) {
		switch statusErr.StatusCode {
		case http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to read %s (403)", what)
		case http.StatusNotFound:
			return fmt.Sprintf("%s not found (404) — the project may not exist, or this resource is unreachable", what)
		}
	}
	return fmt.Sprintf("could not read %s: %v", what, err)
}
