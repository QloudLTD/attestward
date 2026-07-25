// Package envseparation implements C03 env-separation for Azure DevOps —
// the ADO counterpart to internal/collect/github/envseparation, and issue
// #34's env-separation control (SSDF PO.5.1).
//
// Structural point that shapes this whole package: Azure DevOps
// environments are PROJECT-scoped, not repo-scoped (there is no per-repo
// environment concept the way GitHub has). All four results this
// collector produces attach at the project level — Scope.Project set,
// Scope.Repo left empty — and there is exactly one set of four
// CheckResults per Collect() call, never one set per repo the way the
// GitHub twin (and this epic's own C02 repo-protection) fan out.
// scope.Repos is never consulted.
//
// Two upstream calls back every check: Environments - List
// (dev.azure.com/{org}/{project}/_apis/distributedtask/environments) finds
// every environment in the project; Check Configurations - List
// (.../_apis/pipelines/checks/configurations?resourceType=environment&
// resourceId={envId}&$expand=settings) is then called once PER
// production-like environment (resourceId is a query parameter that
// narrows the response server-side to one resource at a time — unlike
// C02's project-wide policy list, there is no single project-wide checks
// call to make). Only production-like environments' checks are fetched at
// all — a non-prod environment's checks are irrelevant to every one of
// this package's four checks, the same scoping the GitHub twin applies.
//
// Environments - List's only documented OAuth/PAT scope is
// vso.environment_manage (manage-level) — verified against Microsoft's own
// REST reference, which lists no read-only alternative at all. This is
// recorded verbatim in CheckMeta.TokenScope for C03.env.exists rather than
// silently assuming a lower-privilege scope exists.
//
// C03.env.exists reuses the GitHub twin's prod*/production case-insensitive
// name heuristic (prodLikeEnvName) verbatim, and this package copies that
// twin's three-way result shape: envs exist and at least one matches the
// heuristic (verified-pass for exists; the other three checks then
// evaluate real posture), envs exist but none match (partial across all
// four — see allPartialNoProdEnv), or the environments read itself failed
// or found zero environments (not-checkable across all four).
//
// C03.env.branch-policy carries a real [fixture-verify] gap, flagged
// explicitly rather than quietly assumed away: a Task Check's
// $expand=settings payload for the built-in Branch Control task
// (evaluatebranchProtection) is UNDOCUMENTED on Microsoft's own Check
// Configurations - List reference (its CheckConfiguration definitions
// table lists no settings field at all — $expand=settings adds it
// dynamically, shape unstated there). taskCheckSettingsRaw's own doc
// comment records exactly what this parse assumes, why, and how an
// unexpected shape degrades to an honest partial rather than a guessed
// pass or fail — issue #151's own specified conservative fallback.
//
// Every server-enum string comparison in this package (check type IDs) is
// case-insensitive — Azure DevOps demonstrably doesn't always match its
// own documented casing, the same hedge C09 audit-logging's status-field
// comparisons already established for this epic. No identity data
// (createdBy/modifiedBy/lastModifiedBy — real names, emails, GUIDs) is
// ever decoded into this package's raw types at all: both environmentRaw
// and checkConfigurationRaw simply have no field for it, so encoding/json's
// silent-drop-of-unknown-keys behavior makes it structurally impossible
// for identity data to reach Facts, not merely unused once decoded.
package envseparation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/model"
)

// collectorID must equal the GitHub twin's Collector string exactly — the
// registry (internal/collect/registry.go's Register) panics if two
// platforms register the same check ID under different Collector strings.
const collectorID = "C03.env-separation"

const (
	idExists            = "C03.env.exists"
	idProtectionRules   = "C03.env.protection-rules"
	idRequiredReviewers = "C03.env.required-reviewers"
	idBranchPolicy      = "C03.env.branch-policy"
)

// checkIDs is checkTitles' keys in a fixed order, so init()'s registration
// order and allNotCheckable's result order are deterministic — mirrors the
// GitHub twin's identical rationale.
var checkIDs = []string{idExists, idProtectionRules, idRequiredReviewers, idBranchPolicy}

var checkTitles = map[string]string{
	idExists:            "A production-like environment exists",
	idProtectionRules:   "Production-like environments have at least one protection check",
	idRequiredReviewers: "Production-like environments require reviewer approval before deployment",
	idBranchPolicy:      "Production-like environments restrict which branches can deploy",
}

var checkRemediations = map[string]string{
	idExists: "Pipelines -> Environments -> New environment -> name it \"production\" (or any prod*/production " +
		"variant — this check's name heuristic is case-insensitive) so deployments can be routed through it.",
	idProtectionRules: "Open the production-like environment -> \"...\" (kebab menu) -> Approvals and checks " +
		"-> Add check -> configure at least one check (Approval, Branch control, Business hours, Invoke Azure " +
		"Function, etc.).",
	idRequiredReviewers: "Open the production-like environment -> Approvals and checks -> Add check -> " +
		"Approvals -> add at least one approver.",
	idBranchPolicy: "Open the production-like environment -> Approvals and checks -> Add check -> Branch " +
		"control -> set \"Allowed branches\" to a real restrictive list (e.g. refs/heads/main), not the " +
		"task's \"*\" (no restriction) default.",
}

// sharedPartialRubric is shared by all four checks: when one or more
// environments exist but none match the production-like naming heuristic,
// every check reports partial identically — mirrors the GitHub twin's
// identical sharedPartialRubric and allPartialNoProdEnv's own doc comment
// for why that's an affirmative "ambiguous, needs a human" result.
const sharedPartialRubric = "one or more environments exist, but none match the production-like naming " +
	"heuristic (`prod`* prefix, case-insensitive) — a human reviewer should judge whether one of them is " +
	"actually production before this check can evaluate anything"

// notCheckableEnvListRubric covers the failure surface all four checks
// share: the project's environments list itself couldn't be read, or the
// project has none at all. notCheckableChecksRubric extends it with the
// second failure surface only the three checks-derived checks depend on
// (idExists never calls Check Configurations - List at all, so a failure
// there can never make idExists not-checkable — see Collect's own doc
// comment for why idExists is computed independently of that call).
const notCheckableEnvListRubric = "the project's environments list couldn't be read (403/404/other API " +
	"error), or the project has zero environments configured at all"

const notCheckableChecksRubric = notCheckableEnvListRubric + ", or a production-like environment's check " +
	"configurations couldn't be read (403/404/other API error)"

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce. idExists can never produce verified-fail — like
// its GitHub twin, checkExists only runs once collectRepo-equivalent logic
// in Collect has already confirmed at least one production-like
// environment exists. idBranchPolicy is the odd one out with two distinct
// partial causes: the shared no-prod-env case every check has, and a
// second, branch-policy-specific ambiguous-settings case from the
// [fixture-verify] gap in resolveBranchPolicy — both are folded into one
// Rubric string since CheckMeta.Rubric holds one static description per
// status, not per triggering cause.
var checkRubrics = map[string]map[model.Status]string{
	idExists: {
		model.StatusVerifiedPass: "at least one environment's name matches the production-like heuristic " +
			"(`prod`* prefix, case-insensitive)",
		model.StatusPartial:      sharedPartialRubric,
		model.StatusNotCheckable: notCheckableEnvListRubric,
	},
	idProtectionRules: {
		model.StatusVerifiedPass: "every production-like environment has at least one non-disabled check " +
			"configuration of any type (GET .../_apis/pipelines/checks/configurations?resourceType=" +
			"environment&resourceId={id} returns at least one entry with isDisabled!=true)",
		model.StatusVerifiedFail: "at least one production-like environment has zero non-disabled check configurations",
		model.StatusPartial:      sharedPartialRubric,
		model.StatusNotCheckable: notCheckableChecksRubric,
	},
	idRequiredReviewers: {
		model.StatusVerifiedPass: "every production-like environment has a non-disabled Approval check " +
			"configuration (type id 8c6f20a7-a545-4486-9777-f762fafe0d4d)",
		model.StatusVerifiedFail: "at least one production-like environment lacks a non-disabled Approval check configuration",
		model.StatusPartial:      sharedPartialRubric,
		model.StatusNotCheckable: notCheckableChecksRubric,
	},
	idBranchPolicy: {
		model.StatusVerifiedPass: "every production-like environment has a non-disabled Task Check " +
			"configuration (type id fe1de3ee-a436-41b4-bb20-f6eb4cb879a7) whose $expand=settings payload " +
			"could be confidently interpreted as a real, non-wildcard allowed-branches restriction — " +
			"[fixture-verify]: this settings schema is undocumented by Microsoft, so the interpretation is a " +
			"corroborated-but-unconfirmed best guess (see taskCheckSettingsRaw's own doc comment) pending a " +
			"recorded real response",
		model.StatusVerifiedFail: "at least one production-like environment has no non-disabled Task Check " +
			"configuration at all — a confident, definitive absence of any branch restriction",
		model.StatusPartial: sharedPartialRubric + ". Separately — when every production-like environment has " +
			"at least one Task Check, but at least one Task Check's settings couldn't be confidently " +
			"interpreted per the verified-pass entry's [fixture-verify] caveat — the conservative fallback " +
			"issue #151 specifies: \"a task check exists but its branch-control settings could not be interpreted\"",
		model.StatusNotCheckable: notCheckableChecksRubric,
	},
}

// environmentsEndpoint and checksEndpoint document which host each lives
// on inline (dev.azure.com for both, but written out per this epic's
// multi-host convention — see internal/collect/azuredevops's own package
// doc comment) — checksEndpoint's query parameters are part of the
// description since resourceType/resourceId/$expand all change what the
// endpoint actually returns (resourceId narrows to one resource;
// $expand=settings is the entire basis of C03.env.branch-policy's parse —
// without it, the settings field this check reads isn't even present in
// the response), the same convention orgsecurity's own Endpoints entries use.
const (
	environmentsEndpoint = "GET dev.azure.com/{org}/{project}/_apis/distributedtask/environments"
	checksEndpoint       = "GET dev.azure.com/{org}/{project}/_apis/pipelines/checks/configurations?resourceType=environment&resourceId={envId}&$expand=settings"
)

var checkEndpoints = map[string][]string{
	idExists:            {environmentsEndpoint},
	idProtectionRules:   {environmentsEndpoint, checksEndpoint},
	idRequiredReviewers: {environmentsEndpoint, checksEndpoint},
	idBranchPolicy:      {environmentsEndpoint, checksEndpoint},
}

// checkTokenScopes documents all four checks' scope needs. idExists names
// only vso.environment_manage's own caveat (Environments - List has no
// read-only PAT scope at all — verified against Microsoft's OAuth scopes
// reference, which lists exactly one scope for this endpoint and it's
// manage-level); the other three also depend on Check Configurations -
// List's own vso.build scope.
var checkTokenScopes = map[string]string{
	idExists: "vso.environment_manage — Environments - List has no documented read-only PAT scope at all; " +
		"the only documented scope for this read endpoint is manage-level",
	idProtectionRules: "vso.environment_manage (Environments - List, see C03.env.exists' own caveat) plus " +
		"vso.build (Check Configurations - List)",
	idRequiredReviewers: "vso.environment_manage (Environments - List, see C03.env.exists' own caveat) plus " +
		"vso.build (Check Configurations - List)",
	idBranchPolicy: "vso.environment_manage (Environments - List, see C03.env.exists' own caveat) plus " +
		"vso.build (Check Configurations - List)",
}

const fixtureRef = "internal/collect/azuredevops/envseparation/envseparation_test.go"

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
			// Every C03 check is project-scoped, never org-scoped —
			// environments are project-level on Azure DevOps (see the
			// package doc comment). See CheckMeta.ScopeLevel (#176).
			ScopeLevel: collect.ScopeLevelProject,
		})
	}
}

// Collector implements C03 env-separation for Azure DevOps.
type Collector struct {
	client *azuredevops.Client
}

// New returns a C03 collector using client for all API calls. A single
// Client is safe to share across this collector's whole Collect() call:
// unlike the GitHub twin's per-repo fan-out, there is no concurrency here
// at all — one Environments - List call followed by a small, sequential
// per-production-environment loop of Check Configurations - List calls —
// so Client.Provenance()'s cumulative log is exactly what backs every one
// of this Collect() call's four results, with no per-check slicing needed
// (contrast with C01 org-security, whose four checks are independent
// enough to need their own provenance attribution).
func New(client *azuredevops.Client) *Collector {
	return &Collector{client: client}
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. It never returns a non-nil
// top-level error: a project-level API failure becomes a not-checkable
// result for the affected check(s), so the rollup can still resolve every
// other check. All four results share Scope.Project (scope.Repos is never
// consulted — see the package doc comment for why).
//
// idExists is always computed from the environments list alone and never
// becomes not-checkable due to a Check Configurations - List failure: it
// answers "does a production-like environment exist", which the
// environments list alone already settles, before any per-environment
// checks call is even attempted.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	envs, err := fetchEnvironments(ctx, c.client, scope.Project)
	prov := c.client.Provenance()
	if err != nil {
		return allNotCheckable(scope.Org, scope.Project, notCheckableEnvReason(err), prov), nil
	}
	if len(envs) == 0 {
		return allNotCheckable(scope.Org, scope.Project, "no environments configured", prov), nil
	}

	allNames := envNames(envs)
	prodEnvs := prodLikeEnvs(envs)
	if len(prodEnvs) == 0 {
		return allPartialNoProdEnv(scope.Org, scope.Project, allNames, prov), nil
	}

	existsResult := checkExists(scope.Org, scope.Project, allNames, prodEnvs, prov)

	envChecks, checksErr := fetchAllCheckConfigurations(ctx, c.client, scope.Project, prodEnvs)
	prov = c.client.Provenance()
	if checksErr != nil {
		reason := notCheckableChecksReason(checksErr)
		return []model.CheckResult{
			existsResult,
			notCheckableResult(idProtectionRules, scope.Org, scope.Project, reason, prov),
			notCheckableResult(idRequiredReviewers, scope.Org, scope.Project, reason, prov),
			notCheckableResult(idBranchPolicy, scope.Org, scope.Project, reason, prov),
		}, nil
	}

	return []model.CheckResult{
		existsResult,
		checkProtectionRules(scope.Org, scope.Project, prodEnvs, envChecks, prov),
		checkRequiredReviewers(scope.Org, scope.Project, prodEnvs, envChecks, prov),
		checkBranchPolicy(scope.Org, scope.Project, prodEnvs, envChecks, prov),
	}, nil
}

// environmentRaw is the subset of Azure DevOps's EnvironmentInstance shape
// (Environments - List) this package needs. createdBy/lastModifiedBy
// (IdentityRef — real names/emails/GUIDs) are deliberately omitted
// entirely — see the package doc comment.
type environmentRaw struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// fetchEnvironments lists every environment in project via GET
// dev.azure.com/{org}/{project}/_apis/distributedtask/environments (scope
// vso.environment_manage — see the package doc comment for why there's no
// lower-privilege alternative).
func fetchEnvironments(ctx context.Context, client *azuredevops.Client, project string) ([]environmentRaw, error) {
	path := fmt.Sprintf("/%s/%s/_apis/distributedtask/environments", client.Org(), project)
	query := url.Values{"api-version": {"7.1"}}

	var raw []environmentRaw
	if err := azuredevops.GetJSON(ctx, client, azuredevops.HostCore, path, query, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// prodLikeEnvName is the GitHub twin's heuristic, reused verbatim: name
// matches "prod*"/"production" case-insensitively. A case-insensitive
// "prod" prefix match covers both forms (and common variants like
// "prod-us-east") in one rule.
func prodLikeEnvName(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "prod")
}

func envNames(envs []environmentRaw) []string {
	names := make([]string, 0, len(envs))
	for _, e := range envs {
		names = append(names, e.Name)
	}
	return names
}

func prodLikeEnvs(envs []environmentRaw) []environmentRaw {
	var out []environmentRaw
	for _, e := range envs {
		if prodLikeEnvName(e.Name) {
			out = append(out, e)
		}
	}
	return out
}

// checkTypeRaw is Azure DevOps's CheckType shape: a check configuration's
// type. Name (e.g. "Approval", "Task Check" — the human-readable label) is
// deliberately not decoded at all: every comparison in this package
// matches on Type.ID (the stable, verified GUID — approvalCheckTypeID,
// taskCheckTypeID), never on the display name, so keeping an unused Name
// field around would just be dead weight.
type checkTypeRaw struct {
	ID string `json:"id"`
}

// checkConfigurationRaw is the subset of Azure DevOps's CheckConfiguration
// shape (Check Configurations - List, $expand=settings) this package
// needs. createdBy/modifiedBy (IdentityRef — real names/emails/GUIDs) are
// deliberately omitted entirely, not merely unused — see the package doc
// comment. Settings is kept as raw JSON rather than a typed struct at this
// level: its real shape varies per check type, and only resolveBranchPolicy
// attempts a further, explicitly-hedged parse of it (for Task Check
// specifically) — see taskCheckSettingsRaw's own doc comment.
type checkConfigurationRaw struct {
	ID         int             `json:"id"`
	IsDisabled bool            `json:"isDisabled"`
	Type       checkTypeRaw    `json:"type"`
	Settings   json.RawMessage `json:"settings"`
}

// fetchCheckConfigurations lists every check configuration on environment
// envID via GET dev.azure.com/{org}/{project}/_apis/pipelines/checks/
// configurations?resourceType=environment&resourceId={envID}&
// $expand=settings (scope vso.build).
func fetchCheckConfigurations(ctx context.Context, client *azuredevops.Client, project string, envID int) ([]checkConfigurationRaw, error) {
	path := fmt.Sprintf("/%s/%s/_apis/pipelines/checks/configurations", client.Org(), project)
	query := url.Values{
		"resourceType": {"environment"},
		"resourceId":   {strconv.Itoa(envID)},
		"$expand":      {"settings"},
		"api-version":  {"7.1-preview.1"},
	}

	var raw []checkConfigurationRaw
	if err := azuredevops.GetJSON(ctx, client, azuredevops.HostCore, path, query, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// fetchAllCheckConfigurations fetches check configurations for every one
// of envs (production-like environments only — see the package doc
// comment for why non-prod environments' checks are never fetched at
// all), stopping at the first failure: a partial map with one
// unreadable environment isn't safe to evaluate "every production-like
// environment" checks against, since the unreadable one might be exactly
// the one that fails.
func fetchAllCheckConfigurations(ctx context.Context, client *azuredevops.Client, project string, envs []environmentRaw) (map[int][]checkConfigurationRaw, error) {
	out := make(map[int][]checkConfigurationRaw, len(envs))
	for _, e := range envs {
		checks, err := fetchCheckConfigurations(ctx, client, project, e.ID)
		if err != nil {
			return nil, err
		}
		out[e.ID] = checks
	}
	return out, nil
}

// enabledChecks returns only the non-disabled entries of checks.
func enabledChecks(checks []checkConfigurationRaw) []checkConfigurationRaw {
	var out []checkConfigurationRaw
	for _, c := range checks {
		if !c.IsDisabled {
			out = append(out, c)
		}
	}
	return out
}

// approvalCheckTypeID is the "Approval" check type — verified against
// Microsoft's own Check Configurations - List reference sample response,
// which shows this exact id alongside type.name=="Approval".
const approvalCheckTypeID = "8c6f20a7-a545-4486-9777-f762fafe0d4d"

// taskCheckTypeID is the "Task Check" check type — verified against the
// same reference sample response, type.name=="Task Check".
const taskCheckTypeID = "fe1de3ee-a436-41b4-bb20-f6eb4cb879a7"

func hasApprovalCheck(checks []checkConfigurationRaw) bool {
	for _, c := range enabledChecks(checks) {
		if strings.EqualFold(c.Type.ID, approvalCheckTypeID) {
			return true
		}
	}
	return false
}

// branchPolicyOutcome is resolveBranchPolicy's typed result for one
// environment — see its own doc comment for what each value means and why
// this is a three-way outcome, not a plain bool.
type branchPolicyOutcome int

const (
	// branchPolicyAbsent means no non-disabled Task Check configuration
	// exists on this environment at all — a confident, definitive "not
	// restricted", mirroring the GitHub twin's fail-on-absent branch
	// policy.
	branchPolicyAbsent branchPolicyOutcome = iota
	// branchPolicyAmbiguous means a Task Check exists, but its settings
	// couldn't be confidently interpreted as a real branch restriction —
	// issue #151's specified conservative fallback for the [fixture-verify]
	// gap in taskCheckSettingsRaw.
	branchPolicyAmbiguous
	// branchPolicyConfigured means a Task Check exists whose settings were
	// confidently interpreted as a real, non-wildcard allowed-branches
	// restriction.
	branchPolicyConfigured
)

// taskCheckSettingsRaw is this package's best-effort, [fixture-verify]
// guess at a Task Check's $expand=settings shape when the underlying task
// is Branch Control (Azure Pipelines' built-in "evaluatebranchProtection"
// task) — UNDOCUMENTED on Microsoft's own Check Configurations - List
// reference: its CheckConfiguration definitions table lists no settings
// field at all, so $expand=settings adds a field whose shape that
// reference page never states. inputs.allowedBranches as a comma-separated
// refs/heads/... list (with "*" as the task's own documented "no
// restriction" default) is corroborated only by third-party
// Terraform/Pulumi provider documentation of the equivalent
// azuredevops_check_branch_control resource — real, but not Microsoft's
// own REST reference, and Terraform-facing field names aren't guaranteed
// to match the raw task's own settings.inputs keys verbatim. issue #151
// requires this parse to degrade honestly rather than error or guess a
// pass when it's wrong: resolveBranchPolicy treats anything that doesn't
// decode into this shape, or decodes with an absent/wildcard/empty
// allowedBranches, as branchPolicyAmbiguous — never as a fabricated pass
// or fail. Confirm or correct this shape against a real recorded response
// before removing this doc comment's [fixture-verify] tag.
type taskCheckSettingsRaw struct {
	Inputs map[string]string `json:"inputs"`
}

// resolveBranchPolicy interprets one environment's (already-fetched) check
// configurations for C03.env.branch-policy — see branchPolicyOutcome's own
// doc comment for what each result means, and taskCheckSettingsRaw's for
// the [fixture-verify] caveat this parse rests on. Multiple Task Check
// configurations on one environment are treated permissively: if ANY of
// them is confidently interpreted as a real restriction, that's enough —
// this mirrors how a single working gate is enough for the GitHub twin's
// binary hasBranchPolicy, not an AND across every Task Check present.
func resolveBranchPolicy(checks []checkConfigurationRaw) branchPolicyOutcome {
	var sawTaskCheck bool
	for _, c := range enabledChecks(checks) {
		if !strings.EqualFold(c.Type.ID, taskCheckTypeID) {
			continue
		}
		sawTaskCheck = true

		var settings taskCheckSettingsRaw
		if err := json.Unmarshal(c.Settings, &settings); err != nil {
			continue // uninterpretable shape — stays ambiguous below unless a later Task Check resolves it
		}
		if hasRealBranchRestriction(settings.Inputs["allowedBranches"]) {
			return branchPolicyConfigured
		}
	}
	if !sawTaskCheck {
		return branchPolicyAbsent
	}
	return branchPolicyAmbiguous
}

// hasRealBranchRestriction reports whether allowedBranches (the Branch
// Control task's comma-separated refs/heads/... input) contains at least
// one entry and none of its entries is a match-all wildcard pattern. A
// single match-all entry makes the whole list vacuous regardless of how
// many more specific entries sit alongside it — "refs/heads/main,*" still
// allows every branch, since the "*" entry alone matches anything — so
// this must scan every comma-separated entry individually rather than
// only reject the literal whole-string "*" (an earlier version of this
// function did exactly that, and so misread "refs/heads/*"/"refs/*" and
// any mixed list containing one of those as a genuine restriction).
func hasRealBranchRestriction(allowedBranches string) bool {
	var sawEntry bool
	for _, part := range strings.Split(allowedBranches, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if isWildcardBranchPattern(part) {
			return false
		}
		sawEntry = true
	}
	return sawEntry
}

// isWildcardBranchPattern reports whether pattern is one of the Branch
// Control task's match-all forms — "*" (the task's own documented "no
// restriction" default) plus its two common ref-qualified spellings,
// "refs/heads/*" and "refs/*". Corroborated only by third-party
// Terraform/Pulumi provider documentation, the same [fixture-verify]
// caveat taskCheckSettingsRaw's own doc comment records for this whole parse.
func isWildcardBranchPattern(pattern string) bool {
	switch pattern {
	case "*", "refs/heads/*", "refs/*":
		return true
	default:
		return false
	}
}

func checkExists(org, project string, allNames []string, prodEnvs []environmentRaw, prov []model.Provenance) model.CheckResult {
	const id = idExists
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
		Reason: fmt.Sprintf("%d production-like environment(s) found among %d total", len(prodEnvs), len(allNames)),
		Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov,
		Facts: map[string]any{
			"all_environment_names":        allNames,
			"production_like_environments": envNames(prodEnvs),
			"production_like_heuristic":    "name matches prod*/production, case-insensitive",
		},
	}
}

func checkProtectionRules(org, project string, prodEnvs []environmentRaw, envChecks map[int][]checkConfigurationRaw, prov []model.Provenance) model.CheckResult {
	const id = idProtectionRules
	var withoutChecks []string
	for _, e := range prodEnvs {
		if len(enabledChecks(envChecks[e.ID])) == 0 {
			withoutChecks = append(withoutChecks, e.Name)
		}
	}
	status, reason := model.StatusVerifiedPass, "every production-like environment has at least one non-disabled check configuration"
	if len(withoutChecks) > 0 {
		status = model.StatusVerifiedFail
		reason = fmt.Sprintf("environment(s) with no non-disabled check configurations: %v", withoutChecks)
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Project: project}, Provenance: prov,
		Facts: map[string]any{
			"production_like_environments": envNames(prodEnvs),
			"environments_without_checks":  withoutChecks,
		},
	}
}

func checkRequiredReviewers(org, project string, prodEnvs []environmentRaw, envChecks map[int][]checkConfigurationRaw, prov []model.Provenance) model.CheckResult {
	const id = idRequiredReviewers
	var without []string
	for _, e := range prodEnvs {
		if !hasApprovalCheck(envChecks[e.ID]) {
			without = append(without, e.Name)
		}
	}
	status, reason := model.StatusVerifiedPass, "every production-like environment has a non-disabled Approval check configured"
	if len(without) > 0 {
		status = model.StatusVerifiedFail
		reason = fmt.Sprintf("environment(s) without a non-disabled Approval check: %v", without)
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Project: project}, Provenance: prov,
		Facts: map[string]any{
			"production_like_environments":            envNames(prodEnvs),
			"environments_without_required_reviewers": without,
		},
	}
}

func checkBranchPolicy(org, project string, prodEnvs []environmentRaw, envChecks map[int][]checkConfigurationRaw, prov []model.Provenance) model.CheckResult {
	const id = idBranchPolicy
	var absent, ambiguous []string
	for _, e := range prodEnvs {
		switch resolveBranchPolicy(envChecks[e.ID]) {
		case branchPolicyAbsent:
			absent = append(absent, e.Name)
		case branchPolicyAmbiguous:
			ambiguous = append(ambiguous, e.Name)
		}
	}

	facts := map[string]any{
		"production_like_environments":                        envNames(prodEnvs),
		"environments_without_task_check":                     absent,
		"environments_with_ambiguous_branch_control_settings": ambiguous,
	}

	// absent (a confident, definitive gap) outranks ambiguous (an honest
	// "can't tell") when both occur across different environments in the
	// same result: this collector never reports a status stronger than
	// what the worst-off production-like environment actually warrants.
	switch {
	case len(absent) > 0:
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: fmt.Sprintf("environment(s) with no Task Check (branch control) configuration at all: %v", absent),
			Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov, Facts: facts,
		}
	case len(ambiguous) > 0:
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusPartial,
			Reason: fmt.Sprintf("a task check exists but its branch-control settings could not be interpreted for: %v", ambiguous),
			Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov, Facts: facts,
		}
	default:
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
			Reason: "every production-like environment has a Task Check restricting deployment to specific branches",
			Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov, Facts: facts,
		}
	}
}

func notCheckableEnvReason(err error) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) {
		switch se.StatusCode {
		case http.StatusForbidden:
			return "token lacks permission to read the project's environments"
		case http.StatusNotFound:
			return "project not found, or its environments endpoint is unreachable"
		}
	}
	return fmt.Sprintf("could not read project environments: %v", err)
}

func notCheckableChecksReason(err error) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) {
		switch se.StatusCode {
		case http.StatusForbidden:
			return "token lacks permission to read check configurations for one or more production-like environments"
		case http.StatusNotFound:
			return "check configurations endpoint not found for one or more production-like environments"
		}
	}
	return fmt.Sprintf("could not read check configurations for one or more production-like environments: %v", err)
}

func notCheckableResult(id, org, project, reason string, prov []model.Provenance) model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: reason,
		Scope: model.ScopeRef{Org: org, Project: project}, Provenance: prov,
	}
}

func allNotCheckable(org, project, reason string, prov []model.Provenance) []model.CheckResult {
	out := make([]model.CheckResult, 0, len(checkIDs))
	for _, id := range checkIDs {
		out = append(out, notCheckableResult(id, org, project, reason, prov))
	}
	return out
}

// allPartialNoProdEnv is the "envs exist but none production-like by
// heuristic" case: a human reviewer, not the heuristic, should decide
// whether one of these environments is actually production — mirrors the
// GitHub twin's identical allPartialNoProdEnv.
func allPartialNoProdEnv(org, project string, allNames []string, prov []model.Provenance) []model.CheckResult {
	reason := fmt.Sprintf("%d environment(s) exist but none match the production-like naming heuristic (prod*/production, case-insensitive) — a human reviewer should judge whether one of them is production", len(allNames))
	out := make([]model.CheckResult, 0, len(checkIDs))
	for _, id := range checkIDs {
		out = append(out, model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusPartial, Reason: reason,
			Scope: model.ScopeRef{Org: org, Project: project}, Provenance: prov,
			Facts: map[string]any{"all_environment_names": allNames},
		})
	}
	return out
}
