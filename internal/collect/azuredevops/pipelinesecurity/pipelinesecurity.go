// Package pipelinesecurity implements C08 pipeline-security for Azure
// DevOps — the ADO counterpart to internal/collect/github/actionssecurity
// — under the same five check IDs (issue #34's check-identity model),
// plus one new ADO-only check where GitHub's pull_request_target semantics
// have no equivalent but ADO's fork-build protections are the adjacent
// real control (issue #153's own C08 spec).
//
// Structural point that shapes this whole package: every one of C08's
// checks reads project-scoped evidence (pipeline general settings, service
// endpoints, build definitions, the project's own visibility) — none of it
// is per-repo. All six results attach at the project level (Scope.Project
// set, Scope.Repo left empty) and there is exactly one set of six
// CheckResults per Collect() call, never one set per repo — mirrors C03
// env-separation's identical architecture exactly (single shared Client,
// no ForEachRepo fan-out, scope.Repos never consulted).
//
// C08.actions.pinned and C08.actions.pull-request-target are not-checkable
// ALWAYS, unconditionally, with no API call of their own — the same shape
// as internal/collect/azuredevops/vdp's C10.vdp.private-reporting/
// C10.vdp.security-policy-org, and C07 provenance's three always-not-
// checkable checks. pinned: Azure Pipelines resolves task references as
// Task@MajorVersion against org-installed task versions — there is no
// commit-SHA-pinnable reference the way a GitHub Actions `uses:` line has,
// so nothing this tool could ever confirm. pull-request-target: Azure
// Pipelines has no trigger equivalent to GitHub's pull_request_target (a
// trigger that runs with base-repo privileges against a pull request) —
// see the NEW check below for the adjacent real control this platform
// actually has. Both follow vdp's exact convention: Reason states the
// platform fact directly, Provenance is always []model.Provenance{}, and
// Collect emits them unconditionally, immune to any upstream failure.
//
// C08.pipelines.fork-protection (ADO-only, no GitHub twin at all) is the
// real, adjacent control issue #153 names: when buildsEnabledForForks is
// true, a fork's pull request can trigger a build at all, and
// forkProtectionEnabled + enforceNoAccessToSecretsFromForks are what
// determine whether that build can access secrets or escalate privilege.
// The issue's own text names two explicit outcomes (pass when both
// settings are on, partial when "mixed" — exactly one is on) but doesn't
// spell out the zero-of-two case; this collector treats neither-enforced
// as verified-fail (the worst, most exposed configuration, the direct
// analogue of the GitHub twin's own confirmed pwn-request exploit
// pattern for pull_request_target) — a deliberate interpretation, stated
// here rather than silently assumed. This check registers under
// azuredevops only, never github, so collect.Register's cross-platform
// Collector-string consistency check never has anything to compare it
// against. Mapping: added to PO.5.1's checks list, copied from the
// existing C08.actions.pull-request-target entry already there — never
// invented (mappings/ssdf-800-218.yaml, version bumped per convention).
//
// C08.actions.token-permissions and C08.pipelines.fork-protection both
// read the SAME General Settings - Get response (fetched once, shared),
// scope vso.project — verified against Microsoft's own REST reference,
// which lists exactly that one scope, surprisingly not vso.build.
// generalSettingsRaw's fields decode as plain bool, not *bool: unlike the
// GHAzDO enablement endpoints' codeSecurityFeatures/secretProtectionFeatures
// blocks (whose own doc comments record a real, documented nullability
// caveat), Microsoft's PipelineGeneralSettings reference documents every
// field here as a plain, always-present boolean with no stated "may be
// null/absent" caveat — there is no sub-object here that could legitimately
// be missing the way EnablementOnCreateSettings could. [fixture-verify]:
// whether a project that has never touched pipeline settings still
// returns every field with a real (non-placeholder) value is unconfirmed
// against a live recorded response, the same open item this epic's own S9
// pass tracks for every other unverified response shape. Two more items
// added to that same S9 list in review, both about checkForkProtection
// specifically: (a) whether the API reports a stored
// enforceNoAccessToSecretsFromForks value at all when the master
// forkProtectionEnabled is off — and if it does, whether that combination
// (master off, sub-setting nominally on) is genuinely the "mixed" partial
// case this collector treats it as, or whether an off master should read
// differently; (b) whether a fresh/never-configured project returns
// buildsEnabledForForks explicitly (true or false) rather than omitting it
// — false-by-omission decoding to the Go zero value would silently
// MANUFACTURE the vector-absent verified-pass checkForkProtection reports
// for buildsEnabledForForks=false, exactly the kind of fabricated-absence
// this epic's own C04 review finding warns against, just for a boolean
// this package chose not to make a *bool (see the plain-bool rationale
// above) on the strength of Microsoft's own field description alone.
//
// C08.actions.self-hosted reads Build Definitions - Get's queue.pool.
// isHosted (TaskAgentPoolReference, verified) for every build definition
// in the project (pipelinehistory.ListPipelines for IDs, a dedicated
// per-definition fetch for queue/pool — a different subset of the same
// endpoint pipelinehistory.FetchBuildDefinition already reads, not
// duplicated there since no existing caller needs both at once), and
// Projects - Get's visibility for the scanned project itself (mirrors
// auditlogging's own resolveProjectID call, adapted to read visibility
// instead of id). Queue and Queue.Pool both decode as pointers: Microsoft's
// own reference gives no guarantee a definition's queue is always
// populated, so a nil here reads as "pool unknown," never a fabricated
// isHosted=false ("self-hosted") — the same absent-object discipline this
// epic's own C04 review finding established for EnablementOnCreateSettings.
// This check has NO verified-fail outcome at all, by design — mirrors the
// GitHub twin's identical choice exactly (self-hosted-runner/pool usage is
// only ever capped at partial on a public project, never a hard fail): a
// private project is always a pass regardless of pool usage (the
// public-fork attack vector this check flags doesn't apply), and an
// unresolved pool on a public project caps at partial alongside a
// confirmed non-hosted one, rather than being silently ignored — an
// evidence gap can't strengthen a pass any more than a confirmed finding
// can weaken a private project's pass.
//
// A project with ZERO build definitions is its own pass, checked ahead of
// visibility — found in review (MEDIUM): the original version fell
// through to the "every definition resolved to a hosted pool" pass text
// even with none, which reads as false when no definition exists at all.
// This is a DELIBERATE divergence from the GitHub twin, which routes its
// own zero-workflow-evidence case to not-checkable
// (sharedNoWorkflowsRubric) instead of a pass: Pipelines - List returning
// an empty array with a 200 for an entire ADO project is a definitive
// enumeration this collector trusts, not the same kind of ambiguous gap a
// GitHub repo's own workflow listing can leave (which can't as cleanly
// rule out "GitHub only returned a partial/broken read"). Treated the same
// way checkForkProtection treats buildsEnabledForForks=false: a confirmed
// absent vector, a genuine pass — see checkSelfHosted's own doc comment.
//
// C08.actions.oidc-vs-secrets reads Endpoints - Get Service Endpoints
// filtered to type=azurerm, scope vso.serviceendpoint. Every
// authorization.scheme comparison is case-insensitive (this project's own
// established default for ADO enum fields — see C09's status-field
// precedent) and defensive: only "workloadidentityfederation" and
// "managedserviceidentity" count as modern; "serviceprincipal" (Azure
// DevOps's own scheme name for a classic App Registration connection,
// which may be either client-secret- or certificate-backed — the REST
// reference's EndpointAuthorization.parameters is opaque/undocumented for
// telling those two apart, so this collector doesn't attempt to; neither
// sub-variant is OIDC/managed-identity, so both count as the fail case)
// counts as a confirmed long-lived-credential fail; anything else
// (including a nil/absent Authorization, or an unrecognized scheme string)
// is the honest "not confirmed either way" partial bucket, never silently
// assumed safe — [fixture-verify]: the exact scheme strings themselves are
// unconfirmed against a live endpoint (the authorization.scheme field
// itself is verified; issue #153's own hedge). Authorization.parameters is
// never given a field to decode into at all, not merely unused — Gets or
// sets the parameters for the selected authorization scheme is opaque
// per-scheme configuration this package must never be able to read into
// memory, structurally, the same discipline auditlogging's own
// consumerInputs omission established for this epic — see
// TestCollect_OIDCvsSecrets_NeverLeaksAuthorizationParameters.
package pipelinesecurity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/collect/azuredevops/pipelinehistory"
	"github.com/sioakim/attestward/internal/model"
)

// collectorID must equal the GitHub twin's Collector string exactly — the
// registry (internal/collect/registry.go's Register) panics if two
// platforms register the same check ID under different Collector strings.
const collectorID = "C08.actions-security"

const (
	idPinned           = "C08.actions.pinned"
	idTokenPermissions = "C08.actions.token-permissions"
	idPRTarget         = "C08.actions.pull-request-target"
	idForkProtection   = "C08.pipelines.fork-protection"
	idOIDC             = "C08.actions.oidc-vs-secrets"
	idSelfHosted       = "C08.actions.self-hosted"
)

// alwaysNotCheckableIDs are the two checks with no API call of their own —
// see the package doc comment.
var alwaysNotCheckableIDs = []string{idPinned, idPRTarget}

var checkIDs = []string{idPinned, idTokenPermissions, idPRTarget, idForkProtection, idOIDC, idSelfHosted}

// checkTitles is allowed to differ from the GitHub twin's wording (epic #34
// open decision 4: same ID, per-platform Title) — pinned/pull-request-
// target are adapted since ADO has no "action"/commit-SHA-pinning
// vocabulary at all; oidc-vs-secrets/self-hosted stay close to the GitHub
// twin's own phrasing, the intent being identical.
var checkTitles = map[string]string{
	idPinned:           "Pipeline tasks are pinned to an immutable version, not a floating major version",
	idTokenPermissions: "Pipeline job tokens are scoped to least privilege",
	idPRTarget:         "No trigger combines base-pipeline privileges with untrusted fork checkout",
	idForkProtection:   "Fork pull request builds are protected from secret access and privilege escalation",
	idOIDC:             "Cloud deployments use workload identity federation or a managed identity, not long-lived static credentials",
	idSelfHosted:       "Self-hosted agent pools are not exposed to public-project pull requests",
}

var checkRemediations = map[string]string{
	idPinned: "No remediation applicable via this tool: Azure Pipelines resolves task references as " +
		"Task@MajorVersion against org-installed task versions — there is no commit-SHA-pinning mechanism to " +
		"move to. If task-version drift is a concern, pin to a specific major version explicitly (never omit " +
		"the @version suffix) and review org-installed task version updates through Azure DevOps' own task " +
		"management.",
	idTokenPermissions: "Project Settings -> Pipelines -> Settings: enable \"Limit job authorization scope to " +
		"current project\" for both build and release pipelines (enforceJobAuthScope, " +
		"enforceJobAuthScopeForReleases), and the setting restricting pipelines to only repositories they " +
		"explicitly reference (enforceReferencedRepoScopedToken).",
	idPRTarget: "No remediation applicable via this tool: Azure Pipelines has no pull_request_target-equivalent " +
		"trigger to reconfigure. If fork pull requests can trigger a privileged build at all, see " +
		"C08.pipelines.fork-protection instead.",
	idForkProtection: "Project Settings -> Pipelines -> Settings: either turn off builds from forked " +
		"repositories entirely (buildsEnabledForForks), or turn on both fork-protection settings " +
		"(forkProtectionEnabled and enforceNoAccessToSecretsFromForks) so a fork's pull request can't access " +
		"secrets or escalate privilege during its build.",
	idOIDC: "Convert each ServicePrincipal-scheme azurerm service connection to workload identity federation " +
		"(Project Settings -> Service connections -> [connection] -> convert to workload identity federation) " +
		"or a managed identity. If a connection's scheme isn't one this collector recognizes, review that " +
		"connection's configuration directly.",
	idSelfHosted: "Only moving affected build definitions to a Microsoft-hosted pool actually clears this " +
		"check on a public project (it looks solely at queue.pool.isHosted, not at build-validation/branch- " +
		"policy approval settings). Real-world exposure can also be reduced without changing this check's " +
		"result: require approval for pull requests from non-team-members, or don't let those definitions " +
		"build fork pull requests at all.",
}

// alwaysNotCheckableReasons is each always-not-checkable check's fixed
// Reason, stated as a direct platform fact rather than echoing the
// Rubric's "always —" framing verbatim — mirrors vdp's/C07's identical
// convention.
var alwaysNotCheckableReasons = map[string]string{
	idPinned: "Azure Pipelines resolves task references as Task@MajorVersion against org-installed task " +
		"versions, not a commit-SHA-pinnable reference — there is no mechanism this tool could ever check for " +
		"a full-SHA pin the way a GitHub Actions `uses:` reference has",
	idPRTarget: "Azure Pipelines has no trigger equivalent to GitHub's pull_request_target (a trigger that " +
		"runs with base-pipeline privileges/secrets against a pull request) — there is nothing this tool " +
		"could ever call to confirm or rule it out; see C08.pipelines.fork-protection for the adjacent real " +
		"ADO control (fork-build protections)",
}

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce — see checks.go for the pass/fail/partial logic
// each rubric below summarizes.
var checkRubrics = map[string]map[model.Status]string{
	idPinned: {
		model.StatusNotCheckable: "always — Azure Pipelines resolves task references as Task@MajorVersion " +
			"against org-installed task versions; there is no commit-SHA-pinning mechanism this tool could " +
			"ever check for",
	},
	idPRTarget: {
		model.StatusNotCheckable: "always — Azure Pipelines has no trigger equivalent to GitHub's " +
			"pull_request_target; see C08.pipelines.fork-protection for the adjacent real ADO control",
	},
	idTokenPermissions: {
		model.StatusVerifiedPass: "enforceJobAuthScope, enforceJobAuthScopeForReleases, and " +
			"enforceReferencedRepoScopedToken are all enabled",
		model.StatusPartial: "one or two, but not all three, of enforceJobAuthScope/" +
			"enforceJobAuthScopeForReleases/enforceReferencedRepoScopedToken are enabled",
		model.StatusVerifiedFail: "none of enforceJobAuthScope, enforceJobAuthScopeForReleases, or " +
			"enforceReferencedRepoScopedToken is enabled",
		model.StatusNotCheckable: sharedGeneralSettingsNotCheckableRubric,
	},
	idForkProtection: {
		model.StatusVerifiedPass: "fork builds are disabled entirely (buildsEnabledForForks is false, the " +
			"attack vector this check flags is absent), or fork builds are enabled and both " +
			"forkProtectionEnabled and enforceNoAccessToSecretsFromForks are on",
		model.StatusPartial: "fork builds are enabled, and exactly one of forkProtectionEnabled/" +
			"enforceNoAccessToSecretsFromForks is on — a mixed, partially-protected configuration",
		model.StatusVerifiedFail: "fork builds are enabled, and neither forkProtectionEnabled nor " +
			"enforceNoAccessToSecretsFromForks is on — a fork's pull request can run pipeline jobs with no " +
			"fork-specific protection at all (this collector's own interpretation of the zero-of-two case, " +
			"not spelled out verbatim in issue #153 — see the package doc comment)",
		model.StatusNotCheckable: sharedGeneralSettingsNotCheckableRubric,
	},
	idOIDC: {
		model.StatusVerifiedPass: "every azurerm service connection's authorization.scheme (case-insensitive) " +
			"is workloadidentityfederation or managedserviceidentity",
		model.StatusPartial: "no connection uses a confirmed long-lived-credential scheme, but at least one " +
			"reports a scheme this collector doesn't recognize as either modern or a known static-secret " +
			"scheme (including a missing/nil authorization) — not confirmed either way",
		model.StatusVerifiedFail: "at least one azurerm service connection's authorization.scheme " +
			"(case-insensitive) is serviceprincipal — Azure DevOps's own scheme name for a classic App " +
			"Registration connection (client-secret- or certificate-backed; this collector doesn't " +
			"distinguish the two — see the package doc comment), never OIDC/managed-identity",
		model.StatusNotCheckable: "the project's azurerm service connections couldn't be read (403/404/" +
			"other API error); or no azurerm service connections exist in this project — nothing to evaluate",
	},
	idSelfHosted: {
		model.StatusVerifiedPass: "the project has zero build definitions at all (a definitive enumeration, " +
			"not an evidence gap — a deliberate divergence from the GitHub twin's own zero-workflow-evidence " +
			"not-checkable; see the package doc comment); or the project is private (the public-fork attack " +
			"vector this check flags doesn't apply, regardless of any definition's own pool); or the project " +
			"is public, but every build definition resolved to a Microsoft-hosted pool",
		model.StatusPartial: "the project is public, and at least one build definition targets a non-hosted " +
			"pool, and/or at least one definition's pool could not be resolved (queue or queue.pool was " +
			"absent from its own Definitions - Get response) — a public contributor's pull request is a " +
			"potential path to a self-hosted pool, or this collector can't confirm otherwise. This check has " +
			"no verified-fail outcome: self-hosted-pool exposure on a public project is only ever capped at " +
			"partial, by design, mirroring the GitHub twin's own identical choice",
		model.StatusNotCheckable: "the project's build definitions couldn't be listed or read (403/404/" +
			"other API error), or the project's own visibility couldn't be read (403/404/other API error)",
	},
}

// sharedGeneralSettingsNotCheckableRubric is shared by token-permissions
// and fork-protection: both read the exact same General Settings - Get
// response, fetched once — see the package doc comment.
const sharedGeneralSettingsNotCheckableRubric = "the project's pipeline general settings couldn't be read " +
	"(403/404/other API error)"

const (
	generalSettingsEndpoint  = "GET dev.azure.com/{org}/{project}/_apis/build/generalsettings"
	serviceEndpointsEndpoint = "GET dev.azure.com/{org}/{project}/_apis/serviceendpoint/endpoints?type=azurerm"
	pipelinesEndpoint        = "GET dev.azure.com/{org}/{project}/_apis/pipelines"
	buildDefinitionEndpoint  = "GET dev.azure.com/{org}/{project}/_apis/build/definitions/{definitionId}"
	projectEndpoint          = "GET dev.azure.com/{org}/_apis/projects/{project}"
)

// checkEndpoints documents only the calls each check's OWN business logic
// reads — mirrors sasthistory's/provenance's identical convention.
// idPinned/idPRTarget are nil: both make no API call at all.
var checkEndpoints = map[string][]string{
	idPinned:           nil,
	idTokenPermissions: {generalSettingsEndpoint},
	idPRTarget:         nil,
	idForkProtection:   {generalSettingsEndpoint},
	idOIDC:             {serviceEndpointsEndpoint},
	idSelfHosted:       {pipelinesEndpoint, buildDefinitionEndpoint, projectEndpoint},
}

var checkTokenScopes = map[string]string{
	idPinned: "none — this check makes no API call of its own; Azure Pipelines has no task-SHA-pinning " +
		"feature to query (see its own doc comment)",
	idTokenPermissions: "vso.project (General Settings - Get — verified against Microsoft's own REST " +
		"reference, surprisingly not vso.build)",
	idPRTarget: "none — this check makes no API call of its own; Azure Pipelines has no pull_request_target-" +
		"equivalent trigger to query (see its own doc comment)",
	idForkProtection: "vso.project (General Settings - Get — same call as C08.actions.token-permissions)",
	idOIDC:           "vso.serviceendpoint (Endpoints - Get Service Endpoints)",
	idSelfHosted:     "vso.build (Pipelines - List, Definitions - Get), vso.project (Projects - Get)",
}

const fixtureRef = "internal/collect/azuredevops/pipelinesecurity/pipelinesecurity_test.go"

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

// Collector implements C08 pipeline-security for Azure DevOps.
type Collector struct {
	client *azuredevops.Client
}

// New returns a C08 collector using client for all API calls. A single
// Client is safe to share across this collector's whole Collect() call —
// mirrors envseparation's identical reasoning: no concurrency, no per-repo
// fan-out, just a short sequence of project-scoped calls.
func New(client *azuredevops.Client) *Collector {
	return &Collector{client: client}
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. It never returns a non-nil
// top-level error: a project-level API failure becomes a not-checkable
// result for the affected check(s). All six results share Scope.Project
// (scope.Repos is never consulted — see the package doc comment for why).
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	always := []model.CheckResult{
		checkPinned(scope.Org, scope.Project),
		checkPullRequestTarget(scope.Org, scope.Project),
	}

	settings, settingsErr := fetchGeneralSettings(ctx, c.client, scope.Project)
	settingsProv := c.client.Provenance()

	endpointsStart := len(c.client.Provenance())
	endpoints, endpointsErr := fetchAzureRMServiceEndpoints(ctx, c.client, scope.Project)
	endpointsProv := tailProvenance(c.client.Provenance(), endpointsStart)

	selfHostedStart := len(c.client.Provenance())
	pools, poolsErr := resolveProjectPools(ctx, c.client, scope.Project)
	visibility, visibilityErr := fetchProjectVisibility(ctx, c.client, scope.Project)
	selfHostedProv := tailProvenance(c.client.Provenance(), selfHostedStart)

	return append(always,
		checkTokenPermissions(scope.Org, scope.Project, settings, settingsErr, settingsProv),
		checkForkProtection(scope.Org, scope.Project, settings, settingsErr, settingsProv),
		checkOIDCvsSecrets(scope.Org, scope.Project, endpoints, endpointsErr, endpointsProv),
		checkSelfHosted(scope.Org, scope.Project, pools, poolsErr, visibility, visibilityErr, selfHostedProv),
	), nil
}

// resolveProjectPools lists every pipeline (build definition) in project
// (pipelinehistory.ListPipelines) and resolves each one's queue/pool via a
// dedicated per-definition fetch (fetchBuildDefinitionPool) — stops at the
// first failure, mirroring envseparation's fetchAllCheckConfigurations: a
// partial result isn't safe to evaluate "every build definition" against,
// since the unreadable one might be exactly the one using a non-hosted pool.
func resolveProjectPools(ctx context.Context, client *azuredevops.Client, project string) ([]poolResolution, error) {
	pipelines, err := pipelinehistory.ListPipelines(ctx, client, project)
	if err != nil {
		return nil, err
	}
	out := make([]poolResolution, 0, len(pipelines))
	for _, p := range pipelines {
		raw, err := fetchBuildDefinitionPool(ctx, client, project, p.ID)
		if err != nil {
			return nil, err
		}
		if raw.Queue == nil || raw.Queue.Pool == nil {
			out = append(out, poolResolution{DefinitionName: p.Name, Resolved: false})
			continue
		}
		out = append(out, poolResolution{DefinitionName: p.Name, IsHosted: raw.Queue.Pool.IsHosted, Resolved: true})
	}
	return out, nil
}

func tailProvenance(prov []model.Provenance, skip int) []model.Provenance {
	if skip >= len(prov) {
		return []model.Provenance{}
	}
	return prov[skip:]
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

func generalSettingsErrorReason(err error) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) {
		switch se.StatusCode {
		case http.StatusForbidden:
			return "token lacks permission to read the project's pipeline general settings"
		case http.StatusNotFound:
			return "project not found, or its pipeline general settings endpoint is unreachable"
		}
	}
	return fmt.Sprintf("could not read pipeline general settings: %v", err)
}

func serviceEndpointsErrorReason(err error) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) {
		switch se.StatusCode {
		case http.StatusForbidden:
			return "token lacks permission to read the project's service endpoints"
		case http.StatusNotFound:
			return "project not found, or its service endpoints endpoint is unreachable"
		}
	}
	return fmt.Sprintf("could not read service endpoints: %v", err)
}

func buildDefinitionsErrorReason(err error) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) {
		switch se.StatusCode {
		case http.StatusForbidden:
			return "token lacks permission to read the project's pipelines or build definitions"
		case http.StatusNotFound:
			return "project not found, or its pipelines/build-definitions endpoint is unreachable"
		}
	}
	return fmt.Sprintf("could not read the project's build definitions: %v", err)
}

func projectVisibilityErrorReason(err error) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) {
		switch se.StatusCode {
		case http.StatusForbidden:
			return "token lacks permission to read the project's own visibility"
		case http.StatusNotFound:
			return "project not found"
		}
	}
	return fmt.Sprintf("could not read the project's visibility: %v", err)
}

// generalSettingsRaw is the subset of Azure DevOps's PipelineGeneralSettings
// shape (General Settings - Get) this package needs — see the package doc
// comment for why every field decodes as plain bool, not *bool.
type generalSettingsRaw struct {
	EnforceJobAuthScope               bool `json:"enforceJobAuthScope"`
	EnforceJobAuthScopeForReleases    bool `json:"enforceJobAuthScopeForReleases"`
	EnforceReferencedRepoScopedToken  bool `json:"enforceReferencedRepoScopedToken"`
	EnforceSettableVar                bool `json:"enforceSettableVar"`
	DisableClassicPipelineCreation    bool `json:"disableClassicPipelineCreation"`
	BuildsEnabledForForks             bool `json:"buildsEnabledForForks"`
	ForkProtectionEnabled             bool `json:"forkProtectionEnabled"`
	EnforceNoAccessToSecretsFromForks bool `json:"enforceNoAccessToSecretsFromForks"`
	EnforceJobAuthScopeForForks       bool `json:"enforceJobAuthScopeForForks"`
}

// fetchGeneralSettings reads the project's pipeline general settings via
// GET dev.azure.com/{org}/{project}/_apis/build/generalsettings (scope
// vso.project — see the package doc comment).
func fetchGeneralSettings(ctx context.Context, client *azuredevops.Client, project string) (generalSettingsRaw, error) {
	path := fmt.Sprintf("/%s/%s/_apis/build/generalsettings", client.Org(), project)
	query := url.Values{"api-version": {"7.1"}}

	var raw generalSettingsRaw
	if err := azuredevops.GetJSONObject(ctx, client, azuredevops.HostCore, path, query, &raw); err != nil {
		return generalSettingsRaw{}, err
	}
	return raw, nil
}

// endpointAuthorizationRaw decodes ONLY the scheme field of Azure DevOps's
// EndpointAuthorization shape — parameters is deliberately never given a
// field to decode into at all, not merely unused — see the package doc
// comment and TestCollect_OIDCvsSecrets_NeverLeaksAuthorizationParameters.
type endpointAuthorizationRaw struct {
	Scheme string `json:"scheme"`
}

// serviceEndpointRaw is the subset of Azure DevOps's ServiceEndpoint shape
// (Endpoints - Get Service Endpoints) this package needs. Authorization is
// *endpointAuthorizationRaw, not a bare struct: a connection missing this
// field entirely reads as "scheme unknown" (the honest partial bucket),
// never a fabricated empty-string scheme silently bucketed as something
// else.
type serviceEndpointRaw struct {
	ID            string                    `json:"id"`
	Name          string                    `json:"name"`
	Type          string                    `json:"type"`
	Authorization *endpointAuthorizationRaw `json:"authorization"`
}

// fetchAzureRMServiceEndpoints lists every azurerm-type service connection
// in project via GET dev.azure.com/{org}/{project}/_apis/serviceendpoint/
// endpoints?type=azurerm (scope vso.serviceendpoint).
func fetchAzureRMServiceEndpoints(ctx context.Context, client *azuredevops.Client, project string) ([]serviceEndpointRaw, error) {
	path := fmt.Sprintf("/%s/%s/_apis/serviceendpoint/endpoints", client.Org(), project)
	query := url.Values{"type": {"azurerm"}, "api-version": {"7.1"}}

	var raw []serviceEndpointRaw
	if err := azuredevops.GetJSON(ctx, client, azuredevops.HostCore, path, query, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// poolResolution is one build definition's resolved (or unresolved) queue
// pool for checkSelfHosted.
type poolResolution struct {
	DefinitionName string
	IsHosted       bool
	// Resolved is false when the definition's own queue or queue.pool was
	// absent from its Definitions - Get response — see the package doc
	// comment for why that must never be read as IsHosted=false.
	Resolved bool
}

// buildDefinitionPoolRaw decodes only the queue/pool subset of Azure
// DevOps's BuildDefinition shape (Definitions - Get) this package needs —
// see the package doc comment for why Queue and Queue.Pool are both
// pointers.
type buildDefinitionPoolRaw struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Queue *struct {
		Pool *struct {
			IsHosted bool   `json:"isHosted"`
			Name     string `json:"name"`
		} `json:"pool"`
	} `json:"queue"`
}

// fetchBuildDefinitionPool fetches one build definition's queue/pool via
// GET dev.azure.com/{org}/{project}/_apis/build/definitions/{definitionId}
// — the same endpoint pipelinehistory.FetchBuildDefinition calls, decoding
// a different subset (see the package doc comment for why this isn't
// hoisted into that shared function).
func fetchBuildDefinitionPool(ctx context.Context, client *azuredevops.Client, project string, definitionID int) (buildDefinitionPoolRaw, error) {
	path := fmt.Sprintf("/%s/%s/_apis/build/definitions/%d", client.Org(), project, definitionID)
	query := url.Values{"api-version": {"7.1"}}

	var raw buildDefinitionPoolRaw
	if err := azuredevops.GetJSONObject(ctx, client, azuredevops.HostCore, path, query, &raw); err != nil {
		return buildDefinitionPoolRaw{}, err
	}
	return raw, nil
}

// projectVisibilityRaw is the subset of Azure DevOps's TeamProject shape
// (Projects - Get) this package needs.
type projectVisibilityRaw struct {
	Visibility string `json:"visibility"`
}

// projectVisibilityPublic is ProjectVisibility's documented "public" value
// — mirrors orgsecurity's identical constant.
const projectVisibilityPublic = "public"

// fetchProjectVisibility reads the scanned project's own visibility via
// GET dev.azure.com/{org}/_apis/projects/{project} (Projects - Get, scope
// vso.project) — mirrors auditlogging's resolveProjectID, adapted to read
// visibility instead of id.
func fetchProjectVisibility(ctx context.Context, client *azuredevops.Client, project string) (string, error) {
	path := fmt.Sprintf("/%s/_apis/projects/%s", client.Org(), url.PathEscape(project))
	query := url.Values{"api-version": {"7.1"}}

	var raw projectVisibilityRaw
	if err := azuredevops.GetJSONObject(ctx, client, azuredevops.HostCore, path, query, &raw); err != nil {
		return "", err
	}
	return raw.Visibility, nil
}

// isPublicVisibility compares case-insensitively — this project's own
// established default for every ADO enum-ish string field (see C09's
// status-field precedent, cited throughout this epic).
func isPublicVisibility(visibility string) bool {
	return strings.EqualFold(visibility, projectVisibilityPublic)
}
