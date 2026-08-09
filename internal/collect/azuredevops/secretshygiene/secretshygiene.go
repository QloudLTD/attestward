// Package secretshygiene implements C04 secrets-hygiene for Azure DevOps —
// the ADO counterpart to internal/collect/github/secretshygiene, plus one
// new ADO-only check with no GitHub twin at all.
//
// Five checks mirror the GitHub twin's check IDs exactly (issue #34's
// check-identity model): C04.secrets.scanning-enabled, C04.secrets.push-
// protection, C04.secrets.advanced-security, and C04.deps.dependabot-alerts
// are per-repo, each derived from GHAzDO (GitHub Advanced Security for
// Azure DevOps)'s Repo Enablement - Get
// (advsec.dev.azure.com/{org}/{project}/_apis/management/repositories/
// {repository}/enablement?includeAllProperties=true, scope vso.advsec) —
// one call per in-scope repo, since resourceId there is a path parameter
// that only ever names one repo at a time, not a project-wide list the way
// C02's policy configurations are. C04.org.security-defaults is org-scoped,
// derived from the equivalent Org Enablement - Get
// (advsec.dev.azure.com/{org}/_apis/management/enablement?
// includeAllProperties=true).
//
// includeAllProperties=true is load-bearing, not decorative: Microsoft's
// own REST reference for SecretProtectionFeatures.blockPushes states "If
// includeAllProperties in the request is false, this value will be null" —
// omitting it silently breaks C04.secrets.push-protection specifically.
// The per-repo fetch itself is not this package's own code: it shares
// internal/collect/azuredevops/pipelinehistory's FetchRepoEnablement with
// C05 sast-history, the concurrent collector that first needed the same
// Repo Enablement - Get endpoint. That shared helper decodes both
// blockPushes and secretProtectionEnabled as *bool, not bool, so a null is
// distinguishable from a confirmed false rather than silently read as
// "off" — see checkPushProtection's and checkScanningEnabled's own doc
// comments. pipelinehistory's own fixture tests (including
// TestFetchRepoEnablement_SendsIncludeAllProperties) regression-guard the
// query parameter itself; this package's tests instead pin the null-vs-
// false behavior end to end through Collect.
//
// C04.vars.secret-hygiene is the new, ADO-only sixth check: Azure DevOps
// variable groups (project-scoped, GET dev.azure.com/{org}/{project}/
// _apis/distributedtask/variablegroups, scope vso.variablegroups_read) can
// store a variable's value in plaintext even when its name looks like it
// should hold a secret (password/token/API key/connection string/etc.) —
// GitHub has no equivalent concept this tool already checks, so there is no
// twin to mirror. This check registers under azuredevops only; it is never
// registered under github, so collect.Register's cross-platform
// Collector-string consistency check never has anything to compare it
// against. Facts record only the offending variable and group NAMES, never
// the stored value — see checkSecretHygiene's own doc comment for the
// sentinel test proving this structurally, the same discipline
// auditlogging's consumerInputs omission and C09's serviceHookSubscriptionRaw
// already established for this epic.
//
// C04.org.security-defaults' own advsec-unavailable path (a 403/404 from
// the org-level enablement query) is reported via azuredevops.IsAdvSecGated
// — but "GHAzDO not licensed for this org/project" is no longer the
// premise behind that path (issue #190): S9's live run (2026-07-23,
// dev.azure.com/seciq, GHAzDO-unlicensed) found the org-level enablement
// query returns HTTP 200 with every enablementOnCreateSettings field false
// for an unlicensed org, not a 403/404 — checkOrgSecurityDefaults correctly
// reads that as a real, verifiable verified-fail, not the ambiguous gated
// path at all. A 403/404 that DOES reach IsAdvSecGated is a genuinely
// different situation now that licensing is ruled out as the cause — see
// IsAdvSecGated's own doc comment and advSecGatedReason below for the
// distinction between what's ruled out (licensing) and what's only the
// most likely remaining explanation, not an observed fact (403: the token
// probably lacks the vso.advsec scope — S9's own scan PAT already carried
// it, so a missing-scope 403 was never actually reachable in that run
// either) versus what remains [fixture-verify] (404: no recorded response
// covers it).
package secretshygiene

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops/pipelinehistory"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// collectorID must equal the GitHub twin's Collector string exactly — the
// registry (internal/collect/registry.go's Register) panics if two
// platforms register the same check ID under different Collector strings.
const collectorID = "C04.secrets-hygiene"

const (
	idScanningEnabled     = "C04.secrets.scanning-enabled"
	idPushProtection      = "C04.secrets.push-protection"
	idAdvancedSecurity    = "C04.secrets.advanced-security"
	idDependabotAlerts    = "C04.deps.dependabot-alerts"
	idOrgSecurityDefaults = "C04.org.security-defaults"
	// idSecretHygiene is the new, ADO-only sixth check — no GitHub twin.
	idSecretHygiene = "C04.vars.secret-hygiene"
)

// repoCheckIDs are the four per-repo checks, in a fixed order — mirrors
// the GitHub twin's identical rationale (an evidence pack should diff
// cleanly across runs of the same scan).
var repoCheckIDs = []string{idScanningEnabled, idPushProtection, idDependabotAlerts, idAdvancedSecurity}

// mirroredCheckIDs are the five checks with a GitHub twin, registered
// under the exact same Collector string as that twin. idSecretHygiene is
// registered separately (see init) since it has no twin to be consistent
// with.
var mirroredCheckIDs = append(append([]string{}, repoCheckIDs...), idOrgSecurityDefaults)

var checkTitles = map[string]string{
	idScanningEnabled:     "Secret scanning (GHAzDO Secret Protection) is active",
	idPushProtection:      "Secret scanning push protection is active",
	idAdvancedSecurity:    "GitHub Advanced Security for Azure DevOps is enabled where applicable",
	idDependabotAlerts:    "Dependency scanning (GHAzDO Code Security) is enabled",
	idOrgSecurityDefaults: "Org enables Code Security/Secret Protection features by default for new repos",
	idSecretHygiene:       "Variable groups don't store sensitive-named variables in plaintext",
}

var checkRemediations = map[string]string{
	idScanningEnabled: "Project Settings -> Repositories -> [repo] -> Security -> GitHub Advanced Security " +
		"-> enable Secret Protection. Requires a GHAzDO Secret Protection license (or the combined GHAzDO " +
		"plan, pre-unbundling).",
	idPushProtection: "With Secret Protection enabled (see C04.secrets.scanning-enabled), also enable " +
		"\"Block pushes that expose secrets\" so a push containing a detected secret is rejected before it lands.",
	idAdvancedSecurity: "Enable both Code Security and Secret Protection for the repo (Project Settings -> " +
		"Repositories -> [repo] -> Security -> GitHub Advanced Security) — post-unbundling GHAzDO is the " +
		"combination of these two plans, not a single toggle.",
	idDependabotAlerts: "Project Settings -> Repositories -> [repo] -> Security -> GitHub Advanced Security " +
		"-> enable Code Security (this enables dependency scanning as part of the Code Security plan).",
	idOrgSecurityDefaults: "Organization Settings -> GitHub Advanced Security -> enable Code Security, " +
		"Secret Protection, block-pushes-on-create, AND dependency-scanning-injection-on-create for newly " +
		"created repositories — all four must be on for this check to pass, so every repo created going " +
		"forward starts protected instead of relying on each repo owner to enable them individually.",
	idSecretHygiene: "Open the flagged variable group (Pipelines -> Library) and mark every offending " +
		"variable (name matching password/passwd/pwd/secret/credential(s)/token/api-key/connstr/connection-" +
		"string) as secret — the padlock icon next to its value — so Azure DevOps encrypts it at rest " +
		"instead of storing it in plaintext.",
}

// sharedRepoFetchFailedRubric is shared by all four per-repo checks — each
// bottoms out at the same Repo Enablement - Get call, before any
// check-specific field read ever runs.
const sharedRepoFetchFailedRubric = "the repo enablement fetch itself failed with a non-licensing error " +
	"(403/404/other API error not attributable to GHAzDO licensing — see the not-checkable entry for the " +
	"advsec-unavailable case specifically)"

// sharedAdvSecGatedRubric is shared by every advsec-backed check (all five
// mirrored checks) — see advSecGatedReason's own doc comment for the full
// story this summarizes (issue #190, updated by issue #225's review): GHAzDO
// not being licensed/enabled is RULED OUT as the cause of a 403/404 reaching
// azuredevops.IsAdvSecGated (observed 2026-07-23 against dev.azure.com/seciq
// — an unlicensed org/project's enablement endpoints read HTTP 200 with
// every flag false/null instead), not an open question the way this text
// used to read. A 403 most likely means the token lacks the vso.advsec
// scope, but that's the most likely remaining explanation, not an observed
// fact — S9's own scan PAT already carried that scope, so a missing-scope
// 403 was never actually reachable in that run; other permission causes
// can't be excluded from the response alone. What actually produces a 404
// remains genuinely unconfirmed [fixture-verify].
const sharedAdvSecGatedRubric = "the call failed with a response azuredevops.IsAdvSecGated treats specially " +
	"(403 or 404) — GHAzDO not being licensed/enabled for this org/project is ruled out as the cause " +
	"(observed 2026-07-23 against dev.azure.com/seciq: an unlicensed org/project's enablement endpoints " +
	"read HTTP 200 with every flag false/null instead, not 403/404 at all); a 403 most likely means the " +
	"token lacks the vso.advsec scope, though other permission causes (tenant conditional access, an IP " +
	"allow-list, project-level denial, an org policy restricting PAT access) can't be excluded from the " +
	"response alone; what actually produces a 404 remains genuinely unconfirmed [fixture-verify] — neither " +
	"is asserted as more than that"

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce. Like the GitHub twin, no check in this package can
// ever produce partial — every one bottoms out at pass, fail, or
// not-checkable.
var checkRubrics = map[string]map[model.Status]string{
	idScanningEnabled: {
		model.StatusVerifiedPass: "secretProtectionFeatures.secretProtectionEnabled is true",
		model.StatusVerifiedFail: "secretProtectionFeatures.secretProtectionEnabled is false",
		model.StatusNotCheckable: sharedRepoFetchFailedRubric + "; or " + sharedAdvSecGatedRubric,
	},
	idPushProtection: {
		model.StatusVerifiedPass: "secretProtectionFeatures.blockPushes is true",
		model.StatusVerifiedFail: "secretProtectionFeatures.blockPushes is false",
		model.StatusNotCheckable: sharedRepoFetchFailedRubric + "; or " + sharedAdvSecGatedRubric + "; or " +
			"the response decoded successfully but blockPushes came back null even though " +
			"includeAllProperties=true was requested — that field is only ever populated with that " +
			"parameter set, so a null here means the request didn't actually carry it, not that push " +
			"protection is off",
	},
	idAdvancedSecurity: {
		model.StatusVerifiedPass: "both codeSecurityFeatures.codeSecurityEnabled and " +
			"secretProtectionFeatures.secretProtectionEnabled are true (post-unbundling GHAzDO is the " +
			"combination of the Code Security and Secret Protection plans)",
		model.StatusVerifiedFail: "codeSecurityEnabled and secretProtectionEnabled are not both true",
		model.StatusNotCheckable: sharedRepoFetchFailedRubric + "; or " + sharedAdvSecGatedRubric,
	},
	idDependabotAlerts: {
		model.StatusVerifiedPass: "codeSecurityFeatures.codeSecurityEnabled is true (dependency scanning is " +
			"part of the Code Security plan)",
		model.StatusVerifiedFail: "codeSecurityFeatures.codeSecurityEnabled is false",
		model.StatusNotCheckable: sharedRepoFetchFailedRubric + "; or " + sharedAdvSecGatedRubric,
	},
	idOrgSecurityDefaults: {
		model.StatusVerifiedPass: "all four of enablementOnCreateSettings.enableCodeSecurityOnCreate, " +
			"enableSecretProtectionOnCreate, enableBlockPushesOnCreate, and " +
			"enableDependencyScanningInjectionOnCreate are true",
		model.StatusVerifiedFail: "at least one of the four on-create-default fields is false",
		model.StatusNotCheckable: "the org enablement fetch failed with a non-licensing error (403/404/other " +
			"API error); or " + sharedAdvSecGatedRubric + "; or the response decoded successfully but omitted " +
			"enablementOnCreateSettings entirely — never assumed to mean every on-create default is off",
	},
	idSecretHygiene: {
		model.StatusVerifiedPass: "no variable across every variable group in the project has both a name " +
			"matching (?i)(password|passwd|pwd|secret|credentials?|token|api[_-]?key|connstr|connection[_-]?" +
			"string) and isSecret absent/false with a non-empty value",
		model.StatusVerifiedFail: "at least one variable with a sensitive-looking name is stored in " +
			"plaintext (isSecret absent/false, value non-empty) — the offending variable and group names " +
			"are recorded in Facts, never the value",
		model.StatusNotCheckable: "the project's variable groups list couldn't be read (403/404/other API error)",
	},
}

// repoEnablementEndpoint and orgEnablementEndpoint document the host inline
// (see internal/collect/azuredevops's own package doc comment) — the query
// parameters are part of the description since includeAllProperties
// changes what the endpoint actually returns (see the package doc comment).
const (
	repoEnablementEndpoint = "GET advsec.dev.azure.com/{org}/{project}/_apis/management/repositories/{repository}/enablement?includeAllProperties=true"
	orgEnablementEndpoint  = "GET advsec.dev.azure.com/{org}/_apis/management/enablement?includeAllProperties=true"
	variableGroupsEndpoint = "GET dev.azure.com/{org}/{project}/_apis/distributedtask/variablegroups"
)

var repoEnablementEndpoints = []string{repoEnablementEndpoint}

var checkEndpoints = map[string][]string{
	idScanningEnabled:     repoEnablementEndpoints,
	idPushProtection:      repoEnablementEndpoints,
	idAdvancedSecurity:    repoEnablementEndpoints,
	idDependabotAlerts:    repoEnablementEndpoints,
	idOrgSecurityDefaults: {orgEnablementEndpoint},
	idSecretHygiene:       {variableGroupsEndpoint},
}

var checkTokenScopes = map[string]string{
	idScanningEnabled:     "vso.advsec (Repo Enablement - Get)",
	idPushProtection:      "vso.advsec (Repo Enablement - Get)",
	idAdvancedSecurity:    "vso.advsec (Repo Enablement - Get)",
	idDependabotAlerts:    "vso.advsec (Repo Enablement - Get)",
	idOrgSecurityDefaults: "vso.advsec (Org Enablement - Get)",
	idSecretHygiene:       "vso.variablegroups_read (Variable Groups - Get Variable Groups)",
}

const fixtureRef = "internal/collect/azuredevops/secretshygiene/secretshygiene_test.go"

func init() {
	for _, id := range mirroredCheckIDs {
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
	// idSecretHygiene has no GitHub twin at all, so it's registered
	// separately from mirroredCheckIDs above — see its own const doc
	// comment. It's project-scoped (variable groups, not org-wide) — see
	// CheckMeta.ScopeLevel (#176).
	collect.Register(collect.CheckMeta{
		ID:          idSecretHygiene,
		Platform:    "azuredevops",
		Title:       checkTitles[idSecretHygiene],
		Collector:   collectorID,
		TokenScope:  checkTokenScopes[idSecretHygiene],
		Remediation: checkRemediations[idSecretHygiene],
		Rubric:      checkRubrics[idSecretHygiene],
		Endpoints:   checkEndpoints[idSecretHygiene],
		FixtureRef:  fixtureRef,
		ScopeLevel:  collect.ScopeLevelProject,
	})
}

// Collector implements C04 secrets-hygiene for Azure DevOps.
type Collector struct {
	org, pat string

	// newClientForTest overrides how each Client is constructed — see
	// internal/collect/azuredevops/vdp.Collector's identical field for why
	// a collector spanning org/project/repo scope needs this rather than a
	// single pre-built Client.
	newClientForTest func(org, pat string) *azuredevops.Client
}

// New returns a C04 collector authenticated with pat against org. Like C10
// vdp, this takes (org, pat) rather than a pre-built *azuredevops.Client:
// this collector spans three scope levels in one Collect() call (org,
// project, and per-repo), and each gets its own fresh Client so
// Client.Provenance() stays scoped to what actually backs that level's
// result(s) — never a shared log another level's calls could pollute.
func New(org, pat string) *Collector {
	return &Collector{org: org, pat: pat}
}

func (c *Collector) newClient() *azuredevops.Client {
	if c.newClientForTest != nil {
		return c.newClientForTest(c.org, c.pat)
	}
	return azuredevops.NewClient(c.org, c.pat)
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. It never returns a non-nil
// top-level error for an API failure — see C01 org-security's Collect doc
// comment for why that matters for the rollup.
//
// Repos are processed sequentially, not fanned out concurrently — mirrors
// C10 vdp's identical choice: internal/collect/azuredevops has no
// ForEachRepo-equivalent helper yet, and adding one to the shared
// foundation package for these two callers alone was judged out of scope.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	orgClient := c.newClient()
	orgResult := checkOrgSecurityDefaults(ctx, orgClient, scope.Org)

	projClient := c.newClient()
	varsResult := checkSecretHygiene(ctx, projClient, scope.Org, scope.Project)

	all := []model.CheckResult{orgResult, varsResult}

	for _, repo := range scope.Repos {
		if ctx.Err() != nil {
			reason := fmt.Sprintf("scan canceled before this repo's checks ran: %v", ctx.Err())
			all = append(all, allRepoNotCheckable(scope.Org, scope.Project, repo, reason, []model.Provenance{})...)
			continue
		}
		client := c.newClient()
		all = append(all, collectRepo(ctx, client, scope.Org, scope.Project, repo)...)
	}
	return all, nil
}

// collectRepo resolves one repo's GHAzDO enablement — via
// pipelinehistory.FetchRepoEnablement, shared with C05 sast-history rather
// than duplicated locally, see the package doc comment — and emits the
// four per-repo CheckResults. It never returns an error; every failure
// becomes a not-checkable result for all four, distinguishing an
// advsec-licensing gap (azuredevops.IsAdvSecGated) from a genuine API error
// — see the package doc comment for the [fixture-verify] hedge this
// distinction rests on.
func collectRepo(ctx context.Context, client *azuredevops.Client, org, project, repo string) []model.CheckResult {
	info, err := pipelinehistory.FetchRepoEnablement(ctx, client, project, repo)
	prov := client.Provenance()
	if err != nil {
		if isAdvSecGated(err) {
			return allRepoNotCheckable(org, project, repo, advSecGatedReason(err, fmt.Sprintf("repo %q", repo)), prov)
		}
		return allRepoNotCheckable(org, project, repo, apiErrorReason(err, fmt.Sprintf("repo enablement for %q", repo)), prov)
	}

	return []model.CheckResult{
		checkScanningEnabled(org, project, repo, info, prov),
		checkPushProtection(org, project, repo, info, prov),
		checkDependabotAlerts(org, project, repo, info, prov),
		checkAdvancedSecurity(org, project, repo, info, prov),
	}
}

// checkScanningEnabled treats a nil SecretProtectionEnabled as
// not-checkable, never as a fabricated false — pipelinehistory.
// RepoEnablementInfo decodes it as *bool precisely so this distinction is
// possible, the same discipline checkPushProtection's own doc comment
// describes for BlockPushes. This collector always requests
// includeAllProperties=true, so a nil here in production would mean
// something unexpected happened between the request and the response, not
// a genuine "off" state.
func checkScanningEnabled(org, project, repo string, info pipelinehistory.RepoEnablementInfo, prov []model.Provenance) model.CheckResult {
	const id = idScanningEnabled
	if info.SecretProtectionEnabled == nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "secretProtectionEnabled came back null even though includeAllProperties=true was requested — " +
				"a null here means the request didn't actually carry it, not that secret scanning is off",
			Scope: model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: prov,
		}
	}
	status, reason := model.StatusVerifiedFail, "secret scanning (Secret Protection) is not enabled"
	if *info.SecretProtectionEnabled {
		status, reason = model.StatusVerifiedPass, "secret scanning (Secret Protection) is enabled"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"secret_protection_enabled": *info.SecretProtectionEnabled},
	}
}

// checkPushProtection treats a nil BlockPushes as not-checkable, never as
// a fabricated false — see checkScanningEnabled's own doc comment for the
// same distinction on SecretProtectionEnabled. This collector always
// requests includeAllProperties=true, so a nil here in production would
// mean something unexpected happened between the request and the
// response, not a genuine "off" state.
func checkPushProtection(org, project, repo string, info pipelinehistory.RepoEnablementInfo, prov []model.Provenance) model.CheckResult {
	const id = idPushProtection
	if info.BlockPushes == nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "blockPushes came back null even though includeAllProperties=true was requested — " +
				"Microsoft's own REST reference documents this field as null only when that parameter is " +
				"false, so a null here means the request didn't actually carry it, not that push protection is off",
			Scope: model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: prov,
		}
	}
	status, reason := model.StatusVerifiedFail, "push protection (blocking pushes that contain secrets) is not enabled"
	if *info.BlockPushes {
		status, reason = model.StatusVerifiedPass, "push protection (blocking pushes that contain secrets) is enabled"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"block_pushes": *info.BlockPushes},
	}
}

// checkAdvancedSecurity mirrors checkScanningEnabled's nil-guard: a nil
// SecretProtectionEnabled must never be read as a confirmed false half of
// the AND, or this check would fabricate a verified-fail against an
// unknown (not a disabled) secret-protection state.
func checkAdvancedSecurity(org, project, repo string, info pipelinehistory.RepoEnablementInfo, prov []model.Provenance) model.CheckResult {
	const id = idAdvancedSecurity
	if info.SecretProtectionEnabled == nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "secretProtectionEnabled came back null even though includeAllProperties=true was requested — " +
				"a null here means the request didn't actually carry it, not that GitHub Advanced Security for " +
				"Azure DevOps is disabled",
			Scope: model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: prov,
		}
	}
	enabled := info.CodeSecurityEnabled && *info.SecretProtectionEnabled
	status, reason := model.StatusVerifiedFail, "GitHub Advanced Security for Azure DevOps is not fully "+
		"enabled — codeSecurityEnabled and secretProtectionEnabled are not both true"
	if enabled {
		status, reason = model.StatusVerifiedPass, "GitHub Advanced Security for Azure DevOps is enabled "+
			"(both Code Security and Secret Protection are active)"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"code_security_enabled":     info.CodeSecurityEnabled,
			"secret_protection_enabled": *info.SecretProtectionEnabled,
		},
	}
}

func checkDependabotAlerts(org, project, repo string, info pipelinehistory.RepoEnablementInfo, prov []model.Provenance) model.CheckResult {
	const id = idDependabotAlerts
	status, reason := model.StatusVerifiedFail, "dependency scanning (GHAzDO Code Security) is not enabled"
	if info.CodeSecurityEnabled {
		status, reason = model.StatusVerifiedPass, "dependency scanning (GHAzDO Code Security) is enabled"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Project: project, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"code_security_enabled": info.CodeSecurityEnabled},
	}
}

// enablementOnCreateSettingsRaw is Azure DevOps's EnablementOnCreateSettings
// shape (Org Enablement - Get) — the org's auto-enable-for-new-repos
// policy, distinct from the org's own live enablement state.
type enablementOnCreateSettingsRaw struct {
	EnableCodeSecurityOnCreate                bool `json:"enableCodeSecurityOnCreate"`
	EnableSecretProtectionOnCreate            bool `json:"enableSecretProtectionOnCreate"`
	EnableBlockPushesOnCreate                 bool `json:"enableBlockPushesOnCreate"`
	EnableDependencyScanningInjectionOnCreate bool `json:"enableDependencyScanningInjectionOnCreate"`
	EnableCodeQLOnCreate                      bool `json:"enableCodeQLOnCreate"`
	EnableDependabotOnCreate                  bool `json:"enableDependabotOnCreate"`
}

// orgEnablementRaw is the subset of Azure DevOps's OrgEnablementSettings
// shape this package needs. codeSecurityFeatures/secretProtectionFeatures/
// reposEnablementStatus (the org's own live state, and a per-repo list) are
// omitted — C04.org.security-defaults asks only about the on-create
// defaults, not the org's current live enablement.
//
// EnablementOnCreateSettings is *enablementOnCreateSettingsRaw, not a bare
// struct: a 200 response whose body omits the whole object (or sends it as
// JSON null) must be told apart from one that includes it with every flag
// genuinely false. A bare struct field can't make that distinction —
// encoding/json leaves it at its zero value (every nested bool false)
// either way, which would make checkOrgSecurityDefaults fabricate a
// verified-fail ("not every security feature is enabled") against zero
// actual evidence. The GitHub twin guards its own exact analog (all four
// of its on-create fields nil) the same way; see checkOrgSecurityDefaults'
// own nil check below.
type orgEnablementRaw struct {
	EnablementOnCreateSettings *enablementOnCreateSettingsRaw `json:"enablementOnCreateSettings"`
}

// fetchOrgEnablement reads GHAzDO's org-level enablement state via GET
// advsec.dev.azure.com/{org}/_apis/management/enablement?
// includeAllProperties=true (scope vso.advsec) — org-scoped, no project in
// the path.
func fetchOrgEnablement(ctx context.Context, client *azuredevops.Client) (orgEnablementRaw, error) {
	path := fmt.Sprintf("/%s/_apis/management/enablement", client.Org())
	query := url.Values{"includeAllProperties": {"true"}, "api-version": {"7.2-preview.3"}}

	var raw orgEnablementRaw
	if err := azuredevops.GetJSONObject(ctx, client, azuredevops.HostAdvSec, path, query, &raw); err != nil {
		return orgEnablementRaw{}, err
	}
	return raw, nil
}

// checkOrgSecurityDefaults mirrors the GitHub twin's four-flag AND rule —
// all four on-create defaults must be true to pass. enableCodeQLOnCreate
// and enableDependabotOnCreate are recorded as Facts only, per issue #151's
// own spec: they're informative context (what auto-enables once Code
// Security itself is on), not part of the pass/fail gate.
func checkOrgSecurityDefaults(ctx context.Context, client *azuredevops.Client, org string) model.CheckResult {
	const id = idOrgSecurityDefaults
	settings, err := fetchOrgEnablement(ctx, client)
	prov := client.Provenance()
	if err != nil {
		if isAdvSecGated(err) {
			return model.CheckResult{
				CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
				Reason: advSecGatedReason(err, fmt.Sprintf("org %q", org)),
				Scope:  model.ScopeRef{Org: org}, Provenance: prov,
			}
		}
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: apiErrorReason(err, fmt.Sprintf("org enablement for %q", org)),
			Scope:  model.ScopeRef{Org: org}, Provenance: prov,
		}
	}

	if settings.EnablementOnCreateSettings == nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("the org enablement response for %q didn't include enablementOnCreateSettings "+
				"at all — never assumed to mean every on-create default is off", org),
			Scope: model.ScopeRef{Org: org}, Provenance: prov,
		}
	}

	s := *settings.EnablementOnCreateSettings
	facts := map[string]any{
		"enable_code_security_on_create":                 s.EnableCodeSecurityOnCreate,
		"enable_secret_protection_on_create":             s.EnableSecretProtectionOnCreate,
		"enable_block_pushes_on_create":                  s.EnableBlockPushesOnCreate,
		"enable_dependency_scanning_injection_on_create": s.EnableDependencyScanningInjectionOnCreate,
		"enable_codeql_on_create":                        s.EnableCodeQLOnCreate,
		"enable_dependabot_on_create":                    s.EnableDependabotOnCreate,
	}

	status, reason := model.StatusVerifiedFail, "not every security feature is enabled by default for new repositories"
	if s.EnableCodeSecurityOnCreate && s.EnableSecretProtectionOnCreate && s.EnableBlockPushesOnCreate && s.EnableDependencyScanningInjectionOnCreate {
		status, reason = model.StatusVerifiedPass, "every security feature is enabled by default for new repositories"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org}, Provenance: prov, Facts: facts,
	}
}

// SensitiveVariableNameRE matches variable names that look like they should
// hold a secret. Exported and package-level (unlike almost everything else
// in this package) specifically so a future GitHub variable-store analog of
// this check could reuse it verbatim rather than forking a second copy —
// no such collector exists yet and none is being added here (speculative
// abstraction is out of scope), this is just leaving the door open.
//
// v2 (issue #181, superseding v1's issue #151 pattern): v1 was internally
// inconsistent — api[_-]?key tolerated a separator but connectionstring
// didn't, so CONNECTION_STRING/connection-string (the dominant real-world
// spelling) never matched. v2 applies [_-]? separator tolerance uniformly
// to every multi-word stem (api[_-]?key, connection[_-]?string) and adds
// the missing common stems pwd, credential(s), and connstr.
//
// This is deliberately a broad substring match, not a word-boundaried one:
// a name like tokenizer_config still matches "token" and is meant to —
// coverage is traded for some false positives, and checkSecretHygiene
// always records the exact offending variable/group name in Facts so a
// false positive is trivial to triage.
var SensitiveVariableNameRE = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|credentials?|token|api[_-]?key|connstr|connection[_-]?string)`)

// variableValueRaw is Azure DevOps's VariableValue shape (one entry of a
// VariableGroup's variables map). Value is read only to test for
// non-emptiness and is NEVER copied into a CheckResult's Facts anywhere in
// this package — see checkSecretHygiene's own doc comment for the
// structural (not just discipline-based) guarantee and its sentinel test.
type variableValueRaw struct {
	Value    string `json:"value"`
	IsSecret bool   `json:"isSecret"`
}

// variableGroupRaw is the subset of Azure DevOps's VariableGroup shape
// (Variable Groups - Get Variable Groups) this package needs. createdBy/
// modifiedBy (IdentityRef — real names/emails/GUIDs) are deliberately
// omitted entirely, the same discipline this whole epic applies to
// identity-bearing response fields.
type variableGroupRaw struct {
	Name      string                      `json:"name"`
	Variables map[string]variableValueRaw `json:"variables"`
}

// fetchVariableGroups lists every variable group in project via GET
// dev.azure.com/{org}/{project}/_apis/distributedtask/variablegroups
// (scope vso.variablegroups_read).
func fetchVariableGroups(ctx context.Context, client *azuredevops.Client, project string) ([]variableGroupRaw, error) {
	path := fmt.Sprintf("/%s/%s/_apis/distributedtask/variablegroups", client.Org(), project)
	query := url.Values{"api-version": {"7.1"}}

	var raw []variableGroupRaw
	if err := azuredevops.GetJSON(ctx, client, azuredevops.HostCore, path, query, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// offendingVariable names one plaintext-stored, sensitive-named variable —
// group and variable NAME only, deliberately no Value field on this type
// at all, so there is nothing for a caller to accidentally forward into
// Facts even by a future refactor.
type offendingVariable struct {
	GroupName    string
	VariableName string
}

// checkSecretHygiene is C04.vars.secret-hygiene, the new ADO-only check —
// see the package doc comment for why no GitHub twin exists. A variable
// counts as plaintext-and-sensitive when its name matches
// SensitiveVariableNameRE, IsSecret is false (Azure DevOps's own zero
// value when absent from the response — encrypted variables are the ones
// documented as explicitly true), and Value is non-empty (an empty value
// stores nothing worth flagging regardless of the name). Facts record
// only offendingVariable's GroupName/VariableName fields, never Value —
// TestCollect_SecretHygiene_NeverLeaksVariableValues is this check's
// sentinel test, the same discipline C09 audit-logging's consumerInputs
// omission established for this epic: proving a distinctive real value
// never appears anywhere in the marshaled result, not just that this
// function's own code doesn't reference it.
func checkSecretHygiene(ctx context.Context, client *azuredevops.Client, org, project string) model.CheckResult {
	const id = idSecretHygiene
	groups, err := fetchVariableGroups(ctx, client, project)
	prov := client.Provenance()
	if err != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: apiErrorReason(err, fmt.Sprintf("variable groups for project %q", project)),
			Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov,
		}
	}

	var offending []offendingVariable
	for _, g := range groups {
		for varName, v := range g.Variables {
			if !SensitiveVariableNameRE.MatchString(varName) {
				continue
			}
			if v.IsSecret {
				continue // encrypted at rest — not plaintext, regardless of name
			}
			if v.Value == "" {
				continue // nothing stored
			}
			offending = append(offending, offendingVariable{GroupName: g.Name, VariableName: varName})
		}
	}
	sort.Slice(offending, func(i, j int) bool {
		if offending[i].GroupName != offending[j].GroupName {
			return offending[i].GroupName < offending[j].GroupName
		}
		return offending[i].VariableName < offending[j].VariableName
	})

	factOffending := make([]map[string]any, 0, len(offending))
	for _, o := range offending {
		factOffending = append(factOffending, map[string]any{"group_name": o.GroupName, "variable_name": o.VariableName})
	}
	facts := map[string]any{"offending_variables": factOffending, "offending_count": len(offending)}

	if len(offending) > 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: fmt.Sprintf("%d sensitive-named variable(s) are stored in plaintext across this "+
				"project's variable groups — see Facts.offending_variables for the group/variable names, "+
				"never the values", len(offending)),
			Scope: model.ScopeRef{Org: org, Project: project}, Provenance: prov, Facts: facts,
		}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
		Reason: "no sensitive-named variable is stored in plaintext across this project's variable groups",
		Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov, Facts: facts,
	}
}

// isAdvSecGated reports whether err is a *azuredevops.StatusError whose
// status code azuredevops.IsAdvSecGated treats as "GHAzDO isn't
// licensed/enabled for this org/project" — see the package doc comment for
// the [fixture-verify] hedge this rests on.
func isAdvSecGated(err error) bool {
	var se *azuredevops.StatusError
	return errors.As(err, &se) && azuredevops.IsAdvSecGated(se.StatusCode)
}

// advSecGatedReason names what a 403/404 from an org- or repo-level
// enablement query means now that S9's live run settled the licensing
// question (issue #190): observed 2026-07-23 against dev.azure.com/seciq
// (GHAzDO-unlicensed), both the org-level (management/enablement) and
// repo-level (management/repositories/{repo}/enablement) endpoints
// returned HTTP 200 with every enablement flag false/null, NOT a 403/404 —
// see checkOrgSecurityDefaults and collectRepo, both of which report that
// case as a real verified-fail rather than routing through this function
// at all. So a 403/404 that DOES reach here is no longer read as "maybe
// unlicensed" — but that's narrower than it first looks (issue #225
// review): S9's own scan PAT already carried vso.advsec, so a
// missing-scope 403 was never actually reachable in that run either. What's
// confirmed is only that licensing ISN'T the cause; "the token lacks the
// vso.advsec scope" is the most likely remaining explanation for a 403, not
// an observed fact — other permission causes (tenant conditional access, an
// IP allow-list, project-level denial, an org policy restricting PAT
// access) can't be excluded from the response alone. 404 remains genuinely
// unconfirmed. The returned strings below stay citation-free on purpose:
// they land in a specific customer's own Reason (evidence.json/report.md),
// and naming a third party's org/date there would be confusing at best,
// leaking at worst — the citation belongs here and in the generated
// rubric (sharedAdvSecGatedRubric), not in a customer's signed pack.
func advSecGatedReason(err error, what string) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) {
		switch se.StatusCode {
		case http.StatusForbidden:
			return fmt.Sprintf("most likely the token lacks the vso.advsec scope needed to read %s's GHAzDO "+
				"enablement (403) — licensing is ruled out as the cause (an unlicensed org/project's "+
				"enablement endpoint reads HTTP 200, not 403); other permission causes can't be excluded "+
				"from the response alone", what)
		case http.StatusNotFound:
			return fmt.Sprintf("GHAzDO enablement query for %s returned 404 — the cause is unconfirmed: "+
				"an unlicensed org/project reads HTTP 200 with every flag false instead, so licensing is "+
				"not a likely explanation for a 404 here — what actually produces one remains open "+
				"[fixture-verify]", what)
		}
	}
	return fmt.Sprintf("GHAzDO enablement query for %s failed: %v", what, err)
}

// apiErrorReason turns a non-advsec-gated failure into a Reason string,
// naming the exact permission/existence problem when err is a
// *azuredevops.StatusError with a 403 or 404 status — mirrors
// orgsecurity's/repoprotection's identical helper (kept as a package-local
// copy rather than shared, this codebase's existing convention for small
// per-package helpers like this).
func apiErrorReason(err error, what string) string {
	var statusErr *azuredevops.StatusError
	if errors.As(err, &statusErr) {
		switch statusErr.StatusCode {
		case http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to read %s (403)", what)
		case http.StatusNotFound:
			return fmt.Sprintf("%s not found (404) — it may not exist, or is unreachable", what)
		}
	}
	return fmt.Sprintf("could not read %s: %v", what, err)
}

func allRepoNotCheckable(org, project, repo, reason string, prov []model.Provenance) []model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	out := make([]model.CheckResult, 0, len(repoCheckIDs))
	for _, id := range repoCheckIDs {
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
