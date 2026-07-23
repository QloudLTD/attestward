package pipelinesecurity

import (
	"fmt"
	"strings"

	"github.com/sioakim/attestward/internal/model"
)

// checkPinned always returns not-checkable with no API call at all — see
// the package doc comment. Callers must get this exact result regardless
// of any other evidence gathered in Collect.
func checkPinned(org, project string) model.CheckResult {
	const id = idPinned
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: alwaysNotCheckableReasons[id],
		Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: []model.Provenance{},
	}
}

// checkPullRequestTarget always returns not-checkable with no API call at
// all — see the package doc comment.
func checkPullRequestTarget(org, project string) model.CheckResult {
	const id = idPRTarget
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: alwaysNotCheckableReasons[id],
		Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: []model.Provenance{},
	}
}

// checkTokenPermissions implements the issue's exact three-way rule: all
// three enforce* settings on is a pass, none on is a fail, anything in
// between is partial. enforceSettableVar/disableClassicPipelineCreation
// are informational Facts only, per the issue's own spec — they don't
// drive this check's own verdict.
func checkTokenPermissions(org, project string, settings generalSettingsRaw, err error, prov []model.Provenance) model.CheckResult {
	const id = idTokenPermissions
	if err != nil {
		return notCheckableResult(id, org, project, generalSettingsErrorReason(err), prov)
	}

	enforced := 0
	var missing []string
	if settings.EnforceJobAuthScope {
		enforced++
	} else {
		missing = append(missing, "enforceJobAuthScope")
	}
	if settings.EnforceJobAuthScopeForReleases {
		enforced++
	} else {
		missing = append(missing, "enforceJobAuthScopeForReleases")
	}
	if settings.EnforceReferencedRepoScopedToken {
		enforced++
	} else {
		missing = append(missing, "enforceReferencedRepoScopedToken")
	}

	status := model.StatusVerifiedFail
	reason := "none of enforceJobAuthScope, enforceJobAuthScopeForReleases, or enforceReferencedRepoScopedToken is enabled — pipeline job tokens are not scoped to least privilege"
	switch {
	case enforced == 3:
		status = model.StatusVerifiedPass
		reason = "enforceJobAuthScope, enforceJobAuthScopeForReleases, and enforceReferencedRepoScopedToken are all enabled"
	case enforced > 0:
		status = model.StatusPartial
		// missing names the specific flag(s) still off — found in review:
		// an operator's first question is "which one," not just "how many."
		reason = fmt.Sprintf("%d of 3 least-privilege job-token settings are enabled, but still missing: %s", enforced, strings.Join(missing, ", "))
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Project: project}, Provenance: prov,
		Facts: map[string]any{
			"enforce_job_auth_scope":               settings.EnforceJobAuthScope,
			"enforce_job_auth_scope_for_releases":  settings.EnforceJobAuthScopeForReleases,
			"enforce_referenced_repo_scoped_token": settings.EnforceReferencedRepoScopedToken,
			"enforce_settable_var":                 settings.EnforceSettableVar,
			"disable_classic_pipeline_creation":    settings.DisableClassicPipelineCreation,
		},
	}
}

// checkForkProtection implements the issue's stated semantics for its two
// named outcomes (pass when both fork-protection settings are on, or when
// fork builds are disabled entirely; partial for "mixed" — exactly one
// on) plus this collector's own interpretation of the unnamed zero-of-two
// case as verified-fail — see the package doc comment for why.
// enforceJobAuthScopeForForks is Facts-only, per the issue's own spec.
func checkForkProtection(org, project string, settings generalSettingsRaw, err error, prov []model.Provenance) model.CheckResult {
	const id = idForkProtection
	if err != nil {
		return notCheckableResult(id, org, project, generalSettingsErrorReason(err), prov)
	}

	facts := map[string]any{
		"builds_enabled_for_forks":                settings.BuildsEnabledForForks,
		"fork_protection_enabled":                 settings.ForkProtectionEnabled,
		"enforce_no_access_to_secrets_from_forks": settings.EnforceNoAccessToSecretsFromForks,
		"enforce_job_auth_scope_for_forks":        settings.EnforceJobAuthScopeForForks,
	}

	if !settings.BuildsEnabledForForks {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
			Reason: "fork builds are disabled entirely (buildsEnabledForForks is false) — the fork-build attack vector this check flags doesn't apply",
			Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov, Facts: facts,
		}
	}

	enforced := 0
	if settings.ForkProtectionEnabled {
		enforced++
	}
	if settings.EnforceNoAccessToSecretsFromForks {
		enforced++
	}

	status := model.StatusVerifiedFail
	reason := "fork builds are enabled, and neither forkProtectionEnabled nor enforceNoAccessToSecretsFromForks is on — a fork's pull request can run pipeline jobs with no fork-specific protection at all"
	switch enforced {
	case 2:
		status = model.StatusVerifiedPass
		reason = "fork builds are enabled, but both forkProtectionEnabled and enforceNoAccessToSecretsFromForks are on"
	case 1:
		status = model.StatusPartial
		// Names the specific flag that's still off, not just "one of two" —
		// found in review: an operator's first question is which one.
		stillOff := "enforceNoAccessToSecretsFromForks"
		if !settings.ForkProtectionEnabled {
			stillOff = "forkProtectionEnabled"
		}
		reason = fmt.Sprintf("fork builds are enabled, and %s is still off (the other fork-protection setting is on) — a mixed, partially-protected configuration", stillOff)
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Project: project}, Provenance: prov, Facts: facts,
	}
}

// Recognized authorization.scheme values (case-insensitive comparison) —
// see the package doc comment for why serviceprincipal doesn't distinguish
// a client-secret- from a certificate-backed connection.
const (
	schemeWorkloadIdentityFederation = "workloadidentityfederation"
	schemeManagedServiceIdentity     = "managedserviceidentity"
	schemeServicePrincipal           = "serviceprincipal"
)

// checkOIDCvsSecrets buckets every azurerm connection into modern
// (workload identity federation/managed identity), a confirmed long-lived
// static credential (serviceprincipal), or the honest "unknown" bucket
// (an unrecognized scheme string, or a nil/absent Authorization) — see the
// package doc comment for the full rationale. A single confirmed
// serviceprincipal connection always wins over any unknown-scheme
// connection: a real, named violation is never softened by an unrelated
// ambiguity elsewhere.
func checkOIDCvsSecrets(org, project string, endpoints []serviceEndpointRaw, err error, prov []model.Provenance) model.CheckResult {
	const id = idOIDC
	if err != nil {
		return notCheckableResult(id, org, project, serviceEndpointsErrorReason(err), prov)
	}
	if len(endpoints) == 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "no azurerm service connections exist in this project — nothing to evaluate",
			Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov,
		}
	}

	var modernAuth, staticSecret, unknownScheme []string
	for _, ep := range endpoints {
		scheme := ""
		if ep.Authorization != nil {
			scheme = strings.ToLower(strings.TrimSpace(ep.Authorization.Scheme))
		}
		switch scheme {
		case schemeWorkloadIdentityFederation, schemeManagedServiceIdentity:
			modernAuth = append(modernAuth, ep.Name)
		case schemeServicePrincipal:
			staticSecret = append(staticSecret, ep.Name)
		default:
			unknownScheme = append(unknownScheme, ep.Name)
		}
	}

	facts := map[string]any{
		"modern_auth_connections":    modernAuth,
		"static_secret_connections":  staticSecret,
		"unknown_scheme_connections": unknownScheme,
	}

	switch {
	case len(staticSecret) > 0:
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: fmt.Sprintf("%d azurerm connection(s) use a serviceprincipal authorization scheme (a client-secret- or certificate-backed long-lived credential, not OIDC/managed-identity): %v", len(staticSecret), staticSecret),
			Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov, Facts: facts,
		}
	case len(unknownScheme) > 0:
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusPartial,
			Reason: fmt.Sprintf("%d azurerm connection(s) report an authorization scheme (or a missing authorization) this collector doesn't recognize as either modern or a known static-secret scheme: %v — not confirmed either way", len(unknownScheme), unknownScheme),
			Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov, Facts: facts,
		}
	default:
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
			Reason: fmt.Sprintf("every azurerm connection (%d) uses workload identity federation or a managed identity, not a long-lived static credential", len(modernAuth)),
			Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov, Facts: facts,
		}
	}
}

// checkSelfHosted has no verified-fail outcome at all, by design — see the
// package doc comment. A private project is always a pass regardless of
// pool usage; on a public project, any non-hosted or unresolved pool caps
// the result at partial rather than either a hard fail or a silently
// ignored gap.
//
// len(pools) == 0 (the project has zero build definitions at all) is its
// own pass, checked before visibility — found in review: the earlier
// version fell through to the "every build definition resolved to a
// Microsoft-hosted pool" pass text even with zero definitions, which is
// false as written when none exist. Azure DevOps's Pipelines - List
// returning an empty array with a 200 is a definitive enumeration, not an
// evidence gap, so this collector treats it the same way it treats
// buildsEnabledForForks=false in checkForkProtection: the vector is
// confirmed absent, a genuine pass. This is a DELIBERATE divergence from
// the GitHub twin, which routes its own zero-workflow-evidence case to
// not-checkable instead (sharedNoWorkflowsRubric) — that's because a
// GitHub repo's workflow listing can itself fail to distinguish "really
// has none" from "GitHub returned a partial/broken read," while ADO's
// Pipelines - List for an entire project returning zero results is not
// ambiguous in the same way.
func checkSelfHosted(org, project string, pools []poolResolution, poolsErr error, visibility string, visibilityErr error, prov []model.Provenance) model.CheckResult {
	const id = idSelfHosted
	if poolsErr != nil {
		return notCheckableResult(id, org, project, buildDefinitionsErrorReason(poolsErr), prov)
	}
	if visibilityErr != nil {
		return notCheckableResult(id, org, project, projectVisibilityErrorReason(visibilityErr), prov)
	}

	var nonHosted, unresolved []string
	for _, p := range pools {
		if !p.Resolved {
			unresolved = append(unresolved, p.DefinitionName)
			continue
		}
		if !p.IsHosted {
			nonHosted = append(nonHosted, p.DefinitionName)
		}
	}

	facts := map[string]any{
		"project_visibility":          visibility,
		"non_hosted_pool_definitions": nonHosted,
		"unresolved_pool_definitions": unresolved,
	}

	if len(pools) == 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
			Reason: "no build definitions exist in this project — the self-hosted-pool attack vector this check flags doesn't apply (a definitive enumeration, not an evidence gap); this is a deliberate divergence from the GitHub twin's own zero-workflow-evidence not-checkable — see the package doc comment",
			Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov, Facts: facts,
		}
	}

	if !isPublicVisibility(visibility) {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
			Reason: "the project is private — the public-fork attack vector a self-hosted pool exposes doesn't apply, regardless of any definition's own pool",
			Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov, Facts: facts,
		}
	}

	if len(nonHosted) > 0 || len(unresolved) > 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusPartial,
			Reason: fmt.Sprintf("the project is public, %d build definition(s) target a non-hosted pool and %d could not be resolved — a public contributor's pull request is a potential path to a self-hosted pool, or this collector can't confirm otherwise; this check has no verified-fail outcome by design, mirroring the GitHub twin", len(nonHosted), len(unresolved)),
			Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov, Facts: facts,
		}
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
		Reason: "the project is public, but every build definition resolved to a Microsoft-hosted pool",
		Scope:  model.ScopeRef{Org: org, Project: project}, Provenance: prov, Facts: facts,
	}
}
