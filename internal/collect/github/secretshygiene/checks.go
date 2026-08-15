package secretshygiene

import (
	"context"
	"fmt"

	ghgithub "github.com/google/go-github/v75/github"

	"gitlab.com/sioakeim/attestward/internal/collect"
	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const statusEnabled = "enabled"

// evalGHASGatedFeature implements the shared plan-awareness rule for
// secret-scanning and push-protection: an observed "enabled" is always a
// pass, full stop — a direct positive observation is never discarded in
// favor of a licensing inference, since GitHub's 2025 unbundling of GHAS
// into standalone Secret Protection/Code Security products means a private
// repo can plausibly have one of these features licensed and enabled while
// the legacy combined advanced_security flag reads disabled. Only when the
// feature reads "off" does licensing context matter: on a public repo the
// feature is free (GitHub, 2024+), so "off" is a real gap; on a private
// repo without a GHAS license, "off" is not-checkable (can't fault an
// unlicensed feature); "off" with GHAS licensed is a real gap.
func evalGHASGatedFeature(featureName string, status *string, isPrivate bool, ghasStatus *string, scope collect.Scope) (model.Status, string) {
	if status != nil && *status == statusEnabled {
		return model.StatusVerifiedPass, featureName + " is enabled"
	}
	// The public-repo free tier is a github.com pricing policy, and it does
	// not exist on GitHub Enterprise Server: there, secret scanning
	// requires a licence regardless of repository visibility. Reporting
	// verified-fail here on GHES faulted a producer for not enabling a
	// feature their install may not be licensed for — a fabricated finding
	// in a signed pack, flowing into the SSDF rollup and poam.md, and
	// contradicting this very collector's own GHESNoteLicenceGated
	// promise that an unlicensed install yields not-checkable and "never a
	// false verified-fail".
	if !isPrivate && !scope.IsGHES {
		return model.StatusVerifiedFail, featureName + " is not enabled (freely available on public repos)"
	}
	if !isPrivate {
		return model.StatusNotCheckable, featureName + " is not enabled, but GitHub Enterprise Server has no " +
			"free public-repository tier for it — whether this install is licensed for the feature cannot be " +
			"determined from the repository response, so this is not reported as a confirmed gap"
	}
	if ghasStatus == nil || *ghasStatus != statusEnabled {
		if scope.IsGHES {
			return model.StatusNotCheckable, "requires GitHub Advanced Security, which this GitHub Enterprise " +
				"Server install does not report as enabled for this repository"
		}
		return model.StatusNotCheckable, "requires GitHub Advanced Security, not licensed on this private repo"
	}
	return model.StatusVerifiedFail, featureName + " is not enabled"
}

func checkSecretScanning(org, repo string, sa *ghgithub.SecurityAndAnalysis, isPrivate bool, scope collect.Scope, prov []model.Provenance) model.CheckResult {
	const id = "C04.secrets.scanning-enabled"
	if sa == nil {
		return securityAndAnalysisAbsent(id, org, repo, scope, prov)
	}
	var status *string
	if sa.SecretScanning != nil {
		status = sa.SecretScanning.Status
	}
	var ghasStatus *string
	if sa.AdvancedSecurity != nil {
		ghasStatus = sa.AdvancedSecurity.Status
	}
	resultStatus, reason := evalGHASGatedFeature("secret scanning", status, isPrivate, ghasStatus, scope)
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: resultStatus, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"secret_scanning_status": strOrEmpty(status), "private": isPrivate},
	}
}

func checkPushProtection(org, repo string, sa *ghgithub.SecurityAndAnalysis, isPrivate bool, scope collect.Scope, prov []model.Provenance) model.CheckResult {
	const id = "C04.secrets.push-protection"
	if sa == nil {
		return securityAndAnalysisAbsent(id, org, repo, scope, prov)
	}
	var status *string
	if sa.SecretScanningPushProtection != nil {
		status = sa.SecretScanningPushProtection.Status
	}
	var ghasStatus *string
	if sa.AdvancedSecurity != nil {
		ghasStatus = sa.AdvancedSecurity.Status
	}
	resultStatus, reason := evalGHASGatedFeature("secret scanning push protection", status, isPrivate, ghasStatus, scope)
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: resultStatus, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"push_protection_status": strOrEmpty(status), "private": isPrivate},
	}
}

// checkAdvancedSecurity is not-checkable on public repos, not
// verified-pass/fail: GHAS as a licensing construct specifically gates
// private-repo features, so the question "is it enabled" doesn't apply the
// same way to a public repo (which gets the equivalent features free).
func checkAdvancedSecurity(org, repo string, sa *ghgithub.SecurityAndAnalysis, isPrivate bool, scope collect.Scope, prov []model.Provenance) model.CheckResult {
	const id = "C04.secrets.advanced-security"
	if !isPrivate {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: advancedSecurityPublicRepoReason(scope),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}
	if sa == nil {
		return securityAndAnalysisAbsent(id, org, repo, scope, prov)
	}
	var status *string
	if sa.AdvancedSecurity != nil {
		status = sa.AdvancedSecurity.Status
	}
	resultStatus, reason := model.StatusVerifiedFail, "GitHub Advanced Security is not enabled"
	if status != nil && *status == statusEnabled {
		resultStatus, reason = model.StatusVerifiedPass, "GitHub Advanced Security is enabled"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: resultStatus, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"advanced_security_status": strOrEmpty(status)},
	}
}

// checkDependabotAlerts relies entirely on go-github's own handling of
// GetVulnerabilityAlerts' unusual wire semantics: GitHub represents this
// endpoint's boolean as an HTTP status code rather than a response body —
// 204 means enabled, 404 means disabled (a real, meaningful "off" state,
// not an error), and go-github's parseBoolResponse already folds 404 into
// (enabled=false, err=nil) rather than surfacing it as an error. Any other
// non-nil err (403 permission-denied, etc.) is a genuine failure to
// determine the state, distinct from an honest "disabled".
//
// On github.com that 404-folded "off" is unambiguous: Dependabot alerts
// are a free, always-available feature, so a 404 confidently means the
// repo owner turned it off. On GitHub Enterprise Server it is not — the
// feature depends on GitHub Connect syncing github.com's advisory
// database, which may not be configured on this install at all, and that
// absence produces the identical 404 shape as a repo that genuinely has
// alerts turned off. Reporting verified-fail there faulted a producer for
// not enabling a feature their install may not have (issue #26): the same
// false-verified-fail reasoning evalGHASGatedFeature above already fixed
// for secret scanning and push protection. An observed "enabled" (204) is
// never ambiguous on either host — a direct positive observation is never
// discarded in favor of a licensing inference — so only the "off" branch
// changes on GHES.
func checkDependabotAlerts(org, repo string, enabled bool, resp *ghgithub.Response, err error, scope collect.Scope, prov []model.Provenance) model.CheckResult {
	const id = "C04.deps.dependabot-alerts"
	if err != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: vulnerabilityAlertsNotCheckableReason(resp, err, org, repo),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}
	status, reason := model.StatusVerifiedFail, "Dependabot vulnerability alerts are not enabled"
	switch {
	case enabled:
		status, reason = model.StatusVerifiedPass, "Dependabot vulnerability alerts are enabled"
	case scope.IsGHES:
		status = model.StatusNotCheckable
		reason = "Dependabot vulnerability alerts read as not enabled, but on GitHub Enterprise Server this " +
			"requires GitHub Connect syncing github.com's advisory database, which this install may not have " +
			"configured — the same 404 this endpoint returns for a repo with alerts genuinely turned off, so " +
			"this is not reported as a confirmed gap"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"dependabot_alerts_enabled": enabled},
	}
}

func securityAndAnalysisAbsent(id, org, repo string, scope collect.Scope, prov []model.Provenance) model.CheckResult {
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: securityAndAnalysisAbsentReason(scope),
		Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
	}
}

func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// checkOrgSecurityDefaults reports the org's "enabled by default for new
// repositories" settings — forward-looking policy context (does the org's
// posture improve automatically as new repos are created), not a per-repo
// gate. Viewing these fields requires org owner or security manager
// permission; a token without it gets all four fields back nil, which this
// treats as not-checkable rather than four false negatives.
//
// When accountType is collect.AccountTypeUser (issue #102), this
// short-circuits to a specific not-checkable reason without attempting
// Organizations.Get at all — org is a personal account, so this check's
// org-scoped endpoint has no equivalent for it and the call would only
// ever 404.
func checkOrgSecurityDefaults(ctx context.Context, client *ghcollect.Client, org string, accountType collect.AccountType) model.CheckResult {
	const id = "C04.org.security-defaults"
	if accountType == collect.AccountTypeUser {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason:     ghcollect.UserAccountNotCheckableReason(org),
			Scope:      model.ScopeRef{Org: org},
			Provenance: []model.Provenance{},
		}
	}

	orgObj, resp, err := client.REST.Organizations.Get(ctx, org)
	if err != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: orgNotCheckableReason(resp, err, org),
			Scope:  model.ScopeRef{Org: org}, Provenance: client.Provenance(),
		}
	}

	if orgObj.SecretScanningEnabledForNewRepos == nil &&
		orgObj.SecretScanningPushProtectionEnabledForNewRepos == nil &&
		orgObj.DependabotAlertsEnabledForNewRepos == nil &&
		orgObj.AdvancedSecurityEnabledForNewRepos == nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("org security-default fields absent from the response for %s (requires org owner or security manager permission to view)", org),
			Scope:  model.ScopeRef{Org: org}, Provenance: client.Provenance(),
		}
	}

	secretScanning := orgObj.GetSecretScanningEnabledForNewRepos()
	pushProtection := orgObj.GetSecretScanningPushProtectionEnabledForNewRepos()
	dependabot := orgObj.GetDependabotAlertsEnabledForNewRepos()
	advancedSecurity := orgObj.GetAdvancedSecurityEnabledForNewRepos()

	status, reason := model.StatusVerifiedFail, "not every security feature is enabled by default for new repositories"
	if secretScanning && pushProtection && dependabot && advancedSecurity {
		status, reason = model.StatusVerifiedPass, "every security feature is enabled by default for new repositories"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org}, Provenance: client.Provenance(),
		Facts: map[string]any{
			"secret_scanning_enabled_for_new_repositories":                 secretScanning,
			"secret_scanning_push_protection_enabled_for_new_repositories": pushProtection,
			"dependabot_alerts_enabled_for_new_repositories":               dependabot,
			"advanced_security_enabled_for_new_repositories":               advancedSecurity,
		},
	}
}

// securityAndAnalysisAbsentReason explains a repository response with no
// security_and_analysis block. The github.com wording names a plan gate;
// GitHub Enterprise Server has no plan tier, so saying so there would be
// the same false claim this epic exists to remove.
func securityAndAnalysisAbsentReason(scope collect.Scope) string {
	if !scope.IsGHES {
		return "the repository API response did not include security_and_analysis (older org, or plan-gated) — never assumed off"
	}
	return "the repository API response did not include security_and_analysis. On GitHub Enterprise Server this " +
		"means the install is not licensed for these features, or its version predates the field — never assumed off"
}

// advancedSecurityPublicRepoReason: on github.com, Advanced Security gates
// only private-repo features, so it is genuinely not applicable to a public
// repo. GitHub Enterprise Server licenses it per active committer across the
// whole install, with no public-repo exemption, so the github.com wording
// would state a licensing rule that does not hold there.
func advancedSecurityPublicRepoReason(scope collect.Scope) string {
	if !scope.IsGHES {
		return "not applicable to public repositories (GHAS licensing only gates private-repo features)"
	}
	return "GitHub Enterprise Server licenses Advanced Security across the install rather than exempting public " +
		"repositories, so this repository's visibility does not determine whether the feature is available; the " +
		"repository response alone cannot establish the install's licensing"
}
