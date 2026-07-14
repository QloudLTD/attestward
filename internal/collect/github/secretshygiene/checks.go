package secretshygiene

import (
	"context"
	"fmt"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/model"
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
func evalGHASGatedFeature(featureName string, status *string, isPrivate bool, ghasStatus *string) (model.Status, string) {
	if status != nil && *status == statusEnabled {
		return model.StatusVerifiedPass, featureName + " is enabled"
	}
	if !isPrivate {
		return model.StatusVerifiedFail, featureName + " is not enabled (freely available on public repos)"
	}
	if ghasStatus == nil || *ghasStatus != statusEnabled {
		return model.StatusNotCheckable, "requires GitHub Advanced Security, not licensed on this private repo"
	}
	return model.StatusVerifiedFail, featureName + " is not enabled"
}

func checkSecretScanning(org, repo string, sa *ghgithub.SecurityAndAnalysis, isPrivate bool, prov []model.Provenance) model.CheckResult {
	const id = "C04.secrets.scanning-enabled"
	if sa == nil {
		return securityAndAnalysisAbsent(id, org, repo, prov)
	}
	var status *string
	if sa.SecretScanning != nil {
		status = sa.SecretScanning.Status
	}
	var ghasStatus *string
	if sa.AdvancedSecurity != nil {
		ghasStatus = sa.AdvancedSecurity.Status
	}
	resultStatus, reason := evalGHASGatedFeature("secret scanning", status, isPrivate, ghasStatus)
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: resultStatus, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"secret_scanning_status": strOrEmpty(status), "private": isPrivate},
	}
}

func checkPushProtection(org, repo string, sa *ghgithub.SecurityAndAnalysis, isPrivate bool, prov []model.Provenance) model.CheckResult {
	const id = "C04.secrets.push-protection"
	if sa == nil {
		return securityAndAnalysisAbsent(id, org, repo, prov)
	}
	var status *string
	if sa.SecretScanningPushProtection != nil {
		status = sa.SecretScanningPushProtection.Status
	}
	var ghasStatus *string
	if sa.AdvancedSecurity != nil {
		ghasStatus = sa.AdvancedSecurity.Status
	}
	resultStatus, reason := evalGHASGatedFeature("secret scanning push protection", status, isPrivate, ghasStatus)
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
func checkAdvancedSecurity(org, repo string, sa *ghgithub.SecurityAndAnalysis, isPrivate bool, prov []model.Provenance) model.CheckResult {
	const id = "C04.secrets.advanced-security"
	if !isPrivate {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "not applicable to public repositories (GHAS licensing only gates private-repo features)",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}
	if sa == nil {
		return securityAndAnalysisAbsent(id, org, repo, prov)
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
func checkDependabotAlerts(org, repo string, enabled bool, resp *ghgithub.Response, err error, prov []model.Provenance) model.CheckResult {
	const id = "C04.deps.dependabot-alerts"
	if err != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: vulnerabilityAlertsNotCheckableReason(resp, err, org, repo),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}
	status, reason := model.StatusVerifiedFail, "Dependabot vulnerability alerts are not enabled"
	if enabled {
		status, reason = model.StatusVerifiedPass, "Dependabot vulnerability alerts are enabled"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"dependabot_alerts_enabled": enabled},
	}
}

func securityAndAnalysisAbsent(id, org, repo string, prov []model.Provenance) model.CheckResult {
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "the repository API response did not include security_and_analysis (older org, or plan-gated) — never assumed off",
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
func checkOrgSecurityDefaults(ctx context.Context, client *ghcollect.Client, org string) model.CheckResult {
	const id = "C04.org.security-defaults"
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
