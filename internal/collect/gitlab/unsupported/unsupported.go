// Package unsupported reports, honestly and in full, every check this build
// cannot yet evidence on GitLab (#1).
//
// It exists for the same reason its Gogs counterpart does: a pack containing
// six results instead of forty-six gives a reader no way to tell "this
// platform cannot attest to it" from "the scanner did not get that far", and
// a missing row reads, to anyone skimming, like a clean one. So every check
// with no GitLab implementation still produces a result, with a status of
// not-checkable and a reason naming the specific limitation.
//
// # Every reason here says "this build does not read it yet"
//
// That phrasing is deliberate and it is the honest one. GitLab has a rich
// API and most of these controls are genuinely discoverable through it — the
// gap is this implementation, not the platform. Writing "GitLab cannot do
// this" would be false for almost every entry below, and false in the
// direction that flatters the tool.
//
// Where a paid tier is involved the reason says so, because that distinction
// changes what an empty API response means: on a free project, Dependency
// Scanning and audit events return nothing, and reading that as "no
// vulnerable dependencies" or "no audit gaps" would be a fabricated pass.
// Nothing here reports verified-pass or verified-fail for exactly that
// reason.
//
// # What this package must never do
//
// Nothing here reports verified-fail — that asserts a control was looked for
// and found absent, and none of these were looked for. Nothing here carries
// provenance either: no API call backs any of it, and a provenance entry
// would claim the tool asked a question it never asked.
//
// As real collectors land, entries move out of this table. The table
// shrinking is the measure of progress on #1.
package unsupported

import (
	"context"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// platform is the registry key every check here registers under.
const platform = "gitlab"

// scope decides both the ScopeRef stamped on each result and how many
// results a scan produces — repo-scoped checks are emitted once per project
// in scope, so a GitLab pack's shape matches a GitHub pack's.
type scope int

const (
	orgScoped scope = iota
	repoScoped
)

type check struct {
	id          string
	title       string
	collectorID string
	scope       scope
	reason      string
}

const remediation = "Not evaluable by this build on GitLab yet. Until a collector lands, answer the corresponding self-attestation question, or evidence the control from whichever system actually enforces it."

var checks = []check{
	{
		id: "C01.org.2fa-required", title: "Org requires two-factor authentication",
		collectorID: "C01.org-security", scope: orgScoped,
		reason: "GitLab groups expose a security surface \u2014 require_two_factor_authentication, default project-creation and visibility levels \u2014 via GET /groups/{id}. This build does not read it yet",
	},
	{
		id: "C01.org.default-repo-permission", title: "Default repository permission for members",
		collectorID: "C01.org-security", scope: orgScoped,
		reason: "GitLab groups expose a security surface \u2014 require_two_factor_authentication, default project-creation and visibility levels \u2014 via GET /groups/{id}. This build does not read it yet",
	},
	{
		id: "C01.org.members-can-create-public", title: "Whether members can create public repositories",
		collectorID: "C01.org-security", scope: orgScoped,
		reason: "GitLab groups expose a security surface \u2014 require_two_factor_authentication, default project-creation and visibility levels \u2014 via GET /groups/{id}. This build does not read it yet",
	},
	{
		id: "C01.org.members-without-2fa", title: "Count of members without two-factor authentication",
		collectorID: "C01.org-security", scope: orgScoped,
		reason: "GitLab groups expose a security surface \u2014 require_two_factor_authentication, default project-creation and visibility levels \u2014 via GET /groups/{id}. This build does not read it yet",
	},
	{
		id: "C02.branch.admin-enforced", title: "Default branch protections apply to admins (no unconditional bypass actor)",
		collectorID: "C02.repo-protection", scope: repoScoped,
		reason: "GitLab exposes protected branches (GET /projects/{id}/protected_branches) and merge-request approval settings. This build does not read them yet",
	},
	{
		id: "C02.branch.deletion-blocked", title: "Default branch blocks branch deletion",
		collectorID: "C02.repo-protection", scope: repoScoped,
		reason: "GitLab exposes protected branches (GET /projects/{id}/protected_branches) and merge-request approval settings. This build does not read them yet",
	},
	{
		id: "C02.branch.force-push-blocked", title: "Default branch blocks force pushes",
		collectorID: "C02.repo-protection", scope: repoScoped,
		reason: "GitLab exposes protected branches (GET /projects/{id}/protected_branches) and merge-request approval settings. This build does not read them yet",
	},
	{
		id: "C02.branch.protection-exists", title: "Default branch has protection (legacy branch protection or a ruleset)",
		collectorID: "C02.repo-protection", scope: repoScoped,
		reason: "GitLab exposes protected branches (GET /projects/{id}/protected_branches) and merge-request approval settings. This build does not read them yet",
	},
	{
		id: "C02.branch.required-reviews", title: "Default branch requires at least one approving review before merge",
		collectorID: "C02.repo-protection", scope: repoScoped,
		reason: "GitLab exposes protected branches (GET /projects/{id}/protected_branches) and merge-request approval settings. This build does not read them yet",
	},
	{
		id: "C02.branch.required-status-checks", title: "Default branch requires status checks before merge",
		collectorID: "C02.repo-protection", scope: repoScoped,
		reason: "GitLab exposes protected branches (GET /projects/{id}/protected_branches) and merge-request approval settings. This build does not read them yet",
	},
	{
		id: "C03.env.branch-policy", title: "Production-like environments restrict which branches/tags can deploy",
		collectorID: "C03.env-separation", scope: orgScoped,
		reason: "GitLab has environments (GET /projects/{id}/environments). Protected environments, which carry the deployment-approval controls this check looks for, are a paid-tier feature. This build reads neither yet",
	},
	{
		id: "C03.env.exists", title: "A production-like environment exists",
		collectorID: "C03.env-separation", scope: orgScoped,
		reason: "GitLab has environments (GET /projects/{id}/environments). Protected environments, which carry the deployment-approval controls this check looks for, are a paid-tier feature. This build reads neither yet",
	},
	{
		id: "C03.env.protection-rules", title: "Production-like environments have at least one protection rule",
		collectorID: "C03.env-separation", scope: orgScoped,
		reason: "GitLab has environments (GET /projects/{id}/environments). Protected environments, which carry the deployment-approval controls this check looks for, are a paid-tier feature. This build reads neither yet",
	},
	{
		id: "C03.env.required-reviewers", title: "Production-like environments require reviewer approval before deployment",
		collectorID: "C03.env-separation", scope: orgScoped,
		reason: "GitLab has environments (GET /projects/{id}/environments). Protected environments, which carry the deployment-approval controls this check looks for, are a paid-tier feature. This build reads neither yet",
	},
	{
		id: "C04.deps.dependabot-alerts", title: "Dependabot vulnerability alerts are enabled",
		collectorID: "C04.secrets-hygiene", scope: orgScoped,
		reason: "GitLab exposes CI/CD variables and their masked/protected flags. Secret Detection, which would evidence historical leakage, is a paid-tier feature and returns nothing on a free project \u2014 an empty result there means 'not entitled', never 'clean'. This build reads neither yet",
	},
	{
		id: "C04.org.security-defaults", title: "Org enables secret/dependency security features by default for new repos",
		collectorID: "C04.secrets-hygiene", scope: orgScoped,
		reason: "GitLab exposes CI/CD variables and their masked/protected flags. Secret Detection, which would evidence historical leakage, is a paid-tier feature and returns nothing on a free project \u2014 an empty result there means 'not entitled', never 'clean'. This build reads neither yet",
	},
	{
		id: "C04.secrets.advanced-security", title: "GitHub Advanced Security is enabled where applicable",
		collectorID: "C04.secrets-hygiene", scope: orgScoped,
		reason: "GitLab exposes CI/CD variables and their masked/protected flags. Secret Detection, which would evidence historical leakage, is a paid-tier feature and returns nothing on a free project \u2014 an empty result there means 'not entitled', never 'clean'. This build reads neither yet",
	},
	{
		id: "C04.secrets.push-protection", title: "Secret scanning push protection is active",
		collectorID: "C04.secrets-hygiene", scope: orgScoped,
		reason: "GitLab exposes CI/CD variables and their masked/protected flags. Secret Detection, which would evidence historical leakage, is a paid-tier feature and returns nothing on a free project \u2014 an empty result there means 'not entitled', never 'clean'. This build reads neither yet",
	},
	{
		id: "C04.secrets.scanning-enabled", title: "Secret scanning is active",
		collectorID: "C04.secrets-hygiene", scope: orgScoped,
		reason: "GitLab exposes CI/CD variables and their masked/protected flags. Secret Detection, which would evidence historical leakage, is a paid-tier feature and returns nothing on a free project \u2014 an empty result there means 'not entitled', never 'clean'. This build reads neither yet",
	},
	{
		id: "C05.sast.cadence", title: "SAST run cadence over the lookback window",
		collectorID: "C05.sast-history", scope: orgScoped,
		reason: "GitLab reports SAST findings through pipeline security reports. Availability and retention vary by tier, so an empty result cannot be read as a clean one. This build does not read them yet",
	},
	{
		id: "C05.sast.default-setup", title: "CodeQL default setup is configured",
		collectorID: "C05.sast-history", scope: orgScoped,
		reason: "GitLab reports SAST findings through pipeline security reports. Availability and retention vary by tier, so an empty result cannot be read as a clean one. This build does not read them yet",
	},
	{
		id: "C05.sast.ran-per-release", title: "A SAST tool ran for each release in the lookback window",
		collectorID: "C05.sast-history", scope: orgScoped,
		reason: "GitLab reports SAST findings through pipeline security reports. Availability and retention vary by tier, so an empty result cannot be read as a clean one. This build does not read them yet",
	},
	{
		id: "C05.sast.tool-configured", title: "A SAST tool is configured",
		collectorID: "C05.sast-history", scope: orgScoped,
		reason: "GitLab reports SAST findings through pipeline security reports. Availability and retention vary by tier, so an empty result cannot be read as a clean one. This build does not read them yet",
	},
	{
		id: "C06.sca.alerts-triaged", title: "Open Dependabot alerts are triaged within the default window",
		collectorID: "C06.sca-history", scope: orgScoped,
		reason: "GitLab Dependency Scanning produces the SCA evidence this check needs and is a paid-tier feature; on a free project the API returns nothing, which is not the same as no vulnerable dependencies. This build does not read it yet",
	},
	{
		id: "C06.sca.dependabot-config", title: "Dependabot config covers the repo's detected dependency ecosystems",
		collectorID: "C06.sca-history", scope: orgScoped,
		reason: "GitLab Dependency Scanning produces the SCA evidence this check needs and is a paid-tier feature; on a free project the API returns nothing, which is not the same as no vulnerable dependencies. This build does not read it yet",
	},
	{
		id: "C06.sca.dependency-review", title: "Dependency review is enforced as a required check on pull requests",
		collectorID: "C06.sca-history", scope: orgScoped,
		reason: "GitLab Dependency Scanning produces the SCA evidence this check needs and is a paid-tier feature; on a free project the API returns nothing, which is not the same as no vulnerable dependencies. This build does not read it yet",
	},
	{
		id: "C06.sca.ran-per-release", title: "An SCA tool ran for each release in the lookback window",
		collectorID: "C06.sca-history", scope: orgScoped,
		reason: "GitLab Dependency Scanning produces the SCA evidence this check needs and is a paid-tier feature; on a free project the API returns nothing, which is not the same as no vulnerable dependencies. This build does not read it yet",
	},
	{
		id: "C06.sca.tool-configured", title: "An SCA tool is configured",
		collectorID: "C06.sca-history", scope: orgScoped,
		reason: "GitLab Dependency Scanning produces the SCA evidence this check needs and is a paid-tier feature; on a free project the API returns nothing, which is not the same as no vulnerable dependencies. This build does not read it yet",
	},
	{
		id: "C07.provenance.commit-linkage", title: "Release artifacts are traceable to a workflow run on the release commit",
		collectorID: "C07.provenance", scope: orgScoped,
		reason: "GitLab exposes releases, tags and release assets (GET /projects/{id}/releases), which is where build provenance and signatures would be evidenced. This build does not read them yet",
	},
	{
		id: "C07.provenance.workflow", title: "A provenance-generating tool is configured",
		collectorID: "C07.provenance", scope: orgScoped,
		reason: "GitLab exposes releases, tags and release assets (GET /projects/{id}/releases), which is where build provenance and signatures would be evidenced. This build does not read them yet",
	},
	{
		id: "C07.release.checksums", title: "Releases ship checksum assets",
		collectorID: "C07.provenance", scope: orgScoped,
		reason: "GitLab exposes releases, tags and release assets (GET /projects/{id}/releases), which is where build provenance and signatures would be evidenced. This build does not read them yet",
	},
	{
		id: "C07.release.signatures", title: "Releases ship signature or attestation assets",
		collectorID: "C07.provenance", scope: orgScoped,
		reason: "GitLab exposes releases, tags and release assets (GET /projects/{id}/releases), which is where build provenance and signatures would be evidenced. This build does not read them yet",
	},
	{
		id: "C07.release.tags-signed", title: "Release tags are signed and GitHub reports the signature verified",
		collectorID: "C07.provenance", scope: orgScoped,
		reason: "GitLab exposes releases, tags and release assets (GET /projects/{id}/releases), which is where build provenance and signatures would be evidenced. This build does not read them yet",
	},
	{
		id: "C08.actions.oidc-vs-secrets", title: "Cloud deployments use OIDC rather than long-lived static credentials",
		collectorID: "C08.actions-security", scope: orgScoped,
		reason: "GitLab CI is configured in .gitlab-ci.yml with job token scoping, protected variables and runner controls exposed through the projects API. This build does not read them yet",
	},
	{
		id: "C08.actions.pinned", title: "Third-party actions and reusable workflows are pinned to a full commit SHA",
		collectorID: "C08.actions-security", scope: orgScoped,
		reason: "GitLab CI is configured in .gitlab-ci.yml with job token scoping, protected variables and runner controls exposed through the projects API. This build does not read them yet",
	},
	{
		id: "C08.actions.pull-request-target", title: "pull_request_target is not combined with checking out the PR head",
		collectorID: "C08.actions-security", scope: orgScoped,
		reason: "GitLab CI is configured in .gitlab-ci.yml with job token scoping, protected variables and runner controls exposed through the projects API. This build does not read them yet",
	},
	{
		id: "C08.actions.self-hosted", title: "Self-hosted runners are not exposed to public-repo pull requests",
		collectorID: "C08.actions-security", scope: orgScoped,
		reason: "GitLab CI is configured in .gitlab-ci.yml with job token scoping, protected variables and runner controls exposed through the projects API. This build does not read them yet",
	},
	{
		id: "C08.actions.token-permissions", title: "Workflows declare explicit, least-privilege GITHUB_TOKEN permissions",
		collectorID: "C08.actions-security", scope: orgScoped,
		reason: "GitLab CI is configured in .gitlab-ci.yml with job token scoping, protected variables and runner controls exposed through the projects API. This build does not read them yet",
	},
	{
		id: "C09.audit.log-streaming", title: "Audit-log export/streaming is configured",
		collectorID: "C09.audit-logging", scope: orgScoped,
		reason: "GitLab's audit events API is a paid-tier feature; on a free project there is no audit stream to read at all, so absence of events is a tier limitation rather than a finding. This build does not read it yet",
	},
	{
		id: "C09.audit.org-log-available", title: "Organization audit log is reachable via the API",
		collectorID: "C09.audit-logging", scope: orgScoped,
		reason: "GitLab's audit events API is a paid-tier feature; on a free project there is no audit stream to read at all, so absence of events is a tier limitation rather than a finding. This build does not read it yet",
	},
	{
		id: "C09.audit.retention-awareness", title: "Audit-log retention window (informational)",
		collectorID: "C09.audit-logging", scope: orgScoped,
		reason: "GitLab's audit events API is a paid-tier feature; on a free project there is no audit stream to read at all, so absence of events is a tier limitation rather than a finding. This build does not read it yet",
	},
	{
		id: "C09.repo.webhooks", title: "A webhook exports push/release/deployment events",
		collectorID: "C09.audit-logging", scope: repoScoped,
		reason: "GitLab's audit events API is a paid-tier feature; on a free project there is no audit stream to read at all, so absence of events is a tier limitation rather than a finding. This build does not read it yet",
	},
	{
		id: "C10.vdp.intake-channel", title: "SECURITY.md advertises an actionable intake channel",
		collectorID: "C10.vdp", scope: orgScoped,
		reason: "GitLab serves repository files over the API, so a SECURITY.md-based disclosure policy is discoverable the same way it is on the other platforms. This build does not read it yet",
	},
	{
		id: "C10.vdp.private-reporting", title: "GitHub private vulnerability reporting is enabled",
		collectorID: "C10.vdp", scope: orgScoped,
		reason: "GitLab serves repository files over the API, so a SECURITY.md-based disclosure policy is discoverable the same way it is on the other platforms. This build does not read it yet",
	},
	{
		id: "C10.vdp.security-md", title: "A SECURITY.md resolves for this repo",
		collectorID: "C10.vdp", scope: orgScoped,
		reason: "GitLab serves repository files over the API, so a SECURITY.md-based disclosure policy is discoverable the same way it is on the other platforms. This build does not read it yet",
	},
	{
		id: "C10.vdp.security-policy-org", title: "The org has an org-wide default security policy",
		collectorID: "C10.vdp", scope: orgScoped,
		reason: "GitLab serves repository files over the API, so a SECURITY.md-based disclosure policy is discoverable the same way it is on the other platforms. This build does not read it yet",
	},
}

func init() {
	for _, c := range checks {
		collect.Register(collect.CheckMeta{
			ID:          c.id,
			Platform:    platform,
			Title:       c.title,
			Collector:   c.collectorID,
			TokenScope:  "read_api",
			Remediation: remediation,
			Rubric: map[model.Status]string{
				model.StatusNotCheckable: c.reason,
			},
			// No endpoint backs any of these: Endpoints documents what a
			// check's own result depends on, and nothing here makes a call.
			// The same shape as the Gogs unsupported table, for the same
			// reason.
			Endpoints:  nil,
			FixtureRef: "internal/collect/gitlab/unsupported/unsupported_test.go",
		})
	}
}

// Collectors returns one collector per check family present in the table, so
// a GitLab scan emits a complete set of results rather than a sparse one.
func Collectors() []collect.Collector {
	seen := map[string]bool{}
	var out []collect.Collector
	for _, c := range checks {
		if seen[c.collectorID] {
			continue
		}
		seen[c.collectorID] = true
		out = append(out, &collector{id: c.collectorID})
	}
	return out
}

type collector struct{ id string }

func (c *collector) ID() string { return c.id }

func (c *collector) Collect(ctx context.Context, sc collect.Scope) ([]model.CheckResult, error) {
	var out []model.CheckResult
	for _, chk := range checks {
		if chk.collectorID != c.id {
			continue
		}
		if chk.scope == repoScoped {
			for _, repo := range sc.Repos {
				out = append(out, result(chk, sc.Org, repo))
			}
			continue
		}
		out = append(out, result(chk, sc.Org, ""))
	}
	return out, nil
}

func result(chk check, org, repo string) model.CheckResult {
	return model.CheckResult{
		CheckID: chk.id,
		Status:  model.StatusNotCheckable,
		Reason:  chk.reason,
		Scope:   model.ScopeRef{Org: org, Repo: repo, Platform: platform},
	}
}
