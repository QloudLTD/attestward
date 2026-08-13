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
	// C03 env-separation moved to internal/collect/gitlab/envseparation: three
	// of its four checks are real — exists, protection-rules and
	// required-reviewers all read GitLab's Environments + Protected
	// Environments APIs, which (contrary to this table's previous blanket
	// "paid tier" reason) are Free-tier and were verified live, including a
	// real write with an approval rule, against this project. The fourth,
	// branch-policy, is always-not-checkable there too, but now for a
	// platform-gap reason rather than a tier one: GitLab has no
	// per-environment branch-restriction mechanism at all — that lives in
	// each deploy job's own `rules:` in .gitlab-ci.yml, outside any
	// environment-scoped API this check could read.
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
	// C05 sast-history moved to internal/collect/gitlab/sasthistory: three
	// of its four checks are real there — tool-configured, ran-per-release
	// and cadence read the merged CI configuration (GET /ci/lint) and the
	// project's job history, both FREE tier, so this table's "availability
	// and retention vary by tier" reason was wrong about them twice over:
	// the evidence is the CI configuration and the job record, not the
	// pipeline security reports it named, and none of it is tier-gated.
	// sast.default-setup stays always-not-checkable there, but for the
	// platform fact that GitLab has no repository-level toggle equivalent to
	// CodeQL default setup — and its title no longer says "CodeQL", which
	// this table's did.
	// C06 sca-history moved to internal/collect/gitlab/scahistory: four of
	// its five checks are real there. tool-configured and ran-per-release are
	// Free-tier, read the same CI evidence as C05's, and were never gated at
	// all; alerts-triaged and dependabot-config (retitled: GitLab has no
	// dependabot.yml, so it compares Dependency Scanning's actual coverage
	// against the repository's own manifests) DO need Ultimate, and take the
	// REST-403 route rather than GraphQL for the reason
	// docs/gitlab-security-apis.md §1 measured — GraphQL answers an
	// unentitled project with empty collections and no error, which is
	// indistinguishable from a clean one. dependency-review stays
	// always-not-checkable, for a genuine platform gap (GitLab has no
	// required-status-check model, and the approval policy that would gate a
	// merge request on findings lives in a separate security policy project
	// this build does not read). This table's C06 reason additionally said
	// that on a free project "the API returns nothing" — measured, REST
	// returns 403 and it is GraphQL that returns nothing, which is the whole
	// distinction these checks turn on (the correction owed in
	// docs/gitlab-security-apis.md §6).
	// C07 provenance moved to internal/collect/gitlab/provenance: checksums,
	// signatures and tags-signed are real, free-tier checks — this table's
	// blanket "does not read them yet" reason was true of them but not the
	// reason to reflag; commit-linkage and workflow stay always-not-checkable
	// there too, for a genuine remaining-scope reason (a cross-platform
	// pipeline-run-history matching engine, not yet ported to GitLab CI), not
	// this one.
	// C08 actions-security moved WHOLESALE to internal/collect/gitlab/
	// actionssecurity — all five checks are real there, none of them left
	// behind. This table's blanket reason ("job token scoping, protected
	// variables and runner controls ... This build does not read them yet")
	// was accurate about the gap but named the wrong evidence for four of
	// the five, and every entry also carried its GitHub twin's title
	// verbatim, naming mechanisms GitLab does not have (GITHUB_TOKEN,
	// pull_request_target, actions, self-hosted runners). The five now read
	// the CI Lint API's resolved `includes` (pinning), the inbound job token
	// allowlist (token scoping), ci_allow_fork_pipelines_to_run_in_parent_
	// project (the fork-into-parent exposure, twice, for the two different
	// things it exposes), and `id_tokens:` weighed against stored cloud
	// credential variables (OIDC) — all Free tier, all verified live.
	// C09 audit-logging moved to internal/collect/gitlab/auditlogging: three of
	// its four checks stay always-not-checkable there for the same paid-tier
	// reason, but the fourth (repo.webhooks) is a real, free-tier check that
	// this package's blanket "paid tier" reason was wrongly applied to.
	// C10 vdp moved to internal/collect/gitlab/vdp: security-md and
	// intake-channel are now real checks; private-reporting and
	// security-policy-org stay always-not-checkable there, but now for the
	// platform fact that neither mechanism exists on GitLab at all, rather
	// than this table's previous "GitLab serves repository files over the
	// API... this build does not read it yet" — true of security-md and
	// intake-channel, but not of the other two, which nothing was ever
	// going to "start reading."
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

func (c *collector) Collect(_ context.Context, sc collect.Scope) ([]model.CheckResult, error) {
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
		Title:   chk.title,
		Status:  model.StatusNotCheckable,
		Reason:  chk.reason,
		Scope:   model.ScopeRef{Org: org, Repo: repo, Platform: platform},
		// An empty slice, not nil: nil marshals to JSON null and the pack
		// schema requires an array. Semantically the same thing — no API
		// call backs any of these — but the schema is the contract a
		// consumer validates against, and it is right to be strict.
		Provenance: []model.Provenance{},
	}
}
