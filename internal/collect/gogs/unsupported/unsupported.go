// Package unsupported reports, honestly and in full, every check a Gogs
// instance cannot evidence (Gogs issue #5).
//
// # Why this package exists at all
//
// Gogs has no CI, no code scanning, no dependency alerts, no secret
// scanning, no environments, no audit log, and no branch-protection API.
// The tempting implementation is to simply not emit those checks. That
// would be the wrong answer, and it is the specific failure this package
// exists to prevent: a pack containing six results instead of forty-six
// gives a reader no way to tell "this platform cannot attest to it" from
// "the scanner didn't get that far", and a missing row reads, to anyone
// skimming, like a clean one.
//
// So every check with no Gogs implementation still produces a result, with
// a status of not-checkable and a Reason that names the specific platform
// limitation. A Gogs pack is mostly negative evidence. That is the product
// working: the CISA SSDA form asks whether a control exists, and "the
// platform hosting this code cannot demonstrate it" is a truthful,
// auditable answer a producer can act on — by moving the control
// elsewhere, or by answering the corresponding self-attestation question.
//
// # Two kinds of not-checkable live here, and they are not the same
//
//   - **No mechanism exists.** Gogs has no equivalent concept at all —
//     GitHub Actions, environments, Dependabot, the audit log. Nothing a
//     producer does to their Gogs instance could ever make these
//     checkable, and the Reason says so.
//   - **A signal exists but this build does not read it.** Gogs does expose
//     repo webhooks, deploy keys, tags and releases. Those could support
//     partial evidence for C04, C07 and C09, and deliberately are not read
//     yet. Saying "Gogs cannot do this" about those would be false, so the
//     Reason instead says what is exposed and that this build does not
//     evaluate it.
//
// Conflating the two would be a lie of exactly the kind this tool exists to
// eliminate. Each entry in the table below states which it is.
//
// # What this package must never do
//
// Nothing here reports verified-fail. A verified-fail asserts that a
// control was looked for and found absent; none of these were looked for,
// because there is nothing to look at. Nothing here carries provenance
// either — no API call backs any of it, and a provenance entry would claim
// the tool asked the instance a question it never asked.
package unsupported

import (
	"context"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// platform is the registry key every check here registers under.
const platform = "gogs"

// scope describes whether a check's result is about the whole account or
// about one repo. It decides both the ScopeRef stamped on each result and
// how many results a scan produces — repo-scoped checks are emitted once
// per repo in scope, so a Gogs pack's shape matches a GitHub pack's.
type scope int

const (
	orgScoped scope = iota
	repoScoped
)

// check is one unsupported check's full metadata plus the reason it can
// never (or cannot yet) be evaluated here.
type check struct {
	id    string
	title string
	// collectorID must match the Collector string the same check ID is
	// registered under on every other platform: the registry rejects two
	// platforms registering one ID under different collectors, because
	// the generated checks reference groups by collector and would
	// otherwise render one check as two unrelated sections.
	collectorID string
	scope       scope
	// reason is what a reader sees next to the status, verbatim, in a
	// signed evidence pack. Nothing in CI asserts on these strings —
	// only statuses are guarded — so they are reviewed as prose.
	reason string
	// remediation is what the producer can actually do. For a control the
	// platform cannot host, that is never "enable it here"; it is either
	// "move the control somewhere that can evidence it" or "answer the
	// corresponding self-attestation question honestly".
	remediation string
}

// checks is the full table. Grouped by collector, in check-ID order.
//
// C02 repo-protection and C10 vdp are deliberately absent: both have real
// Gogs collectors of their own. Adding them here would double-register
// their IDs and panic at init, which is the registry doing its job.
var checks = []check{
	// ---- C01 org-security -------------------------------------------
	//
	// Gogs has no org-level security policy surface whatsoever: no 2FA
	// enforcement setting, no default repository permission, no
	// member-creation policy. GET /orgs/{org}/members is not implemented
	// either (404 on Gogs 0.15), so even enumerating who is in the org to
	// report on them is not possible.
	{
		id: "C01.org.2fa-required", title: "Org requires two-factor authentication",
		collectorID: "C01.org-security", scope: orgScoped,
		reason: "Gogs has no org-wide two-factor enforcement setting. Individual users can enable 2FA on " +
			"their own accounts, but there is no organization policy that requires it and no API that " +
			"reports on it — GET /orgs/{org}/members is not implemented on Gogs 0.15, so the members " +
			"cannot even be enumerated to report their individual state",
		remediation: "This control cannot be enforced or evidenced on Gogs. If mandatory 2FA is required, " +
			"it has to come from the identity layer in front of the instance (an SSO proxy or the host's " +
			"own authentication), and be answered through self-attestation rather than measured here.",
	},
	{
		id: "C01.org.default-repo-permission", title: "Org default repository permission is not overly broad",
		collectorID: "C01.org-security", scope: orgScoped,
		reason: "Gogs has no org-wide default repository permission setting. Access is granted per team and " +
			"per repository, with no account-level default to read",
		remediation: "Review team membership and per-repo collaborators directly in the Gogs UI. There is no " +
			"single default to tighten, so this is a review task rather than a setting change.",
	},
	{
		id: "C01.org.members-can-create-public", title: "Members cannot create public repositories unchecked",
		collectorID: "C01.org-security", scope: orgScoped,
		reason: "Gogs has no org policy governing who may create public repositories, and no API reporting " +
			"one. Instance-wide settings in app.ini can force every repository private, but that is host " +
			"configuration, not organization policy, and is not exposed through the API",
		remediation: "If public repositories must be prevented, set it instance-wide in the Gogs server's " +
			"app.ini (REQUIRE_SIGNIN_VIEW / repository defaults) and attest to it out of band — the API " +
			"cannot confirm it.",
	},
	{
		id: "C01.org.members-without-2fa", title: "No members are without two-factor authentication",
		collectorID: "C01.org-security", scope: orgScoped,
		reason: "GET /orgs/{org}/members is not implemented on Gogs 0.15 (404), and no endpoint reports a " +
			"user's two-factor state, so neither the member list nor their 2FA status can be observed",
		remediation: "Enumerate members and their 2FA state from the Gogs admin UI, and answer through " +
			"self-attestation. The API offers no path to this.",
	},

	// ---- C03 env-separation ------------------------------------------
	//
	// Environments are a CI/CD deployment concept. Gogs hosts git and
	// nothing else — there is no deployment target to separate, gate, or
	// require reviewers on.
	{
		id: "C03.env.exists", title: "Deployment environments are defined",
		collectorID: "C03.env-separation", scope: repoScoped,
		reason: "Gogs has no environments concept. It hosts repositories and does not model deployment " +
			"targets at all, so there is nothing to define or read",
		remediation: "Environment separation, if practised, lives in whatever system actually performs " +
			"deployments. Evidence has to come from that system; Gogs cannot produce it.",
	},
	{
		id: "C03.env.protection-rules", title: "Environments have protection rules",
		collectorID: "C03.env-separation", scope: repoScoped,
		reason:      "Gogs has no environments, so there are no protection rules to read",
		remediation: "See C03.env.exists — this belongs to the deployment system, not to Gogs.",
	},
	{
		id: "C03.env.required-reviewers", title: "Production environments require reviewers",
		collectorID: "C03.env-separation", scope: repoScoped,
		reason:      "Gogs has no environments, so there are no required reviewers to read",
		remediation: "See C03.env.exists — this belongs to the deployment system, not to Gogs.",
	},
	{
		id: "C03.env.branch-policy", title: "Environments restrict which branches may deploy",
		collectorID: "C03.env-separation", scope: repoScoped,
		reason:      "Gogs has no environments, so there is no deployment branch policy to read",
		remediation: "See C03.env.exists — this belongs to the deployment system, not to Gogs.",
	},

	// ---- C04 secrets-hygiene ----------------------------------------
	//
	// Gogs has no secret scanning of any kind. It does expose repo
	// webhooks and deploy keys, which is why two of these five say
	// something different from the other three.
	{
		id: "C04.secrets.scanning-enabled", title: "Secret scanning is enabled",
		collectorID: "C04.secrets-hygiene", scope: repoScoped,
		reason: "Gogs has no secret scanning feature. Nothing inspects pushed content for credentials, so " +
			"there is no setting to enable and no alert history to read",
		remediation: "Run secret scanning outside the platform — a pre-commit hook, a CI job on whatever " +
			"system builds this repo, or a scheduled scan of a clone — and attest to it separately.",
	},
	{
		id: "C04.secrets.push-protection", title: "Push protection blocks committed secrets",
		collectorID: "C04.secrets-hygiene", scope: repoScoped,
		reason: "Gogs has no push protection. A server-side git hook could reject pushes containing " +
			"credentials, but Gogs neither ships one nor reports whether an operator installed one",
		remediation: "A custom server-side update hook on the Gogs host is the only equivalent. If one is " +
			"in place, it must be attested to out of band — the API cannot confirm it.",
	},
	{
		id: "C04.secrets.advanced-security", title: "Advanced security features are enabled",
		collectorID: "C04.secrets-hygiene", scope: repoScoped,
		reason: "Gogs has no advanced-security product or licence tier — the concept does not exist on this " +
			"platform, so there is nothing to enable",
		remediation: "Not applicable to Gogs. The underlying controls (secret scanning, code scanning, " +
			"dependency alerts) have to come from tooling outside the platform.",
	},
	{
		id: "C04.org.security-defaults", title: "Org-level security defaults are enabled for new repos",
		collectorID: "C04.secrets-hygiene", scope: orgScoped,
		reason: "Gogs has no org-level security defaults for new repositories — no such settings exist to " +
			"apply or to read",
		remediation: "Not applicable to Gogs. Any per-repo hygiene has to be applied repo by repo.",
	},
	{
		id: "C04.deps.dependabot-alerts", title: "Dependency vulnerability alerts are enabled",
		collectorID: "C04.secrets-hygiene", scope: repoScoped,
		reason: "Gogs has no dependency scanning or vulnerability alerting. It does not parse manifests or " +
			"track advisories, so there is no alert state to read",
		remediation: "Use an external SCA tool against a clone of the repo, and attest to its findings " +
			"separately.",
	},

	// ---- C05 sast-history / C06 sca-history ---------------------------
	//
	// This is the decision recorded in Gogs issue #8. A repo mirrored from
	// GitHub still carries .github/workflows/*.yml in its tree, and the
	// contents API will serve it — but those workflows can never execute
	// on Gogs, which has no CI at all. Reading them would mean matching a
	// scanner signature against a definition that provably never ran, and
	// reporting it as evidence of scanning. The decision was: do not read
	// CI files on this platform, and say plainly that any real evidence
	// comes from a system this tool cannot see.
	{
		id: "C05.sast.tool-configured", title: "A SAST tool is configured",
		collectorID: "C05.sast-history", scope: repoScoped,
		reason: "Gogs has no CI system, so no scanner can be configured to run on it. A repository mirrored " +
			"from another platform may still contain CI definitions in its tree, but those never execute " +
			"here — treating one as evidence of scanning would assert a control that provably did not run " +
			"on this platform (Gogs issue #8)",
		remediation: "SAST for a Gogs-hosted repo runs in an external CI system. Evidence has to come from " +
			"that system, or be answered through self-attestation.",
	},
	{
		id: "C05.sast.default-setup", title: "Platform-managed SAST is enabled",
		collectorID: "C05.sast-history", scope: repoScoped,
		reason: "Gogs offers no platform-managed code scanning — there is no first-party analysis service " +
			"to turn on, and no setting that would record whether one had been",
		remediation: "Not applicable to Gogs — see C05.sast.tool-configured.",
	},
	{
		id: "C05.sast.ran-per-release", title: "SAST ran for each release in the lookback window",
		collectorID: "C05.sast-history", scope: repoScoped,
		reason: "Gogs runs no CI, so it holds no run history to correlate with releases. Tags and releases " +
			"are readable here, but nothing links them to a scan that this platform never executed",
		remediation: "Correlate scans to releases in the external CI system that runs them.",
	},
	{
		id: "C05.sast.cadence", title: "SAST runs on a regular cadence",
		collectorID: "C05.sast-history", scope: repoScoped,
		reason:      "Gogs runs no CI and holds no run history, so no cadence can be observed",
		remediation: "See C05.sast.ran-per-release — cadence evidence lives in the external CI system.",
	},
	{
		id: "C06.sca.tool-configured", title: "An SCA tool is configured",
		collectorID: "C06.sca-history", scope: repoScoped,
		reason: "Gogs has no CI system and no dependency scanning, so no SCA tool can be configured to run " +
			"on it. As with C05, CI definitions present in a mirrored repo's tree never execute here and " +
			"are deliberately not read as evidence (Gogs issue #8)",
		remediation: "SCA for a Gogs-hosted repo runs in an external system. Evidence has to come from " +
			"there.",
	},
	{
		id: "C06.sca.dependabot-config", title: "Automated dependency updates are configured",
		collectorID: "C06.sca-history", scope: repoScoped,
		reason: "Gogs has no automated dependency-update service. A configuration file for another " +
			"platform's service may exist in the tree, but nothing here acts on it",
		remediation: "Not applicable to Gogs — run dependency updates from an external system.",
	},
	{
		id: "C06.sca.dependency-review", title: "Dependency review runs on pull requests",
		collectorID: "C06.sca-history", scope: repoScoped,
		reason: "Gogs has pull requests but no dependency review, and no mechanism for a required check to " +
			"gate one",
		remediation: "Not applicable to Gogs — dependency review has to happen in an external system.",
	},
	{
		id: "C06.sca.ran-per-release", title: "SCA ran for each release in the lookback window",
		collectorID: "C06.sca-history", scope: repoScoped,
		reason:      "Gogs runs no CI, so it holds no run history to correlate with releases",
		remediation: "Correlate scans to releases in the external system that runs them.",
	},
	{
		id: "C06.sca.alerts-triaged", title: "Dependency alerts are triaged",
		collectorID: "C06.sca-history", scope: repoScoped,
		reason:      "Gogs raises no dependency alerts, so there is no triage state to read",
		remediation: "Not applicable to Gogs — triage evidence lives wherever the alerts are raised.",
	},

	// ---- C07 provenance ----------------------------------------------
	//
	// Gogs does expose tags, releases and commits, which is why these
	// reasons distinguish "the platform cannot" from "this build does
	// not". Signature verification is the genuine gap: Gogs returns no
	// verification object on a commit or tag, so it cannot report whether
	// a signature exists or is valid, however the object was signed.
	{
		id: "C07.release.signatures", title: "Releases are signed",
		collectorID: "C07.provenance", scope: repoScoped,
		reason: "Gogs returns no signature verification data. Its commit and tag objects carry no " +
			"verification field of any kind, so even a properly signed tag is indistinguishable from an " +
			"unsigned one through the API — this is a limitation of the platform, not an observation " +
			"about the repository",
		remediation: "Verify signatures out of band against a clone (git verify-tag / git verify-commit), " +
			"or publish signed artifacts through a release process that records its own attestation.",
	},
	{
		id: "C07.release.checksums", title: "Release artifacts publish checksums",
		collectorID: "C07.provenance", scope: repoScoped,
		reason: "Gogs exposes releases and their attachments through the API, but this build does not " +
			"evaluate them for checksum files. This is a gap in this scanner, not in the platform",
		remediation: "Publish a checksums file alongside release artifacts. Note that this scanner does not " +
			"yet read Gogs releases, so it cannot confirm you have.",
	},
	{
		id: "C07.release.tags-signed", title: "Release tags are signed",
		collectorID: "C07.provenance", scope: repoScoped,
		reason: "Tags are listable through the API, but Gogs reports no signature state for them — see " +
			"C07.release.signatures. Whether a tag is signed cannot be determined from this platform",
		remediation: "Sign tags as normal; verify out of band against a clone, since the platform will not " +
			"report it.",
	},
	{
		id: "C07.provenance.workflow", title: "A build provenance workflow exists",
		collectorID: "C07.provenance", scope: repoScoped,
		reason: "Gogs runs no CI, so no build workflow exists on this platform to produce provenance",
		remediation: "Build provenance comes from whatever system performs the build. Evidence has to come " +
			"from there.",
	},
	{
		id: "C07.provenance.commit-linkage", title: "Releases link to the commits they were built from",
		collectorID: "C07.provenance", scope: repoScoped,
		reason: "Gogs exposes commits, tags and releases, so the underlying data exists, but this build does " +
			"not correlate them. This is a gap in this scanner, not in the platform",
		remediation: "No action available through this scanner yet.",
	},

	// ---- C08 pipeline security ----------------------------------------
	//
	// Every one of these describes a property of a CI pipeline. Gogs has
	// none, so all five are unconditionally unanswerable here.
	{
		id: "C08.actions.pinned", title: "Pipeline steps are pinned to immutable versions",
		collectorID: "C08.actions-security", scope: repoScoped,
		reason:      "Gogs has no CI system, so there are no pipeline steps to pin or to inspect",
		remediation: "Pipeline hardening applies to whatever system actually runs the builds.",
	},
	{
		id: "C08.actions.token-permissions", title: "Pipeline tokens are least-privilege",
		collectorID: "C08.actions-security", scope: repoScoped,
		reason: "Gogs has no CI system and issues no pipeline tokens, so there is no credential scope to " +
			"read or compare against least privilege",
		remediation: "Applies to the external build system, not to Gogs.",
	},
	{
		id: "C08.actions.pull-request-target", title: "No dangerous pull-request triggers are used",
		collectorID: "C08.actions-security", scope: repoScoped,
		reason: "Gogs has no CI system, so no pipeline triggers exist to audit — the dangerous-trigger " +
			"classes this check looks for are properties of workflow definitions that never execute here",
		remediation: "Applies to the external build system, not to Gogs.",
	},
	{
		id: "C08.actions.self-hosted", title: "Self-hosted runner usage is understood",
		collectorID: "C08.actions-security", scope: repoScoped,
		reason: "Gogs has no CI system and no runner concept, so there is no build machine — self-hosted " +
			"or otherwise — whose provenance this platform could report",
		remediation: "Applies to the external build system, not to Gogs.",
	},
	{
		id: "C08.actions.oidc-vs-secrets", title: "Pipelines prefer OIDC over long-lived secrets",
		collectorID: "C08.actions-security", scope: repoScoped,
		reason:      "Gogs has no CI system, so there are no pipeline credentials to compare",
		remediation: "Applies to the external build system, not to Gogs.",
	},

	// ---- C09 audit-logging --------------------------------------------
	//
	// Gogs writes a server log to disk on the host, which an operator can
	// read; it exposes no audit API at all. Repo webhooks are the one
	// exception in this family — they are listable, and this build simply
	// does not read them yet.
	{
		id: "C09.audit.org-log-available", title: "An organization audit log is available",
		collectorID: "C09.audit-logging", scope: orgScoped,
		reason: "Gogs has no audit-log API. The server writes an operational log to disk on the host, but it " +
			"is not an organization audit trail, is not exposed through the API, and cannot be read by " +
			"this tool",
		remediation: "If an audit trail is required, ship the Gogs server's own logs to a log store outside " +
			"the instance, and attest to that arrangement — the platform will not report it.",
	},
	{
		id: "C09.audit.log-streaming", title: "Audit events stream to external storage",
		collectorID: "C09.audit-logging", scope: orgScoped,
		reason:      "Gogs has no audit log and therefore no streaming configuration to read",
		remediation: "See C09.audit.org-log-available — host-level log shipping is the only equivalent.",
	},
	{
		id: "C09.audit.retention-awareness", title: "Audit log retention is understood",
		collectorID: "C09.audit-logging", scope: orgScoped,
		reason: "Gogs has no audit log, so it has no retention policy to report. Retention of the server's " +
			"operational log is a property of the host filesystem and whatever rotates it",
		remediation: "Document the host's log rotation and retention, and attest to it out of band.",
	},
	{
		id: "C09.repo.webhooks", title: "Repository webhooks are securely configured",
		collectorID: "C09.audit-logging", scope: repoScoped,
		reason: "Gogs does expose repository webhooks through GET /repos/{owner}/{repo}/hooks, so this is " +
			"checkable in principle — this build simply does not read them yet. Reported as not-checkable " +
			"rather than passed over, so the gap is visible: it is a gap in this scanner, not in the " +
			"platform",
		remediation: "No action available through this scanner yet. Review webhook targets and secrets in " +
			"the Gogs UI in the meantime.",
	},
}

// notCheckableRubric is every entry's rubric. There is exactly one status
// each of these can produce, and the rubric says why in general terms; the
// specific limitation is in each check's own Reason, which is what a pack
// reader actually sees.
const notCheckableRubric = "always. This check describes a control the Gogs platform either has no " +
	"mechanism for, or exposes data for that this build does not yet read — see the result's own Reason, " +
	"which distinguishes the two. It is never verified-fail: a verified-fail asserts that a control was " +
	"looked for and found absent, and nothing was looked for here"

func init() {
	for _, c := range checks {
		meta := collect.CheckMeta{
			ID:        c.id,
			Platform:  platform,
			Title:     c.title,
			Collector: c.collectorID,
			TokenScope: "none — no API call backs this check. A Gogs token is still needed for the scan as " +
				"a whole, but nothing about this result depends on what it can reach",
			Remediation: c.remediation,
			Rubric:      map[model.Status]string{model.StatusNotCheckable: notCheckableRubric},
			// Endpoints is deliberately empty: CheckMeta.Endpoints
			// documents what a check's own result depends on, and no
			// endpoint backs a fixed platform fact. C09.audit.log-streaming
			// on GitHub has the same shape for the same reason.
			Endpoints:  nil,
			FixtureRef: "internal/collect/gogs/unsupported/unsupported_test.go",
		}
		if c.scope == orgScoped {
			meta.ScopeLevel = collect.ScopeLevelOrg
		}
		collect.Register(meta)
	}
}

// Collector emits every unsupported check belonging to one collector ID.
// One instance per collector ID rather than a single catch-all: ID() is how
// the orchestrator's --check filter and its per-collector progress output
// identify work, so a single collector claiming to be all of C01 through
// C09 at once would break both.
type Collector struct {
	id     string
	checks []check
}

// Collectors returns one Collector per collector ID represented in the
// table, in stable order — the full set a Gogs scan wires in alongside the
// real collectors.
func Collectors() []collect.Collector {
	var ids []string
	grouped := map[string][]check{}
	for _, c := range checks {
		if _, seen := grouped[c.collectorID]; !seen {
			ids = append(ids, c.collectorID)
		}
		grouped[c.collectorID] = append(grouped[c.collectorID], c)
	}

	out := make([]collect.Collector, 0, len(ids))
	for _, id := range ids {
		out = append(out, &Collector{id: id, checks: grouped[id]})
	}
	return out
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return c.id }

// Collect implements collect.Collector. It makes no API call — every result
// is a fixed statement about the platform — so it cannot fail, ignores
// cancellation (there is nothing in flight to cancel and no call that could
// have been interrupted), and returns no error.
//
// Repo-scoped checks are emitted once per repo in scope. A scan with no
// repos still emits the org-scoped ones: an empty repo list is a scoping
// outcome, not a reason to drop statements about the account.
func (c *Collector) Collect(_ context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	var out []model.CheckResult
	for _, chk := range c.checks {
		if chk.scope == orgScoped {
			out = append(out, chk.result(scope.Org, ""))
			continue
		}
		for _, repo := range scope.Repos {
			out = append(out, chk.result(scope.Org, repo))
		}
	}
	return out, nil
}

func (c check) result(org, repo string) model.CheckResult {
	return model.CheckResult{
		CheckID: c.id,
		Title:   c.title,
		Status:  model.StatusNotCheckable,
		Reason:  c.reason,
		Scope:   model.ScopeRef{Org: org, Repo: repo, Platform: platform},
		// Never nil: the pack schema requires the field, and an empty
		// slice says "no calls backed this", where nil would be a
		// marshalling accident.
		Provenance: []model.Provenance{},
	}
}
