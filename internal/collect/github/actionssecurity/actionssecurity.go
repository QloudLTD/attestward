// Package actionssecurity implements C08 actions-security: the static
// security posture of a repo's GitHub Actions workflow files — third-party
// action pinning, explicit least-privilege GITHUB_TOKEN permissions,
// pull_request_target's checkout-of-PR-head danger pattern, OIDC vs.
// long-lived cloud credentials, and self-hosted runner exposure on public
// repos (SSDF PO.5.1, PW.4.1, PW.6.2). Pure static analysis of workflow
// YAML on the default branch — no run history, unlike C05/C06/C07.
package actionssecurity

import (
	"context"
	"fmt"
	"net/http"

	ghgithub "github.com/google/go-github/v75/github"

	"gitlab.com/sioakeim/attestward/internal/collect"
	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const collectorID = "C08.actions-security"

var checkTitles = map[string]string{
	checkPinnedID:           "Third-party actions and reusable workflows are pinned to a full commit SHA",
	checkTokenPermissionsID: "Workflows declare explicit, least-privilege GITHUB_TOKEN permissions",
	checkPRTargetID:         "pull_request_target is not combined with checking out the PR head",
	checkOIDCID:             "Cloud deployments use OIDC rather than long-lived static credentials",
	checkSelfHostedID:       "Self-hosted runners are not exposed to public-repo pull requests",
}

var checkIDs = []string{
	checkPinnedID,
	checkTokenPermissionsID,
	checkPRTargetID,
	checkOIDCID,
	checkSelfHostedID,
}

var checkRemediations = map[string]string{
	checkPinnedID: "Pin every third-party action/reusable-workflow `uses:` reference to a full 40-char " +
		"commit SHA, not a tag or branch (e.g. `uses: actions/checkout@<full-sha> # v5.0.0` — keep the " +
		"version as a comment for readability). A tool like `pin-github-action`/`pinact`, or Renovate's " +
		"digest-pinning preset, can do this initial tag-to-SHA conversion (Dependabot cannot — it only " +
		"keeps an already-pinned reference's version comment up to date going forward, via that same " +
		"trailing comment). First-party `actions/*` references on a mutable tag are tolerated (capped at " +
		"partial) but should be pinned too for a full pass.",
	checkTokenPermissionsID: "Add an explicit `permissions:` block — at workflow level, or per job for " +
		"finer scoping — set to the minimum needed (e.g. `contents: read`), not the ambient default. " +
		"Replace any `permissions: write-all` with a specific, scoped list of only the permissions that " +
		"job actually needs.",
	checkPRTargetID: "Switch the trigger to `pull_request` if privileged (secrets/write token) access to " +
		"the base repo isn't actually needed. If it genuinely is needed against fork code, use the " +
		"two-workflow pattern instead: an untrusted `pull_request`-triggered workflow that uploads an " +
		"artifact, and a separate, minimally-privileged `workflow_run`-triggered workflow that consumes " +
		"it — either fully eliminates the pull_request_target trigger and reaches a pass. Just removing " +
		"the `actions/checkout` step's PR-head ref (`github.event.pull_request.head.*` or `github.head_ref`) " +
		"while keeping the pull_request_target trigger only demotes this from a fail to partial — " +
		"pull_request_target itself is still flagged as risky by design.",
	checkOIDCID: "Configure the login action's OIDC parameters — for aws-actions/configure-aws-credentials " +
		"use `role-to-assume` (with `permissions: id-token: write` on the job); for azure/login use " +
		"`client-id`+`tenant-id`+`subscription-id` (also needs `permissions: id-token: write`); for " +
		"google-github-actions/auth use `workload_identity_provider` (also needs `permissions: id-token: " +
		"write`). If this replaces an existing long-lived static credential (verified-fail), delete it " +
		"afterward from repo/org Settings -> Secrets and variables; if instead neither an OIDC nor a " +
		"static-credential parameter was recognized at all (the \"ambiguous\" partial case), there's no " +
		"existing secret to remove — just add the OIDC parameters above.",
	checkSelfHostedID: "Only moving the job to a GitHub-hosted runner actually clears this check (it looks " +
		"solely at whether `runs-on: self-hosted` appears, not at trigger/approval settings). Real-world " +
		"exposure can also be reduced without changing this check's result: require approval for " +
		"first-time/outside contributors (Settings -> Actions -> General -> \"Approval for running fork " +
		"pull request workflows from contributors\"), or don't trigger the job on pull_request/" +
		"pull_request_target from forks at all.",
}

// sharedUpstreamFetchFailureRubric is shared by all five checks: the
// repo fetch and the workflow listing both early-return allNotCheckable
// in collectRepo — none of the five checks below can be computed
// without this shared evidence. Unlike C05-C07, this package never loads
// the embedded scanner-signature registry at all (pure static analysis
// of already-fetched workflow YAML, no runhistory.MatchWorkflows call),
// so there's no analogous binary-level-failure not-checkable cause here.
const sharedUpstreamFetchFailureRubric = "the repo fetch or the workflow listing failed (403/plan-gated/" +
	"other API error) — collectRepo returns not-checkable for every check on either failure, since none of " +
	"them can be computed without this shared evidence"

// sharedNoWorkflowsRubric is shared by four of the five checks (every one
// except oidc-vs-secrets, which folds this same cause into a differently-
// worded not-checkable reason — see its own rubric entry below). Kept
// in sync with checks.go's noWorkflowsReason: deliberately weaker than
// "no workflow files exist" — a listed file whose content couldn't be
// fetched or parsed also reaches this same not-checkable status,
// distinguished in the reason text (and skipped_workflows) once any
// were actually skipped.
const sharedNoWorkflowsRubric = "no GitHub Actions workflow file could be fetched and parsed from the " +
	"default branch — either none exist there, or GitHub listed one or more but every one failed to fetch " +
	"or parse (see skipped_workflows for which and why)"

// sharedIncompleteEvidencePartialRubric is shared by the four checks
// whose pass path is "no violation found among the workflows this
// collector could read" — pinned, token-permissions, pull-request-
// target, and oidc-vs-secrets. Each also caps at partial (rather than a
// confident pass) when a listed or referenced workflow couldn't be
// fetched or parsed at all: a clean result over incomplete evidence
// isn't the same claim as a clean result over everything that exists.
// self-hosted has its own, narrower version of this same idea — see its
// own rubric entry for why only ONE of its two pass sub-cases needs it.
const sharedIncompleteEvidencePartialRubric = "no violation was found among the workflows successfully " +
	"read, but one or more listed/referenced workflows could not be fetched or parsed — this result may be " +
	"incomplete (see skipped_workflows)"

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce — see checks.go for the pass/fail/partial logic
// each rubric below summarizes. C08.actions.self-hosted is notable:
// unlike every other check in this package, it has no verified-fail
// outcome at all — self-hosted-runner usage on a public repo is only
// ever capped at partial, by design (see checkSelfHosted's own doc
// comment).
var checkRubrics = map[string]map[model.Status]string{
	checkPinnedID: {
		model.StatusVerifiedPass: "no external action or reusable-workflow reference exists at all, or " +
			"every third-party reference (and every first-party `actions/*` reference) is pinned to a " +
			"full 40-character commit SHA — and every listed or referenced workflow was successfully " +
			"fetched and parsed (no skipped_workflows entries)",
		model.StatusPartial: "every third-party reference is pinned to a full commit SHA, but at least " +
			"one first-party `actions/*` reference uses a mutable tag instead; or " +
			sharedIncompleteEvidencePartialRubric,
		model.StatusVerifiedFail: "at least one third-party action or reusable-workflow reference is not " +
			"pinned to a full 40-character commit SHA",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or " + sharedNoWorkflowsRubric,
	},
	checkTokenPermissionsID: {
		model.StatusVerifiedPass: "every job (or its workflow, inherited when the job declares none of " +
			"its own) declares an explicit `permissions:` block that isn't `write-all` — and every listed " +
			"or referenced workflow was successfully fetched and parsed",
		model.StatusPartial: "some but not all jobs/workflows declare an explicit `permissions:` block; " +
			"or every one does, but at least one is `write-all` rather than a scoped, least-privilege set; " +
			"or " + sharedIncompleteEvidencePartialRubric,
		model.StatusVerifiedFail: "no job or workflow declares an explicit `permissions:` block at all — " +
			"every job runs with the ambient default GITHUB_TOKEN permissions",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or " + sharedNoWorkflowsRubric,
	},
	checkPRTargetID: {
		model.StatusVerifiedPass: "no workflow triggers on `pull_request_target` at all — and every " +
			"listed or referenced workflow was successfully fetched and parsed",
		model.StatusPartial: "`pull_request_target` is used, but no checkout of the PR head commit/" +
			"branch was detected in any of its jobs — still a risky trigger by design, but no confirmed " +
			"exploit pattern found; or " + sharedIncompleteEvidencePartialRubric,
		model.StatusVerifiedFail: "at least one `pull_request_target`-triggered workflow checks out the " +
			"PR head commit/branch (an `actions/checkout` step whose `with.ref` references " +
			"`github.event.pull_request.head.{sha,ref}` or the `github.head_ref` alias) — the classic " +
			"\"pwn request\" pattern",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or " + sharedNoWorkflowsRubric,
	},
	checkOIDCID: {
		model.StatusVerifiedPass: "every detected cloud-deployment login step (AWS/Azure/GCP's official " +
			"login action) sets a recognized OIDC parameter — for azure/login specifically, BOTH " +
			"`client-id` and `tenant-id` — and no recognized static-credential parameter; and every " +
			"listed or referenced workflow was successfully fetched and parsed",
		model.StatusPartial: "at least one detected cloud-deployment login step sets no recognized " +
			"static-credential parameter, and doesn't set a complete OIDC parameter set either (for " +
			"azure/login, setting only `client-id` or only `tenant-id` — not both — still counts as " +
			"ambiguous here, not OIDC) — not confirmed either way; or " + sharedIncompleteEvidencePartialRubric,
		model.StatusVerifiedFail: "at least one detected cloud-deployment login step sets a recognized " +
			"long-lived static-credential parameter (a static parameter always wins over an OIDC one if " +
			"both are somehow present)",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or no cloud-deployment login " +
			"action (aws-actions/configure-aws-credentials, azure/login, or google-github-actions/auth) " +
			"was found among the workflows successfully read — either because none exists there, or " +
			"because one or more listed/referenced workflows couldn't be fetched or parsed at all (see " +
			"skipped_workflows for which)",
	},
	checkSelfHostedID: {
		model.StatusVerifiedPass: "no job uses `runs-on: self-hosted` at all, and every listed or " +
			"referenced workflow was successfully fetched and parsed; or one or more self-hosted usages " +
			"ARE found but the repository is private (the public-fork attack vector this check flags " +
			"doesn't apply) — that specific pass sub-case is unaffected by any skipped workflow, since a " +
			"confirmed finding on a private repo can't be weakened by what else might be unread",
		model.StatusPartial: "one or more jobs use `runs-on: self-hosted` and the repository is public — " +
			"an external contributor's pull request is a potential path to the runner; or no self-hosted " +
			"usage was found among the workflows successfully read, but one or more listed/referenced " +
			"workflows could not be fetched or parsed — this result may be incomplete. This check has no " +
			"verified-fail outcome: self-hosted-runner usage is only ever capped at partial, by design, " +
			"never a hard fail",
		model.StatusNotCheckable: sharedUpstreamFetchFailureRubric + "; or " + sharedNoWorkflowsRubric,
	},
}

// sharedEvidenceEndpoints are the calls that determine units (every
// fetched/parsed workflow file, including same-org reusable workflows
// resolved one level deep) and, via the same repo fetch, defaultBranch
// and private — used by every one of the five checks. Unlike the other
// four, checkTokenPermissions also reads a sixth endpoint
// (GetDefaultWorkflowPermissions) in collectRepo, but that call's result
// is Facts-only context (repo_default_workflow_permissions) — it never
// feeds this check's Status determination, so it's deliberately excluded
// here per this project's "Endpoints backs Status" convention (see
// checkTokenPermissions' own doc comment for why the default setting is
// never a substitute for an explicit permissions: block).
var sharedEvidenceEndpoints = []string{
	"GET /repos/{owner}/{repo}",
	"GET /repos/{owner}/{repo}/actions/workflows",
	"GET /repos/{owner}/{repo}/contents/{path}",
}

var checkEndpoints = map[string][]string{
	checkPinnedID:           append([]string{}, sharedEvidenceEndpoints...),
	checkTokenPermissionsID: append([]string{}, sharedEvidenceEndpoints...),
	checkPRTargetID:         append([]string{}, sharedEvidenceEndpoints...),
	checkOIDCID:             append([]string{}, sharedEvidenceEndpoints...),
	checkSelfHostedID:       append([]string{}, sharedEvidenceEndpoints...),
}

const fixtureRef = "internal/collect/github/actionssecurity/actionssecurity_test.go"

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:        id,
			Platform:  "github",
			Title:     checkTitles[id],
			Collector: collectorID,
			TokenScope: "repo (classic) or Contents: read-only (fine-grained) for workflow file content — plus " +
				"Administration: read-only (fine-grained) for the repo default-workflow-permissions context fact, " +
				"which this collector tolerates failing to read rather than treating as fatal; exact fine-grained " +
				"category for that one unverified, see C05's TokenScope for the same kind of hedge",
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			FixtureRef:  fixtureRef,
		})
	}
}

// Collector implements C08 actions-security.
type Collector struct {
	token string

	// hostConfig carries the resolved GHES base URL/CA (or the zero value,
	// for github.com) into every per-repo Client this collector builds —
	// see ghcollect.ResolveHostConfig (issue #11).
	hostConfig ghcollect.ClientConfig

	// newClientForTest overrides how each repo's Client is constructed —
	// see sasthistory.Collector's identical field for why.
	newClientForTest func(token string) *ghcollect.Client
}

// New returns a C08 collector authenticated with token, targeting cfg's
// host — github.com for the zero value, or a GitHub Enterprise Server
// install (issue #11). Per-repo checks fan out via ForEachRepo's concurrent
// worker pool, so each repo constructs its own Client — see
// sasthistory.New's doc comment for why a shared client across concurrent
// repos would corrupt provenance attribution.
func New(token string, cfg ghcollect.ClientConfig) *Collector {
	return &Collector{token: token, hostConfig: cfg}
}

func (c *Collector) newClient() *ghcollect.Client {
	if c.newClientForTest != nil {
		return c.newClientForTest(c.token)
	}
	return ghcollect.NewClient(c.token, c.hostConfig)
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. It never returns a non-nil
// top-level error for a per-repo API failure — see org-security's Collect
// doc comment for why that matters for the rollup.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	repoResults := ghcollect.ForEachRepo(ctx, scope.Repos, ghcollect.DefaultConcurrency, func(ctx context.Context, repo string) ([]model.CheckResult, error) {
		client := c.newClient()
		return collectRepo(ctx, client, scope.Org, repo), nil
	})

	var all []model.CheckResult
	for _, r := range repoResults {
		if r.Err != nil {
			all = append(all, allNotCheckable(scope.Org, r.Repo, fmt.Sprintf("scan canceled before this repo's checks ran: %v", r.Err), nil)...)
			continue
		}
		all = append(all, r.Value...)
	}
	if all == nil {
		all = []model.CheckResult{}
	}
	return all, nil
}

// collectRepo fetches every workflow file on the repo's default branch
// (plus, one level deep, any same-org reusable workflows they call), then
// derives all five CheckResults from that single fetched set — none of the
// five checks needs its own additional API call except token-permissions'
// context fact. It never returns an error; every failure becomes a
// not-checkable result for the affected check(s).
func collectRepo(ctx context.Context, client *ghcollect.Client, org, repo string) []model.CheckResult {
	// prevLen starts at 0, not len(client.Provenance()) after the Get call
	// below — client is freshly constructed per repo, so Provenance() is
	// empty at this point anyway, and starting here means the first
	// snapshot() call includes this initial Get's own provenance entry
	// (see C07's provenance.go for the bug this ordering avoids).
	prevLen := 0
	snapshot := func() []model.Provenance {
		all := client.Provenance()
		seg := append([]model.Provenance{}, all[prevLen:]...)
		prevLen = len(all)
		return seg
	}

	repository, resp, err := client.REST.Repositories.Get(ctx, org, repo)
	if err != nil {
		return allNotCheckable(org, repo, notCheckableReason(resp, err, org, repo), client.Provenance())
	}
	defaultBranch := repository.GetDefaultBranch()
	private := repository.GetPrivate()

	units, skippedDirect, wfResp, err := fetchWorkflows(ctx, client, org, repo, defaultBranch)
	if err != nil {
		return allNotCheckable(org, repo, notCheckableReason(wfResp, err, org, repo), client.Provenance())
	}

	reusable, unresolvedExternal, skippedReusable := resolveReusableWorkflows(ctx, client, org, repo, units)
	units = append(units, reusable...)
	coreProv := snapshot()

	// skipped is every listed or referenced workflow this collector
	// couldn't turn into evidence for a reason other than a benign
	// 404-at-ref — passed to every check so none of them assert a
	// confident verified-pass ("no violation found") over evidence that
	// was actually incomplete. See skippedWorkflow's doc comment.
	skipped := append(append([]skippedWorkflow{}, skippedDirect...), skippedReusable...)

	defaultPerm, defaultPermKnown := fetchDefaultWorkflowPermissions(ctx, client, org, repo)
	permProv := snapshot()

	return []model.CheckResult{
		checkPinned(org, repo, units, unresolvedExternal, skipped, coreProv),
		checkTokenPermissions(org, repo, units, defaultPerm, defaultPermKnown, skipped, concatProv(coreProv, permProv)),
		checkPullRequestTarget(org, repo, units, skipped, coreProv),
		checkOIDCvsSecrets(org, repo, units, skipped, coreProv),
		checkSelfHosted(org, repo, units, private, skipped, coreProv),
	}
}

// fetchDefaultWorkflowPermissions reads the repo's default GITHUB_TOKEN
// permission setting purely as a context fact for token-permissions (see
// that check's doc comment) — this endpoint commonly needs repo-admin
// access, so a failure here is tolerated rather than failing the whole
// repo's checks.
func fetchDefaultWorkflowPermissions(ctx context.Context, client *ghcollect.Client, org, repo string) (string, bool) {
	perm, _, err := client.REST.Repositories.GetDefaultWorkflowPermissions(ctx, org, repo)
	if err != nil || perm == nil {
		return "", false
	}
	return perm.GetDefaultWorkflowPermissions(), true
}

func notCheckableReason(resp *ghgithub.Response, err error, org, repo string) string {
	if resp != nil {
		switch {
		case resp.StatusCode == http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to read %s/%s", org, repo)
		case ghcollect.IsPlanGated(resp.StatusCode):
			return fmt.Sprintf("feature not available for %s/%s (plan-gated, or repository not found)", org, repo)
		}
	}
	return fmt.Sprintf("could not query %s/%s: %v", org, repo, err)
}

func concatProv(segments ...[]model.Provenance) []model.Provenance {
	var out []model.Provenance
	for _, s := range segments {
		out = append(out, s...)
	}
	if out == nil {
		out = []model.Provenance{}
	}
	return out
}

func allNotCheckable(org, repo, reason string, prov []model.Provenance) []model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	out := make([]model.CheckResult, 0, len(checkIDs))
	for _, id := range checkIDs {
		out = append(out, model.CheckResult{
			CheckID:    id,
			Title:      checkTitles[id],
			Status:     model.StatusNotCheckable,
			Reason:     reason,
			Scope:      model.ScopeRef{Org: org, Repo: repo},
			Provenance: prov,
		})
	}
	return out
}
