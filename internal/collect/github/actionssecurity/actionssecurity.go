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

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/model"
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

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:        id,
			Title:     checkTitles[id],
			Collector: collectorID,
			TokenScope: "repo (classic) or Contents: read-only (fine-grained) for workflow file content — plus " +
				"Administration: read-only (fine-grained) for the repo default-workflow-permissions context fact, " +
				"which this collector tolerates failing to read rather than treating as fatal; exact fine-grained " +
				"category for that one unverified, see C05's TokenScope for the same kind of hedge",
			Remediation: checkRemediations[id],
		})
	}
}

// Collector implements C08 actions-security.
type Collector struct {
	token string

	// newClientForTest overrides how each repo's Client is constructed —
	// see sasthistory.Collector's identical field for why.
	newClientForTest func(token string) *ghcollect.Client
}

// New returns a C08 collector authenticated with token. Per-repo checks
// fan out via ForEachRepo's concurrent worker pool, so each repo
// constructs its own Client — see sasthistory.New's doc comment for why a
// shared client across concurrent repos would corrupt provenance
// attribution.
func New(token string) *Collector {
	return &Collector{token: token}
}

func (c *Collector) newClient() *ghcollect.Client {
	if c.newClientForTest != nil {
		return c.newClientForTest(c.token)
	}
	return ghcollect.NewClient(c.token)
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

	units, wfResp, err := fetchWorkflows(ctx, client, org, repo, defaultBranch)
	if err != nil {
		return allNotCheckable(org, repo, notCheckableReason(wfResp, err, org, repo), client.Provenance())
	}

	reusable, unresolvedExternal := resolveReusableWorkflows(ctx, client, org, units)
	units = append(units, reusable...)
	coreProv := snapshot()

	defaultPerm, defaultPermKnown := fetchDefaultWorkflowPermissions(ctx, client, org, repo)
	permProv := snapshot()

	return []model.CheckResult{
		checkPinned(org, repo, units, unresolvedExternal, coreProv),
		checkTokenPermissions(org, repo, units, defaultPerm, defaultPermKnown, concatProv(coreProv, permProv)),
		checkPullRequestTarget(org, repo, units, coreProv),
		checkOIDCvsSecrets(org, repo, units, coreProv),
		checkSelfHosted(org, repo, units, private, coreProv),
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
