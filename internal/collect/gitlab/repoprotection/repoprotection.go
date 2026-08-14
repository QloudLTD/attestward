// Package repoprotection implements C02 repo-protection for GitLab (#1).
//
// GitLab spreads this control area across three endpoints, and each answers
// a different question:
//
//   - GET /projects/{id}                       — default branch, and the
//     merge gates that live on the project rather than the branch
//     (only_allow_merge_if_pipeline_succeeds)
//   - GET /projects/{id}/protected_branches    — force-push, code-owner
//     approval, and who may push or merge
//   - GET /projects/{id}/approvals             — approvals_before_merge and
//     whether an author may approve their own change
//
// # Two GitLab behaviours drive most of the mapping
//
// **Deletion is only partly blocked.** On GitHub, allow_deletions=false blocks
// deletion outright. GitLab has no equivalent toggle: protecting a branch stops
// deletion from Git clients, but a Maintainer or Owner can still delete it
// through the UI or API. So this check never reports a pass — partial is the
// honest ceiling, and the remaining control is who holds Maintainer.
//
// **Approval rules are tier-split.** approvals_before_merge is readable on
// Free. Richer rules — required approvers per path, code-owner enforcement
// as a gate — are Premium, and GET /projects/{id}/approval_settings returns
// an empty rules array on Free rather than an error. An empty array there
// means "not entitled", not "no rules", so this collector reads the Free
// field and does not infer anything from the empty one.
//
// # Nothing here reports a fail because of a missing entitlement
//
// Every tier-gated read is translated to not-checkable naming the tier. A
// verified-fail asserts a control was looked for and found absent; on a Free
// project the richer approval surface was never visible to look at.
package repoprotection

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const (
	platform    = "gitlab"
	collectorID = "C02.repo-protection"

	idProtectionExists     = "C02.branch.protection-exists"
	idForcePushBlocked     = "C02.branch.force-push-blocked"
	idDeletionBlocked      = "C02.branch.deletion-blocked"
	idRequiredReviews      = "C02.branch.required-reviews"
	idRequiredStatusChecks = "C02.branch.required-status-checks"
	idAdminEnforced        = "C02.branch.admin-enforced"
)

type project struct {
	Path                             string `json:"path"`
	DefaultBranch                    string `json:"default_branch"`
	OnlyAllowMergeIfPipelineSucceeds bool   `json:"only_allow_merge_if_pipeline_succeeds"`
	AllowMergeOnSkippedPipeline      *bool  `json:"allow_merge_on_skipped_pipeline"`
}

type accessLevel struct {
	AccessLevel            int    `json:"access_level"`
	AccessLevelDescription string `json:"access_level_description"`
}

type protectedBranch struct {
	Name                      string        `json:"name"`
	AllowForcePush            bool          `json:"allow_force_push"`
	CodeOwnerApprovalRequired bool          `json:"code_owner_approval_required"`
	PushAccessLevels          []accessLevel `json:"push_access_levels"`
	MergeAccessLevels         []accessLevel `json:"merge_access_levels"`
}

type approvals struct {
	ApprovalsBeforeMerge        int  `json:"approvals_before_merge"`
	MergeRequestsAuthorApproval bool `json:"merge_requests_author_approval"`
	ResetApprovalsOnPush        bool `json:"reset_approvals_on_push"`
}

// Collector reads one project's branch-protection posture.
type Collector struct {
	baseURL, token string
	newClient      func() (*gitlabcollect.Client, error)
}

// New builds the collector against a live GitLab instance.
func New(baseURL, token string) *Collector {
	c := &Collector{baseURL: baseURL, token: token}
	c.newClient = func() (*gitlabcollect.Client, error) { return gitlabcollect.NewClient(baseURL, token) }
	return c
}

// NewForTest builds the collector against an arbitrary base URL and
// round-tripper, so tests exercise the same client production assembles.
func NewForTest(baseURL, token string, newClient func() (*gitlabcollect.Client, error)) *Collector {
	return &Collector{baseURL: baseURL, token: token, newClient: newClient}
}

// ID returns the collector identifier recorded on every result it emits.
func (c *Collector) ID() string { return collectorID }

// Collect reads the project and its protected branches and returns one
// result per registered check. A read failure yields not-checkable results
// rather than an error, so one unreadable project cannot fail a whole scan.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	var out []model.CheckResult
	for _, repo := range scope.Repos {
		out = append(out, c.collectRepo(ctx, scope.Org, repo)...)
	}
	return out, nil
}

func (c *Collector) collectRepo(ctx context.Context, org, repo string) []model.CheckResult {
	client, err := c.newClient()
	if err != nil {
		return allNotCheckable(org, repo, fmt.Sprintf("could not build a GitLab client: %v", err), nil)
	}
	id := projectID(org, repo)

	var proj project
	if err := gitlabcollect.GetJSON(ctx, client, "/projects/"+id, nil, &proj); err != nil {
		return allNotCheckable(org, repo, describeErr("project", org+"/"+repo, err), client.Provenance())
	}
	if proj.DefaultBranch == "" {
		return resultsWithoutBranchData(org, repo, proj,
			"the project has no default branch — it is empty, so there is no branch to protect and nothing to evidence yet",
			client.Provenance())
	}

	branches, err := gitlabcollect.GetJSONPaged[protectedBranch](ctx, client, "/projects/"+id+"/protected_branches", nil)
	if err != nil {
		return resultsWithoutBranchData(org, repo, proj,
			describeErr("protected branches", org+"/"+repo, err), client.Provenance())
	}

	// Every rule whose pattern matches the default branch, not just an exact
	// name match. GitLab protected-branch rules accept wildcards, so a branch
	// protected only by "*" or "ma*" has no exact entry — matching by name
	// alone fabricated three failures for a correctly protected repository.
	//
	// ⚠ And where several rules match, GitLab applies the MOST PERMISSIVE.
	// Reading only the exact rule could therefore report allow_force_push=false
	// while a wildcard rule alongside it actually permits force pushes: a false
	// pass, which is the worst outcome this tool can produce.
	def := mergeMatchingRules(branches, proj.DefaultBranch)

	// Approvals is read separately and is allowed to fail without sinking the
	// rest: on some tiers and token scopes it 403s, and that must not turn
	// force-push evidence into a non-answer.
	var appr approvals
	apprErr := gitlabcollect.GetJSON(ctx, client, "/projects/"+id+"/approvals", nil, &appr)

	prov := client.Provenance()
	results := []model.CheckResult{
		protectionExists(org, repo, proj, def),
		forcePush(org, repo, proj, def),
		deletionBlocked(org, repo, proj, def),
		requiredReviews(org, repo, proj, appr, apprErr),
		requiredStatusChecks(org, repo, proj),
	}
	for i := range results {
		results[i].Provenance = prov
	}
	// admin-enforced is appended after the provenance loop, not inside it: no
	// API call backs it, so citing the two reads as its evidence would claim a
	// basis it never used. Same treatment as envseparation's branch-policy.
	return append(results, adminEnforced(org, repo))
}

func protectionExists(org, repo string, p project, b *protectedBranch) model.CheckResult {
	if b == nil {
		return res(idProtectionExists, "Default branch is protected", model.StatusVerifiedFail, org, repo,
			fmt.Sprintf("the default branch %q has no protected-branch rule, so anyone with push access can commit to it directly", p.DefaultBranch),
			map[string]any{"default_branch": p.DefaultBranch, "protected": false})
	}
	return res(idProtectionExists, "Default branch is protected", model.StatusVerifiedPass, org, repo,
		fmt.Sprintf("the default branch %q has a protected-branch rule (push: %s, merge: %s)",
			p.DefaultBranch, describeLevels(b.PushAccessLevels), describeLevels(b.MergeAccessLevels)),
		map[string]any{
			"default_branch": p.DefaultBranch, "protected": true,
			"push_access": describeLevels(b.PushAccessLevels), "merge_access": describeLevels(b.MergeAccessLevels),
		})
}

func forcePush(org, repo string, p project, b *protectedBranch) model.CheckResult {
	if b == nil {
		return res(idForcePushBlocked, "Force pushes are blocked on the default branch", model.StatusVerifiedFail, org, repo,
			fmt.Sprintf("the default branch %q is not protected at all, so force pushes are not restricted", p.DefaultBranch),
			map[string]any{"protected": false})
	}
	if b.AllowForcePush {
		return res(idForcePushBlocked, "Force pushes are blocked on the default branch", model.StatusVerifiedFail, org, repo,
			fmt.Sprintf("the protected-branch rule for %q sets allow_force_push=true, so history on the default branch can be rewritten", p.DefaultBranch),
			map[string]any{"allow_force_push": true})
	}
	return res(idForcePushBlocked, "Force pushes are blocked on the default branch", model.StatusVerifiedPass, org, repo,
		fmt.Sprintf("the protected-branch rule for %q sets allow_force_push=false", p.DefaultBranch),
		map[string]any{"allow_force_push": false})
}

// deletionBlocked derives from protection rather than a dedicated field —
// see the package doc. The reason states the derivation so a reader does not
// take the pass as evidence of a setting GitLab does not have.
func deletionBlocked(org, repo string, p project, b *protectedBranch) model.CheckResult {
	if b == nil {
		return res(idDeletionBlocked, "Default branch cannot be deleted", model.StatusVerifiedFail, org, repo,
			fmt.Sprintf("the default branch %q is not protected, so it can be deleted by anyone who can push to it", p.DefaultBranch),
			map[string]any{"protected": false})
	}
	// ⚠ Protection does NOT make a branch undeletable on GitLab. It blocks
	// deletion from Git clients, but a user with Maintainer or Owner can still
	// delete a protected branch through the web UI. An earlier version of this
	// check claimed otherwise and reported verified-pass, which put a false
	// statement into signed evidence: a reader would conclude the branch was
	// deletion-proof when a Maintainer could remove it in two clicks.
	//
	// GitHub's allow_deletions=false genuinely does block deletion, so the same
	// status must not mean both things. Partial is the honest answer here.
	return res(idDeletionBlocked, "Default branch cannot be deleted", model.StatusPartial, org, repo,
		fmt.Sprintf("the default branch %q is protected, which blocks deletion from Git clients — but GitLab still "+
			"permits a Maintainer or Owner to delete a protected branch through the web UI, so this is not the "+
			"absolute block GitHub's allow_deletions provides. Limit who holds Maintainer and above", p.DefaultBranch),
		map[string]any{"protected": true, "git_client_deletion_blocked": true, "ui_deletion_allowed_from": "Maintainer"})
}

func requiredReviews(org, repo string, _ project, a approvals, err error) model.CheckResult {
	if err != nil {
		if gitlabcollect.IsTierGated(err) {
			// ⚠ Do not attribute this 403 to tier alone. Two causes produce it
			// and the response body distinguishes neither: the token sits below
			// Maintainer (GET /projects/:id/approvals answers 403 at Reporter,
			// measured live — issue #18), or the tier does not entitle the
			// richer approval surface. Naming only the tier told an operator
			// whose token was simply under-scoped that they had nothing to fix.
			return res(idRequiredReviews, "Merge requests require review", model.StatusNotCheckable, org, repo,
				"the project approvals API is not readable with this token or tier (HTTP 403). Either the token is "+
					"below Maintainer — this endpoint returns 403 at Reporter — or the project's tier does not "+
					"entitle the richer approval surface, and the response does not say which. Merge-request "+
					"approval rules are a paid-tier feature on GitLab, and an unreadable rule set is not evidence "+
					"that no review is required", nil)
		}
		return res(idRequiredReviews, "Merge requests require review", model.StatusNotCheckable, org, repo,
			fmt.Sprintf("could not read the project approvals settings: %v", err), nil)
	}
	if a.ApprovalsBeforeMerge < 1 {
		// ⚠ Do NOT fail from this field alone. approvals_before_merge was
		// deprecated in GitLab 12.3 and does not reflect approval *rules*,
		// which are how required review is configured on Premium and above. A
		// project enforcing "2 approvals" through a rule still reports 0 here,
		// so failing on it asserted "can be merged with no approval from
		// anyone" about projects where it plainly could not.
		//
		// Rules live behind a paid tier, so their absence on Free is a tier
		// limitation rather than a finding — verified on a Free namespace,
		// where setting approvals_before_merge is accepted and then ignored.
		return res(idRequiredReviews, "Merge requests require review", model.StatusNotCheckable, org, repo,
			"approvals_before_merge is 0, but that field was deprecated in GitLab 12.3 and does not reflect "+
				"approval rules, which are the modern mechanism and a paid-tier feature. A zero here is therefore "+
				"consistent both with no review requirement and with a rule this tier cannot expose, and the two "+
				"cannot be distinguished from the readable API surface",
			map[string]any{"approvals_before_merge": a.ApprovalsBeforeMerge, "field_deprecated_since": "12.3"})
	}
	// ⚠ A value >= 1 is no more trustworthy than a 0. The same deprecation
	// applies: on a Free namespace approvals_before_merge is accepted and then
	// ignored, so a project reading 2 may enforce nothing at all. Reporting
	// verified-pass from it would be the mirror image of the fail this function
	// already refuses to emit — and a false pass is the worse of the two.
	//
	// Only an approval RULE positively confirms enforcement, and rules are a
	// paid-tier feature, so the honest answer without one is partial.
	return res(idRequiredReviews, "Merge requests require review", model.StatusPartial, org, repo,
		fmt.Sprintf("approvals_before_merge is %d, but that field was deprecated in GitLab 12.3 and is not what "+
			"enforces review on current versions — approval rules are, and they are a paid-tier feature this scan "+
			"could not read. The value indicates intent; it is not evidence the gate is enforced%s",
			a.ApprovalsBeforeMerge, authorNote(a)),
		map[string]any{
			"approvals_before_merge":         a.ApprovalsBeforeMerge,
			"merge_requests_author_approval": a.MergeRequestsAuthorApproval,
			"reset_approvals_on_push":        a.ResetApprovalsOnPush,
			"field_deprecated_since":         "12.3",
		})
}

func authorNote(a approvals) string {
	if a.MergeRequestsAuthorApproval {
		return ". Additionally merge_requests_author_approval is true, so an author could supply that approval themselves"
	}
	return ""
}

func requiredStatusChecks(org, repo string, p project) model.CheckResult {
	if !p.OnlyAllowMergeIfPipelineSucceeds {
		return res(idRequiredStatusChecks, "Merges require passing checks", model.StatusVerifiedFail, org, repo,
			"only_allow_merge_if_pipeline_succeeds is false, so a merge request can be merged while its pipeline is failing or absent",
			map[string]any{"only_allow_merge_if_pipeline_succeeds": false})
	}
	if p.AllowMergeOnSkippedPipeline != nil && *p.AllowMergeOnSkippedPipeline {
		return res(idRequiredStatusChecks, "Merges require passing checks", model.StatusPartial, org, repo,
			"only_allow_merge_if_pipeline_succeeds is true, but allow_merge_on_skipped_pipeline is also true — a "+
				"skipped pipeline satisfies the gate, so a change that runs no jobs can merge unchecked",
			map[string]any{"only_allow_merge_if_pipeline_succeeds": true, "allow_merge_on_skipped_pipeline": true})
	}
	return res(idRequiredStatusChecks, "Merges require passing checks", model.StatusVerifiedPass, org, repo,
		"only_allow_merge_if_pipeline_succeeds is true", map[string]any{"only_allow_merge_if_pipeline_succeeds": true})
}

// adminEnforced has no GitLab equivalent worth asserting. GitHub's
// enforce_admins makes a rule apply to administrators too; GitLab's model is
// access levels, where a rule permitting only Maintainers already binds
// everyone below Owner, and an Owner can always edit the rule. Reporting a
// pass or fail would be mapping a control that does not exist.
//
// It reads nothing and takes no arguments beyond the scope, so every path
// through collectRepo emits it — including the failure paths, which used to
// replace this reason with whichever read had failed (issue #21). The status
// was right for a stated cause that was never the real one: a reader was told
// protected branches were unreadable, when the actual reason is that GitLab
// models no such control and no read could ever answer it. It carries no
// provenance for the same reason.
func adminEnforced(org, repo string) model.CheckResult {
	return res(idAdminEnforced, checkTitles[idAdminEnforced], model.StatusNotCheckable, org, repo,
		"GitLab has no equivalent of GitHub's enforce_admins. Protection is expressed as access levels rather than a "+
			"rule with an admin exemption, so there is no setting that says whether administrators are bound. An "+
			"Owner can always change a protected-branch rule; a check reporting pass or fail here would be asserting "+
			"a control GitLab does not model", nil)
}

func describeLevels(levels []accessLevel) string {
	if len(levels) == 0 {
		return "nobody"
	}
	out := ""
	for i, l := range levels {
		if i > 0 {
			out += ", "
		}
		if l.AccessLevelDescription != "" {
			out += l.AccessLevelDescription
			continue
		}
		out += fmt.Sprintf("access_level=%d", l.AccessLevel)
	}
	return out
}

func describeErr(what, subject string, err error) string {
	code, ok := gitlabcollect.StatusCodeOf(err)
	switch {
	case ok && code == http.StatusNotFound:
		return fmt.Sprintf("%s for %q was not found, or the token cannot see it — GitLab answers 404 rather than 403 "+
			"for a private project a credential has no access to, so this cannot distinguish the two", what, subject)
	case ok && code == http.StatusForbidden:
		return fmt.Sprintf("the token is not permitted to read %s for %q (HTTP 403)", what, subject)
	default:
		return fmt.Sprintf("could not read %s for %q: %v", what, subject, err)
	}
}

var checkTitles = map[string]string{
	idProtectionExists:     "Default branch is protected",
	idForcePushBlocked:     "Force pushes are blocked on the default branch",
	idDeletionBlocked:      "Default branch cannot be deleted",
	idRequiredReviews:      "Merge requests require review",
	idRequiredStatusChecks: "Merges require passing checks",
	idAdminEnforced:        "Branch protection applies to administrators",
}

// allNotCheckable covers the two states where nothing at all was read: the
// client could not be built, or GET /projects/{id} failed. admin-enforced is
// still emitted with its own reason rather than the caller's — see its doc
// comment.
func allNotCheckable(org, repo, reason string, prov []model.Provenance) []model.CheckResult {
	out := notCheckable(org, repo, reason, prov,
		idProtectionExists, idForcePushBlocked, idDeletionBlocked, idRequiredReviews, idRequiredStatusChecks)
	return append(out, adminEnforced(org, repo))
}

// resultsWithoutBranchData covers the two states where GET /projects/{id}
// succeeded but the protected-branch data did not arrive: the project is
// empty, so there is no branch to look up, or the protected_branches read
// failed outright.
//
// Two of the six checks survive that, and before issue #21 both were swept
// into the abort:
//
//   - required-status-checks reads only only_allow_merge_if_pipeline_succeeds
//     and allow_merge_on_skipped_pipeline, which are fields of the project
//     object already in hand. Its registered endpoint list says so: GET
//     /projects/{id}, and nothing else. Reporting it not-checkable discarded a
//     computed answer and blamed a read it never depends on.
//   - admin-enforced reads nothing at all.
//
// required-reviews does NOT survive: its endpoint, GET /projects/{id}/approvals,
// is reached only after the protected-branches read and so was never attempted
// on either path. It stays not-checkable, but says that rather than implying
// its own data was unreadable.
func resultsWithoutBranchData(org, repo string, p project, branchReason string, prov []model.Provenance) []model.CheckResult {
	out := notCheckable(org, repo, branchReason, prov, idProtectionExists, idForcePushBlocked, idDeletionBlocked)
	out = append(out, notCheckable(org, repo,
		"this check's own endpoint, GET /projects/{id}/approvals, was never attempted — the scan stopped "+
			"before reaching it: "+branchReason, prov, idRequiredReviews)...)

	statusChecks := requiredStatusChecks(org, repo, p)
	statusChecks.Provenance = provOrEmpty(prov)
	return append(out, statusChecks, adminEnforced(org, repo))
}

func notCheckable(org, repo, reason string, prov []model.Provenance, ids ...string) []model.CheckResult {
	prov = provOrEmpty(prov)
	out := make([]model.CheckResult, 0, len(ids))
	for _, id := range ids {
		r := res(id, checkTitles[id], model.StatusNotCheckable, org, repo, reason, nil)
		r.Provenance = prov
		out = append(out, r)
	}
	return out
}

// provOrEmpty keeps a nil slice out of the result: nil marshals to null, and
// the evidence schema wants an array.
func provOrEmpty(prov []model.Provenance) []model.Provenance {
	if prov == nil {
		return []model.Provenance{}
	}
	return prov
}

func res(id, title string, status model.Status, org, repo, reason string, facts map[string]any) model.CheckResult {
	return model.CheckResult{
		CheckID:    id,
		Title:      title,
		Status:     status,
		Reason:     reason,
		Scope:      model.ScopeRef{Org: org, Repo: repo, Platform: platform},
		Facts:      facts,
		Provenance: []model.Provenance{},
	}
}

// projectID builds the URL-encoded "group/project" id GitLab addresses
// projects by.
func projectID(org, repo string) string {
	return escapePath(org) + "%2F" + escapePath(repo)
}

func escapePath(s string) string {
	out := make([]byte, 0, len(s)+8)
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			out = append(out, '%', '2', 'F')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// GET /projects/:id and GET /projects/:id/protected_branches both answer 200
// to a read_api token at Reporter, so the four checks derived from them are
// reachable at that role.
const branchTokenScope = "read_api (Reporter or above on the project)"

// admin-enforced makes no request of its own — GitLab models no control for
// it to read (see adminEnforced) — so no role makes it resolve and none is
// documented. Same wording as auditlogging and envseparation's branch-policy,
// which are the same shape of check.
//
// It documented branchTokenScope until issue #21, and that was honest at the
// time for a bad reason: a failed protected-branches read used to blank this
// check out with its siblings, so the role that made THAT read succeed did in
// practice decide what an operator saw here. Now that it is emitted on every
// path, nothing about it depends on the token any more.
const noAPICallTokenScope = "none — no API call backs this check. A GitLab token is still needed for the scan " +
	"as a whole, but nothing about this result depends on what it can reach"

// required-reviews needs a strictly higher role than its five siblings:
// GET /projects/:id/approvals returns 403 to a read_api token at Reporter,
// measured live 2026-08-14 (issue #18) on gitlab.com/qloud-ltd-group/
// attestward-fixtures with a Reporter project access token, and 200 to a
// token above that role on the same project in the same run. The issue #17
// probe measured 200 at Maintainer specifically on the same endpoint.
//
// The same run confirmed the other two endpoints this collector reads answer
// 200 at Reporter, which is why only this one check moves.
//
// Documenting Reporter here bought an operator a token that silently degrades
// this check to not-checkable rather than the answer the docs promise.
const approvalsTokenScope = "read_api (Maintainer or above on the project — " +
	"GET /projects/:id/approvals returns 403 at Reporter)"

func init() {
	reg := func(id, title, tokenScope, remediation string, rubric map[model.Status]string, endpoints []string) {
		collect.Register(collect.CheckMeta{
			ID: id, Platform: platform, Title: title, Collector: collectorID,
			TokenScope:  tokenScope,
			Remediation: remediation, Rubric: rubric, Endpoints: endpoints,
			FixtureRef: "internal/collect/gitlab/repoprotection/repoprotection_test.go",
		})
	}
	branchEndpoints := []string{"GET /projects/{id}", "GET /projects/{id}/protected_branches"}

	reg(idProtectionExists, "Default branch is protected", branchTokenScope,
		"Project → Settings → Repository → Protected branches → protect the default branch, allowing push and merge only to Maintainers.",
		map[model.Status]string{
			model.StatusVerifiedPass: "A protected-branch rule exists whose name matches the project's default_branch.",
			model.StatusVerifiedFail: "No protected-branch rule matches the default branch.",
			model.StatusNotCheckable: "The project or its protected branches could not be read, or the project is empty and has no default branch.",
		}, branchEndpoints)

	reg(idForcePushBlocked, "Force pushes are blocked on the default branch", branchTokenScope,
		"Project → Settings → Repository → Protected branches → set \"Allowed to force push\" to off for the default branch.",
		map[model.Status]string{
			model.StatusVerifiedPass: "The default branch's protection sets allow_force_push=false.",
			model.StatusVerifiedFail: "allow_force_push is true, or the branch is unprotected so force pushes are unrestricted.",
			model.StatusNotCheckable: "Protection state could not be read.",
		}, branchEndpoints)

	reg(idDeletionBlocked, "Default branch cannot be deleted", branchTokenScope,
		"Protect the default branch, then limit who holds Maintainer and above. Protection blocks deletion from Git clients but not from the UI or API, so the membership list is the remaining control.",
		map[model.Status]string{
			model.StatusPartial:      "The default branch is protected, which blocks deletion from Git clients. It is NOT an absolute block: a Maintainer or Owner can still delete a protected branch through the GitLab UI or API, so this never reports a pass.",
			model.StatusVerifiedFail: "The default branch is unprotected and can therefore be deleted by anyone who can push to it.",
			model.StatusNotCheckable: "Protection state could not be read.",
		}, branchEndpoints)

	reg(idRequiredReviews, "Merge requests require review", approvalsTokenScope,
		"Project → Settings → Merge requests → add an approval rule requiring at least one approver, and enable \"Prevent approvals by author\". Note that approval RULES are a paid-tier feature; on Free the \"Approvals required\" number is accepted and not enforced, which is why this check cannot confirm the gate from the API alone. Scan with a token at Maintainer or above: at Reporter this check's only endpoint returns 403 and it cannot resolve at all.",
		map[model.Status]string{
			model.StatusPartial:      "approvals_before_merge is 1 or more, which shows intent — but that field was deprecated in GitLab 12.3 and does not enforce review on current versions. Approval rules do, and they are a paid-tier feature this scan cannot read, so enforcement is not confirmed. The reason names author self-approval when it is enabled.",
			model.StatusNotCheckable: "approvals_before_merge is 0, or the approvals endpoint was unreadable — a 403 there means the token is below Maintainer or the tier does not entitle the approval surface, and the response does not distinguish them. Neither case distinguishes \"no review required\" from \"a rule this tier cannot expose\", so no pass or fail is asserted. A third route reaches this status without the endpoint being read at all: the project is empty, or the earlier protected-branches read failed, and the scan stops before the approvals call — the reason says so when that is what happened.",
		}, []string{"GET /projects/{id}/approvals"})

	reg(idRequiredStatusChecks, "Merges require passing checks", branchTokenScope,
		"Project → Settings → Merge requests → enable \"Pipelines must succeed\", and leave \"Skipped pipelines are considered successful\" off.",
		map[model.Status]string{
			model.StatusVerifiedPass: "only_allow_merge_if_pipeline_succeeds is true and a skipped pipeline does not satisfy it.",
			model.StatusPartial:      "Pipelines must succeed, but allow_merge_on_skipped_pipeline is true, so a change that runs no jobs merges unchecked.",
			model.StatusVerifiedFail: "only_allow_merge_if_pipeline_succeeds is false.",
			model.StatusNotCheckable: "The project object could not be read. Nothing else reaches this status: both fields are read from that object, so neither a failed protected-branches read nor an empty project with no default branch affects this check.",
		}, []string{"GET /projects/{id}"})

	reg(idAdminEnforced, "Branch protection applies to administrators", noAPICallTokenScope,
		"Not applicable on GitLab: protection is expressed as access levels rather than a rule with an administrator exemption. Restrict push and merge to Maintainers and limit who holds Owner.",
		map[model.Status]string{
			model.StatusNotCheckable: "GitLab has no equivalent of GitHub's enforce_admins, so no API field answers this. Reporting pass or fail would assert a control GitLab does not model. This is a fixed answer on every scan: no read can change it, and no read failure changes its stated reason either.",
		}, nil)
}

// mergeMatchingRules returns the effective protection for branch, combining
// every rule whose pattern matches it.
//
// GitLab evaluates overlapping protected-branch rules most-permissively, so the
// effective posture is the union of what each matching rule allows — not the
// first or most specific match. Returns nil when no rule matches at all.
func mergeMatchingRules(rules []protectedBranch, branch string) *protectedBranch {
	var eff *protectedBranch
	for i := range rules {
		if !branchPatternMatches(rules[i].Name, branch) {
			continue
		}
		r := rules[i]
		if eff == nil {
			cp := r
			cp.Name = branch
			eff = &cp
			continue
		}
		// Most permissive wins: any matching rule allowing force push means
		// force push is allowed, and code-owner approval only holds if every
		// matching rule requires it.
		if r.AllowForcePush {
			eff.AllowForcePush = true
		}
		// GitLab: code-owner approval is required if ANY matching rule enables
		// it — the opposite of the permissive merge used for force push. An
		// earlier comment here claimed the reverse, which would have become a
		// false fail for the first check that reads this field.
		if r.CodeOwnerApprovalRequired {
			eff.CodeOwnerApprovalRequired = true
		}
		eff.PushAccessLevels = append(eff.PushAccessLevels, r.PushAccessLevels...)
		eff.MergeAccessLevels = append(eff.MergeAccessLevels, r.MergeAccessLevels...)
	}
	return eff
}

// branchPatternMatches implements GitLab's protected-branch wildcard matching,
// which is shell-glob style: "*" matches any run of characters. Exact names
// are the common case and are handled by the same path.
func branchPatternMatches(pattern, branch string) bool {
	if pattern == branch {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return false
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(branch[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			return false // a leading literal must anchor at the start
		}
		pos += idx + len(part)
	}
	// A trailing literal must reach the end of the branch name.
	if last := parts[len(parts)-1]; last != "" && !strings.HasSuffix(branch, last) {
		return false
	}
	return true
}
