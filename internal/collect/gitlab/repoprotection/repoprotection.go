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
// **Deletion needs no separate setting.** On GitHub, branch deletion is a
// protection toggle you can leave off. On GitLab, a protected branch cannot
// be deleted at all — deletion is governed by the same protection record, so
// the existence of protection *is* the evidence. This check therefore
// derives from protection rather than looking for a field, and says so, so
// nobody reads a pass as evidence of a setting that does not exist.
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
		return allNotCheckable(org, repo,
			"the project has no default branch — it is empty, so there is no branch to protect and nothing to evidence yet",
			client.Provenance())
	}

	branches, err := gitlabcollect.GetJSONPaged[protectedBranch](ctx, client, "/projects/"+id+"/protected_branches", nil)
	if err != nil {
		return allNotCheckable(org, repo, describeErr("protected branches", org+"/"+repo, err), client.Provenance())
	}

	var def *protectedBranch
	for i := range branches {
		if branches[i].Name == proj.DefaultBranch {
			def = &branches[i]
			break
		}
	}

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
		adminEnforced(org, repo, proj, def),
	}
	for i := range results {
		results[i].Provenance = prov
	}
	return results
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
			fmt.Sprintf("the default branch %q is not protected, and an unprotected branch can be deleted by anyone who can push to it", p.DefaultBranch),
			map[string]any{"protected": false})
	}
	return res(idDeletionBlocked, "Default branch cannot be deleted", model.StatusVerifiedPass, org, repo,
		fmt.Sprintf("the default branch %q is protected. GitLab has no separate deletion toggle: a protected branch "+
			"cannot be deleted, so protection is the evidence for this control rather than a field of its own", p.DefaultBranch),
		map[string]any{"protected": true, "derived_from": "protected_branches"})
}

func requiredReviews(org, repo string, _ project, a approvals, err error) model.CheckResult {
	if err != nil {
		if gitlabcollect.IsTierGated(err) {
			return res(idRequiredReviews, "Merge requests require review", model.StatusNotCheckable, org, repo,
				"the project approvals API is not readable with this token or tier (HTTP 403). Merge-request approval "+
					"rules are a paid-tier feature on GitLab, and an unreadable rule set is not evidence that no "+
					"review is required", nil)
		}
		return res(idRequiredReviews, "Merge requests require review", model.StatusNotCheckable, org, repo,
			fmt.Sprintf("could not read the project approvals settings: %v", err), nil)
	}
	if a.ApprovalsBeforeMerge < 1 {
		return res(idRequiredReviews, "Merge requests require review", model.StatusVerifiedFail, org, repo,
			"approvals_before_merge is 0, so a merge request can be merged with no approval from anyone",
			map[string]any{"approvals_before_merge": a.ApprovalsBeforeMerge})
	}
	status, note := model.StatusVerifiedPass, ""
	if a.MergeRequestsAuthorApproval {
		status = model.StatusPartial
		note = " — but merge_requests_author_approval is true, so an author can supply that approval themselves"
	}
	return res(idRequiredReviews, "Merge requests require review", status, org, repo,
		fmt.Sprintf("approvals_before_merge is %d%s", a.ApprovalsBeforeMerge, note),
		map[string]any{
			"approvals_before_merge":         a.ApprovalsBeforeMerge,
			"merge_requests_author_approval": a.MergeRequestsAuthorApproval,
			"reset_approvals_on_push":        a.ResetApprovalsOnPush,
		})
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
func adminEnforced(org, repo string, _ project, _ *protectedBranch) model.CheckResult {
	return res(idAdminEnforced, "Branch protection applies to administrators", model.StatusNotCheckable, org, repo,
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

func allNotCheckable(org, repo, reason string, prov []model.Provenance) []model.CheckResult {
	ids := []struct{ id, title string }{
		{idProtectionExists, "Default branch is protected"},
		{idForcePushBlocked, "Force pushes are blocked on the default branch"},
		{idDeletionBlocked, "Default branch cannot be deleted"},
		{idRequiredReviews, "Merge requests require review"},
		{idRequiredStatusChecks, "Merges require passing checks"},
		{idAdminEnforced, "Branch protection applies to administrators"},
	}
	out := make([]model.CheckResult, 0, len(ids))
	for _, c := range ids {
		r := res(c.id, c.title, model.StatusNotCheckable, org, repo, reason, nil)
		r.Provenance = prov
		out = append(out, r)
	}
	return out
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

func init() {
	reg := func(id, title, remediation string, rubric map[model.Status]string, endpoints []string) {
		collect.Register(collect.CheckMeta{
			ID: id, Platform: platform, Title: title, Collector: collectorID,
			TokenScope:  "read_api (Reporter or above on the project)",
			Remediation: remediation, Rubric: rubric, Endpoints: endpoints,
			FixtureRef: "internal/collect/gitlab/repoprotection/repoprotection_test.go",
		})
	}
	branchEndpoints := []string{"GET /projects/{id}", "GET /projects/{id}/protected_branches"}

	reg(idProtectionExists, "Default branch is protected",
		"Project → Settings → Repository → Protected branches → protect the default branch, allowing push and merge only to Maintainers.",
		map[model.Status]string{
			model.StatusVerifiedPass: "A protected-branch rule exists whose name matches the project's default_branch.",
			model.StatusVerifiedFail: "No protected-branch rule matches the default branch.",
			model.StatusNotCheckable: "The project or its protected branches could not be read, or the project is empty and has no default branch.",
		}, branchEndpoints)

	reg(idForcePushBlocked, "Force pushes are blocked on the default branch",
		"Project → Settings → Repository → Protected branches → set \"Allowed to force push\" to off for the default branch.",
		map[model.Status]string{
			model.StatusVerifiedPass: "The default branch's protection sets allow_force_push=false.",
			model.StatusVerifiedFail: "allow_force_push is true, or the branch is unprotected so force pushes are unrestricted.",
			model.StatusNotCheckable: "Protection state could not be read.",
		}, branchEndpoints)

	reg(idDeletionBlocked, "Default branch cannot be deleted",
		"Protect the default branch. GitLab blocks deletion of protected branches; there is no separate deletion setting to enable.",
		map[model.Status]string{
			model.StatusVerifiedPass: "The default branch is protected, and GitLab does not permit deletion of a protected branch. Derived from protection, not from a dedicated field — GitLab has none.",
			model.StatusVerifiedFail: "The default branch is unprotected and can therefore be deleted.",
			model.StatusNotCheckable: "Protection state could not be read.",
		}, branchEndpoints)

	reg(idRequiredReviews, "Merge requests require review",
		"Project → Settings → Merge requests → set \"Approvals required\" to at least 1, and disable \"Prevent approval by author\"'s inverse so authors cannot self-approve.",
		map[model.Status]string{
			model.StatusVerifiedPass: "approvals_before_merge is 1 or more and authors cannot approve their own merge requests.",
			model.StatusPartial:      "Approvals are required, but merge_requests_author_approval is true so the author can supply the approval themselves.",
			model.StatusVerifiedFail: "approvals_before_merge is 0.",
			model.StatusNotCheckable: "The approvals endpoint was not readable — on GitLab the richer approval-rule surface is a paid-tier feature, and an unreadable rule set is not evidence that no review is required.",
		}, []string{"GET /projects/{id}/approvals"})

	reg(idRequiredStatusChecks, "Merges require passing checks",
		"Project → Settings → Merge requests → enable \"Pipelines must succeed\", and leave \"Skipped pipelines are considered successful\" off.",
		map[model.Status]string{
			model.StatusVerifiedPass: "only_allow_merge_if_pipeline_succeeds is true and a skipped pipeline does not satisfy it.",
			model.StatusPartial:      "Pipelines must succeed, but allow_merge_on_skipped_pipeline is true, so a change that runs no jobs merges unchecked.",
			model.StatusVerifiedFail: "only_allow_merge_if_pipeline_succeeds is false.",
			model.StatusNotCheckable: "The project object could not be read.",
		}, []string{"GET /projects/{id}"})

	reg(idAdminEnforced, "Branch protection applies to administrators",
		"Not applicable on GitLab: protection is expressed as access levels rather than a rule with an administrator exemption. Restrict push and merge to Maintainers and limit who holds Owner.",
		map[model.Status]string{
			model.StatusNotCheckable: "GitLab has no equivalent of GitHub's enforce_admins, so no API field answers this. Reporting pass or fail would assert a control GitLab does not model.",
		}, nil)
}
