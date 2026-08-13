package repoprotection

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops/adofixture"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const (
	testOrg     = "attestward-demo"
	testProject = "demo-project"
)

func repositoriesPath() string { return "/" + testOrg + "/" + testProject + "/_apis/git/repositories" }
func policiesPath() string     { return "/" + testOrg + "/" + testProject + "/_apis/policy/configurations" }

// newTestCollector wires a Collector against fx via
// azuredevops.NewClientForTest — the same cross-package testing seam
// orgsecurity's and pipelinehistory's own tests use.
func newTestCollector(fx http.RoundTripper) *Collector {
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)
	return New(client)
}

func resultByID(results []model.CheckResult, repo, id string) model.CheckResult {
	for _, r := range results {
		if r.CheckID == id && r.Scope.Repo == repo {
			return r
		}
	}
	return model.CheckResult{}
}

func reposFixture(fx *adofixture.Transport, repos ...map[string]any) *adofixture.Transport {
	return fx.Set("GET", azuredevops.HostCore, repositoriesPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"count": len(repos), "value": repos},
	})
}

func policiesFixture(fx *adofixture.Transport, policies ...map[string]any) *adofixture.Transport {
	return fx.Set("GET", azuredevops.HostCore, policiesPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"count": len(policies), "value": policies},
	})
}

func minReviewersPolicy(scope []map[string]any, minApprovers int, blocking, creatorVoteCounts bool) map[string]any {
	return map[string]any{
		"isEnabled":  true,
		"isBlocking": blocking,
		"isDeleted":  false,
		"type":       map[string]any{"id": minReviewersTypeID},
		"settings": map[string]any{
			"minimumApproverCount": minApprovers,
			"creatorVoteCounts":    creatorVoteCounts,
			"scope":                scope,
		},
	}
}

func buildValidationPolicy(scope []map[string]any, blocking bool) map[string]any {
	return map[string]any{
		"isEnabled":  true,
		"isBlocking": blocking,
		"isDeleted":  false,
		"type":       map[string]any{"id": buildValidationTypeID},
		"settings": map[string]any{
			"buildDefinitionId": 5,
			"scope":             scope,
		},
	}
}

func projectWideScope(refName, matchKind string) []map[string]any {
	return []map[string]any{{"refName": refName, "matchKind": matchKind, "repositoryId": nil}}
}

func repoScope(refName, matchKind, repositoryID string) []map[string]any {
	return []map[string]any{{"refName": refName, "matchKind": matchKind, "repositoryId": repositoryID}}
}

// defaultBranchCrossRepoScope is the exact shape Azure DevOps's
// project-level "Protect the default branch of each repository"
// cross-repository policy emits: refName and repositoryId both null,
// matchKind "DefaultBranch" — verified against
// terraform-provider-azuredevops's own documentation of this matchKind.
func defaultBranchCrossRepoScope() []map[string]any {
	return []map[string]any{{"refName": nil, "matchKind": "DefaultBranch", "repositoryId": nil}}
}

// TestCollect_ProtectionExists_PassAndFail covers the protection-exists
// rubric lines: a tracked-type (minimum-reviewers) policy scoped to the
// default branch passes; zero tracked-type policies fails.
func TestCollect_ProtectionExists_PassAndFail(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx,
		map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/main"},
		map[string]any{"id": "repo-b-id", "name": "repo-b", "defaultBranch": "refs/heads/main"},
	)
	policiesFixture(fx,
		minReviewersPolicy(repoScope("refs/heads/main", "Exact", "repo-a-id"), 1, true, false),
	)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a", "repo-b"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	a := resultByID(results, "repo-a", idProtectionExists)
	if a.Status != model.StatusVerifiedPass {
		t.Errorf("repo-a protection-exists = %q, want verified-pass; reason=%q", a.Status, a.Reason)
	}
	if a.Facts["tracked_policy_count"] != 1 {
		t.Errorf("repo-a tracked_policy_count = %v, want 1", a.Facts["tracked_policy_count"])
	}

	b := resultByID(results, "repo-b", idProtectionExists)
	if b.Status != model.StatusVerifiedFail {
		t.Errorf("repo-b protection-exists = %q, want verified-fail (policy is scoped to repo-a only); reason=%q", b.Status, b.Reason)
	}
}

// TestCollect_RequiredReviews_Pass covers the isBlocking->pass rubric line.
func TestCollect_RequiredReviews_Pass(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx, map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/main"})
	policiesFixture(fx, minReviewersPolicy(projectWideScope("refs/heads/main", "Exact"), 2, true, false))

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	r := resultByID(results, "repo-a", idRequiredReviews)
	if r.Status != model.StatusVerifiedPass {
		t.Errorf("required-reviews = %q, want verified-pass; reason=%q", r.Status, r.Reason)
	}
	if r.Facts["minimum_approver_count"] != 2 {
		t.Errorf("minimum_approver_count = %v, want 2", r.Facts["minimum_approver_count"])
	}
}

// TestCollect_RequiredReviews_PartialNonBlocking covers the
// non-blocking->partial rubric line.
func TestCollect_RequiredReviews_PartialNonBlocking(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx, map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/main"})
	policiesFixture(fx, minReviewersPolicy(projectWideScope("refs/heads/main", "Exact"), 1, false, false))

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	r := resultByID(results, "repo-a", idRequiredReviews)
	if r.Status != model.StatusPartial {
		t.Errorf("required-reviews = %q, want partial; reason=%q", r.Status, r.Reason)
	}
	if r.Facts["any_blocking_policy"] != false {
		t.Errorf("any_blocking_policy = %v, want false", r.Facts["any_blocking_policy"])
	}
}

// TestCollect_RequiredReviews_PartialCreatorVoteCounts covers the
// creatorVoteCounts->partial rubric line.
func TestCollect_RequiredReviews_PartialCreatorVoteCounts(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx, map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/main"})
	policiesFixture(fx, minReviewersPolicy(projectWideScope("refs/heads/main", "Exact"), 1, true, true))

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	r := resultByID(results, "repo-a", idRequiredReviews)
	if r.Status != model.StatusPartial {
		t.Errorf("required-reviews = %q, want partial; reason=%q", r.Status, r.Reason)
	}
	if r.Facts["creator_vote_counts"] != true {
		t.Errorf("creator_vote_counts = %v, want true", r.Facts["creator_vote_counts"])
	}
	// Regression for the review finding on this PR: a blocking policy (even
	// with creatorVoteCounts=true) can never be bypassed by "override
	// branch policies at completion" the way a genuinely non-blocking
	// policy can, so the partial Reason must never claim overridability
	// here.
	if r.Facts["any_blocking_policy"] != true {
		t.Errorf("any_blocking_policy = %v, want true", r.Facts["any_blocking_policy"])
	}
	if containsFold(r.Reason, "overridden at completion") {
		t.Errorf("reason = %q, must never claim the requirement can be overridden at completion when a blocking policy exists", r.Reason)
	}
}

// TestCollect_RequiredReviews_StrongestPolicyGovernsWithWeakerSibling is the
// regression test for the aggregation-semantics review finding: Azure
// DevOps enforces every matching policy simultaneously (an AND-gate), so a
// blocking, fully-compliant policy is a genuine requirement even when a
// separate, weaker (non-blocking) matching policy also applies to the same
// branch — this must report verified-pass, not partial ("the weakest
// policy governs" was the bug this fixes).
func TestCollect_RequiredReviews_StrongestPolicyGovernsWithWeakerSibling(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx, map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/main"})
	policiesFixture(fx,
		minReviewersPolicy(projectWideScope("refs/heads/main", "Exact"), 2, true, false),
		minReviewersPolicy(repoScope("refs/heads/main", "Exact", "repo-a-id"), 1, false, false),
	)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	r := resultByID(results, "repo-a", idRequiredReviews)
	if r.Status != model.StatusVerifiedPass {
		t.Errorf("required-reviews = %q, want verified-pass — the blocking policy governs even though a non-blocking sibling also matches; reason=%q", r.Status, r.Reason)
	}
}

// TestCollect_RequiredReviews_Fail covers the absent->fail rubric line.
func TestCollect_RequiredReviews_Fail(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx, map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/main"})
	policiesFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	r := resultByID(results, "repo-a", idRequiredReviews)
	if r.Status != model.StatusVerifiedFail {
		t.Errorf("required-reviews = %q, want verified-fail; reason=%q", r.Status, r.Reason)
	}
}

// TestCollect_RequiredStatusChecks_PassPartialFail covers all three
// required-status-checks rubric lines in one scenario set (blocking
// build policy passes; non-blocking partials; absent fails).
func TestCollect_RequiredStatusChecks_PassPartialFail(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx,
		map[string]any{"id": "repo-pass-id", "name": "repo-pass", "defaultBranch": "refs/heads/main"},
		map[string]any{"id": "repo-partial-id", "name": "repo-partial", "defaultBranch": "refs/heads/main"},
		map[string]any{"id": "repo-fail-id", "name": "repo-fail", "defaultBranch": "refs/heads/main"},
	)
	policiesFixture(fx,
		buildValidationPolicy(repoScope("refs/heads/main", "Exact", "repo-pass-id"), true),
		buildValidationPolicy(repoScope("refs/heads/main", "Exact", "repo-partial-id"), false),
	)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-pass", "repo-partial", "repo-fail"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if got := resultByID(results, "repo-pass", idRequiredStatusChecks).Status; got != model.StatusVerifiedPass {
		t.Errorf("repo-pass required-status-checks = %q, want verified-pass", got)
	}
	if got := resultByID(results, "repo-partial", idRequiredStatusChecks).Status; got != model.StatusPartial {
		t.Errorf("repo-partial required-status-checks = %q, want partial", got)
	}
	if got := resultByID(results, "repo-fail", idRequiredStatusChecks).Status; got != model.StatusVerifiedFail {
		t.Errorf("repo-fail required-status-checks = %q, want verified-fail", got)
	}
}

// TestCollect_RequiredStatusChecks_StrongestPolicyGovernsWithWeakerSibling
// is required-status-checks' copy of the aggregation-semantics regression
// test above: one blocking Build policy is a genuine requirement even
// when a separate, non-blocking matching policy also applies.
func TestCollect_RequiredStatusChecks_StrongestPolicyGovernsWithWeakerSibling(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx, map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/main"})
	policiesFixture(fx,
		buildValidationPolicy(projectWideScope("refs/heads/main", "Exact"), true),
		buildValidationPolicy(repoScope("refs/heads/main", "Exact", "repo-a-id"), false),
	)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	r := resultByID(results, "repo-a", idRequiredStatusChecks)
	if r.Status != model.StatusVerifiedPass {
		t.Errorf("required-status-checks = %q, want verified-pass — the blocking policy governs even though a non-blocking sibling also matches; reason=%q", r.Status, r.Reason)
	}
}

// TestCollect_PrefixScopeMatchKind covers the required "prefix-scope
// matchKind matching" acceptance criterion: a policy scoped via
// matchKind=="Prefix" applies to a default branch that starts with (but
// isn't exactly) refName.
func TestCollect_PrefixScopeMatchKind(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx, map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/release/2.0"})
	policiesFixture(fx, minReviewersPolicy(projectWideScope("refs/heads/release/", "Prefix"), 1, true, false))

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	r := resultByID(results, "repo-a", idRequiredReviews)
	if r.Status != model.StatusVerifiedPass {
		t.Errorf("required-reviews = %q, want verified-pass (prefix scope match); reason=%q", r.Status, r.Reason)
	}
}

// TestCollect_DefaultBranchMatchKindCrossRepoPolicy is the regression test
// for the HIGH review finding on this PR: Azure DevOps's project-level
// "Protect the default branch of each repository" cross-repository policy
// emits a scope entry with matchKind=="DefaultBranch" and refName/
// repositoryId both null — treating that as an exact match against a null
// refName (the original bug) meant it could never match anything,
// producing a false verified-fail on exactly this best-practice setup.
func TestCollect_DefaultBranchMatchKindCrossRepoPolicy(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx, map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/main"})
	policiesFixture(fx, minReviewersPolicy(defaultBranchCrossRepoScope(), 1, true, false))

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	r := resultByID(results, "repo-a", idRequiredReviews)
	if r.Status != model.StatusVerifiedPass {
		t.Errorf("required-reviews = %q, want verified-pass (matchKind=DefaultBranch cross-repo policy must match this repo's own default branch); reason=%q", r.Status, r.Reason)
	}

	pe := resultByID(results, "repo-a", idProtectionExists)
	if pe.Status != model.StatusVerifiedPass {
		t.Errorf("protection-exists = %q, want verified-pass (matchKind=DefaultBranch cross-repo policy); reason=%q", pe.Status, pe.Reason)
	}
}

// TestCollect_PolicyScopedToDifferentRepoIsIgnored covers the required
// "a policy scoped to a DIFFERENT repo being ignored" acceptance
// criterion: two repos share the same default branch name, but a policy
// naming only repo-b's repositoryId must never apply to repo-a.
func TestCollect_PolicyScopedToDifferentRepoIsIgnored(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx,
		map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/main"},
		map[string]any{"id": "repo-b-id", "name": "repo-b", "defaultBranch": "refs/heads/main"},
	)
	policiesFixture(fx, minReviewersPolicy(repoScope("refs/heads/main", "Exact", "repo-b-id"), 1, true, false))

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a", "repo-b"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if got := resultByID(results, "repo-a", idRequiredReviews).Status; got != model.StatusVerifiedFail {
		t.Errorf("repo-a required-reviews = %q, want verified-fail (policy scoped to repo-b only, must be ignored for repo-a)", got)
	}
	if got := resultByID(results, "repo-b", idRequiredReviews).Status; got != model.StatusVerifiedPass {
		t.Errorf("repo-b required-reviews = %q, want verified-pass", got)
	}
}

// TestCollect_ProjectWidePolicyAppliesToEveryRepo covers the required
// "project-wide (repositoryId null) policy applying" acceptance criterion.
func TestCollect_ProjectWidePolicyAppliesToEveryRepo(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx,
		map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/main"},
		map[string]any{"id": "repo-b-id", "name": "repo-b", "defaultBranch": "refs/heads/main"},
	)
	policiesFixture(fx, minReviewersPolicy(projectWideScope("refs/heads/main", "Exact"), 1, true, false))

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a", "repo-b"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if got := resultByID(results, "repo-a", idRequiredReviews).Status; got != model.StatusVerifiedPass {
		t.Errorf("repo-a required-reviews = %q, want verified-pass (project-wide policy)", got)
	}
	if got := resultByID(results, "repo-b", idRequiredReviews).Status; got != model.StatusVerifiedPass {
		t.Errorf("repo-b required-reviews = %q, want verified-pass (project-wide policy)", got)
	}
}

// TestCollect_ThreeACLChecksAlwaysNotCheckable proves admin-enforced,
// force-push-blocked, and deletion-blocked are not-checkable regardless of
// how "protected" the repo otherwise looks via policy data.
func TestCollect_ThreeACLChecksAlwaysNotCheckable(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx, map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/main"})
	policiesFixture(fx,
		minReviewersPolicy(projectWideScope("refs/heads/main", "Exact"), 2, true, false),
		buildValidationPolicy(projectWideScope("refs/heads/main", "Exact"), true),
	)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, id := range []string{idAdminEnforced, idForcePushBlocked, idDeletionBlocked} {
		r := resultByID(results, "repo-a", id)
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable regardless of policy data", id, r.Status)
		}
		if r.Reason == "" {
			t.Errorf("%s has empty Reason, want an actionable ACL-surface explanation", id)
		}
		if r.Provenance == nil {
			t.Errorf("%s Provenance is nil, want a non-nil (possibly empty) slice", id)
		}
	}
	// deletion-blocked and force-push-blocked must name the SAME ADO
	// permission — Azure DevOps has no permission distinct from force-push
	// for deleting a branch (see the package doc comment).
	fp := resultByID(results, "repo-a", idForcePushBlocked)
	del := resultByID(results, "repo-a", idDeletionBlocked)
	if !containsFold(fp.Reason, "Force push") || !containsFold(del.Reason, "Force push") {
		t.Errorf("force-push-blocked/deletion-blocked reasons must both name \"Force push (rewrite history, delete branches and tags)\"; got fp=%q del=%q", fp.Reason, del.Reason)
	}
}

// TestCollect_RepositoriesAPIFailure_NotCheckable covers the
// repositories-list api-fail path: the three policy-driven checks become
// not-checkable, but the three ACL checks are unaffected (they never
// depend on this data at all).
func TestCollect_RepositoriesAPIFailure_NotCheckable(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostCore, repositoriesPath(), adofixture.Response{
		Status: http.StatusForbidden,
		Body:   map[string]any{"message": "Forbidden"},
	})
	policiesFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 6 {
		t.Fatalf("len(results) = %d, want 6", len(results))
	}

	for _, id := range policyDrivenCheckIDs {
		r := resultByID(results, "repo-a", id)
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, r.Status)
		}
		if !containsFold(r.Reason, "permission") {
			t.Errorf("%s reason = %q, want it to mention the permission problem", id, r.Reason)
		}
		if len(r.Provenance) == 0 {
			t.Errorf("%s has no provenance, want the failed repositories call's entry attached", id)
		}
	}
	for _, id := range []string{idAdminEnforced, idForcePushBlocked, idDeletionBlocked} {
		if got := resultByID(results, "repo-a", id).Status; got != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable (its own fixed reason, unaffected by the repositories failure)", id, got)
		}
	}
}

// TestCollect_RepositoryNotFoundInProject_NotCheckable covers a named repo
// that the project's repositories list doesn't contain at all.
func TestCollect_RepositoryNotFoundInProject_NotCheckable(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx, map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/main"})
	policiesFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"nonexistent-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	r := resultByID(results, "nonexistent-repo", idProtectionExists)
	if r.Status != model.StatusNotCheckable {
		t.Errorf("protection-exists = %q, want not-checkable", r.Status)
	}
	if !containsFold(r.Reason, "not found") {
		t.Errorf("reason = %q, want it to say the repo wasn't found", r.Reason)
	}
}

// TestCollect_FindRepositoryIsCaseInsensitive is the regression test for
// the LOW review finding on this PR: Azure DevOps repository names are
// case-insensitive, and unlike GitHub's collectors, this package has no
// repoLister to canonicalize a user-supplied --repo value against the
// platform's own casing first — a --repo value typed in different casing
// than the platform's canonical stored name must still resolve, not
// report a real, existing repo as not-checkable ("not found").
func TestCollect_FindRepositoryIsCaseInsensitive(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx, map[string]any{"id": "repo-a-id", "name": "myrepo", "defaultBranch": "refs/heads/main"})
	policiesFixture(fx, minReviewersPolicy(projectWideScope("refs/heads/main", "Exact"), 1, true, false))

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"MyRepo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	r := resultByID(results, "MyRepo", idProtectionExists)
	if r.Status != model.StatusVerifiedPass {
		t.Errorf("protection-exists = %q, want verified-pass (--repo MyRepo must match the canonical name myrepo case-insensitively); reason=%q", r.Status, r.Reason)
	}
}

// TestCollect_EmptyRepositoryNoDefaultBranch_NotCheckable covers a repo
// with no defaultBranch field at all — Microsoft's own Repositories - List
// reference sample response shows exactly this shape for a genuinely
// empty repository.
func TestCollect_EmptyRepositoryNoDefaultBranch_NotCheckable(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx, map[string]any{"id": "repo-a-id", "name": "repo-a"})
	policiesFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	r := resultByID(results, "repo-a", idProtectionExists)
	if r.Status != model.StatusNotCheckable {
		t.Errorf("protection-exists = %q, want not-checkable", r.Status)
	}
	if !containsFold(r.Reason, "default branch") {
		t.Errorf("reason = %q, want it to mention the missing default branch", r.Reason)
	}
}

// TestCollect_PolicyConfigurationsAPIFailure_NotCheckable covers the
// policy-configurations-list api-fail path, distinct from the
// repositories-list failure above (repo/branch resolved fine, but policy
// data itself couldn't be read).
func TestCollect_PolicyConfigurationsAPIFailure_NotCheckable(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx, map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/main"})
	fx.Set("GET", azuredevops.HostCore, policiesPath(), adofixture.Response{
		Status: http.StatusNotFound,
		Body:   map[string]any{"message": "Not Found"},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	r := resultByID(results, "repo-a", idRequiredReviews)
	if r.Status != model.StatusNotCheckable {
		t.Errorf("required-reviews = %q, want not-checkable", r.Status)
	}
	if !containsFold(r.Reason, "not found") {
		t.Errorf("reason = %q, want it to mention the 404", r.Reason)
	}
}

// TestCollect_ProvenanceNeverNil proves every result carries a non-nil
// Provenance slice.
func TestCollect_ProvenanceNeverNil(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx, map[string]any{"id": "repo-a-id", "name": "repo-a", "defaultBranch": "refs/heads/main"})
	policiesFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 6 {
		t.Fatalf("len(results) = %d, want 6", len(results))
	}
	for _, r := range results {
		if r.Provenance == nil {
			t.Errorf("%s Provenance is nil, want a non-nil (possibly empty) slice", r.CheckID)
		}
	}
}

// TestCollect_NoReposInScopeProducesNoResults proves an empty scope.Repos
// yields zero results (not nil — see the schema invariant tests above),
// since there is nothing to iterate.
func TestCollect_NoReposInScopeProducesNoResults(t *testing.T) {
	fx := adofixture.New()
	reposFixture(fx)
	policiesFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if results == nil {
		t.Fatal("results is nil, want a non-nil empty slice")
	}
	if len(results) != 0 {
		t.Errorf("len(results) = %d, want 0", len(results))
	}
}

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// TestCollect_RegistersAllSixChecks proves the init()-registered CheckMeta
// entries match the six check IDs Collect() actually produces, under the
// azuredevops platform.
func TestCollect_RegistersAllSixChecks(t *testing.T) {
	for _, id := range checkIDs {
		if _, ok := collect.LookupPlatform("azuredevops", id); !ok {
			t.Errorf("check %q not found in the collect.CheckMeta registry for platform azuredevops", id)
		}
	}
	if len(checkIDs) != 6 {
		t.Fatalf("len(checkIDs) = %d, want 6", len(checkIDs))
	}
}

// TestCollect_CollectorIDMatchesGitHubTwin proves this package registers
// under the exact same Collector string as
// internal/collect/github/repoprotection — collect.Register panics on a
// mismatch (registry.go), but this test pins the expectation directly.
func TestCollect_CollectorIDMatchesGitHubTwin(t *testing.T) {
	if collectorID != "C02.repo-protection" {
		t.Errorf("collectorID = %q, want \"C02.repo-protection\" (must match the GitHub twin's exactly)", collectorID)
	}
}

// checksWithNoEndpoint are the checks whose Endpoints is legitimately
// empty: none of the three ACL-governed checks make any API call at all —
// see checkRubrics' own doc comment, and orgsecurity's identical pattern.
var checksWithNoEndpoint = map[string]bool{
	idForcePushBlocked: true,
	idDeletionBlocked:  true,
	idAdminEnforced:    true,
}

// checkWantStatuses is a human-reviewed declaration of exactly which
// statuses each check can produce — see orgsecurity's own copy of this
// pattern for the full rationale.
var checkWantStatuses = map[string][]model.Status{
	idProtectionExists:     {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	idRequiredReviews:      {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
	idRequiredStatusChecks: {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
	idForcePushBlocked:     {model.StatusNotCheckable},
	idDeletionBlocked:      {model.StatusNotCheckable},
	idAdminEnforced:        {model.StatusNotCheckable},
}

// endpointVerbRE matches this package's Endpoints convention: verb, host,
// path — see checkEndpoints' own doc comment.
var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) dev\.azure\.com/`)

// TestCollect_RegisteredMetadataCompleteForChecksReference mirrors
// orgsecurity's test of the same name — see its own doc comment for the
// full rationale.
func TestCollect_RegisteredMetadataCompleteForChecksReference(t *testing.T) {
	if len(checkRubrics) != len(checkIDs) {
		t.Errorf("checkRubrics has %d entries, checkIDs has %d — a typo'd/orphaned key won't otherwise be caught", len(checkRubrics), len(checkIDs))
	}
	if len(checkEndpoints) != len(checkIDs) {
		t.Errorf("checkEndpoints has %d entries, checkIDs has %d — a typo'd/orphaned key won't otherwise be caught", len(checkEndpoints), len(checkIDs))
	}
	if len(checkTokenScopes) != len(checkIDs) {
		t.Errorf("checkTokenScopes has %d entries, checkIDs has %d — a typo'd/orphaned key won't otherwise be caught", len(checkTokenScopes), len(checkIDs))
	}
	if len(checkRemediations) != len(checkIDs) {
		t.Errorf("checkRemediations has %d entries, checkIDs has %d — a typo'd/orphaned key won't otherwise be caught", len(checkRemediations), len(checkIDs))
	}

	for _, id := range checkIDs {
		meta, ok := collect.LookupPlatform("azuredevops", id)
		if !ok {
			t.Fatalf("check %q not found in the collect.CheckMeta registry", id)
		}
		if meta.Collector != collectorID {
			t.Errorf("%s Collector = %q, want %q", id, meta.Collector, collectorID)
		}
		if meta.TokenScope == "" {
			t.Errorf("%s TokenScope is empty", id)
		}

		want, ok := checkWantStatuses[id]
		if !ok {
			t.Fatalf("checkWantStatuses is missing an entry for %q", id)
		}
		wantSet := make(map[model.Status]bool, len(want))
		for _, s := range want {
			wantSet[s] = true
		}
		for s := range wantSet {
			if meta.Rubric[s] == "" {
				t.Errorf("%s: Rubric[%s] is empty, want a concrete explanation", id, s)
			}
		}
		for s := range meta.Rubric {
			if !wantSet[s] {
				t.Errorf("%s: Rubric has an entry for status %q, but checkWantStatuses says this check can't produce it", id, s)
			}
		}

		if len(meta.Endpoints) == 0 && !checksWithNoEndpoint[id] {
			t.Errorf("%s: Endpoints is empty, want at least one (or add it to checksWithNoEndpoint with a reason)", id)
		}
		if len(meta.Endpoints) > 0 && checksWithNoEndpoint[id] {
			t.Errorf("%s: checksWithNoEndpoint says this check should have zero Endpoints, but it has %v", id, meta.Endpoints)
		}
		for _, e := range meta.Endpoints {
			if !endpointVerbRE.MatchString(e) {
				t.Errorf("%s: Endpoints entry %q isn't GET/HEAD against a known ADO host — this project is read-only forever (ADR-0004)", id, e)
			}
		}

		if meta.FixtureRef == "" {
			t.Errorf("%s: FixtureRef is empty", id)
		}
	}
}

// rubricState is one fixture world for TestRubricsMatchObservedBehaviour.
// Both fields are the only two responses this collector reads, and want is
// the whole result map that world must produce for the single in-scope repo.
type rubricState struct {
	name string
	// repos and policies back ALL THREE policy-driven checks — there is no
	// second API surface any of them could read instead, so a state matrix
	// that only ever varies "are the two calls healthy" moves all three in
	// lockstep. See the test's doc comment for what splits them.
	repos    adofixture.Response
	policies adofixture.Response
	want     map[string]model.Status
}

func (st rubricState) fixture() *adofixture.Transport {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, repositoriesPath(), st.repos)
	fx.Set("GET", azuredevops.HostCore, policiesPath(), st.policies)
	return fx
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue #10).
//
// Eleven states reach every status this collector can emit. force-push-blocked,
// deletion-blocked and admin-enforced make no API call at all and return
// not-checkable unconditionally (they are ACL-governed — see the package doc
// comment), so no fixture can move them; the guard's
// documented-but-unreachable direction is what pins that rather than any state.
//
// The matrix is shaped by a conflation risk that is structural here rather
// than incidental: protection-exists, required-reviews and required-status-checks
// are computed from ONE client-side filter (matchingPolicies) over ONE response,
// and they differ only in which policy TYPE they count and which FIELD of it
// they read. A matrix that varies whole policy sets moves all three together
// and a check reading the wrong type ID — or the wrong policy's isBlocking —
// stays invisible. So the matrix splits them on both axes:
//
//   - type axis: state 2 has ONLY a Build policy (required-reviews must fail
//     while required-status-checks passes); state 3 is the exact reverse.
//   - blocking axis: state 4 has both types present and only the reviewers
//     policy degraded; state 6 has both types present and only the Build
//     policy degraded. Neither involves a missing policy, so they separate
//     the two checks by the field each reads on its OWN policy.
//
// Two states then cover the ways a policy can be well-formed and still have to
// be IGNORED, which is the other half of what matchingPolicies does: one scoped
// to a sibling repo, and one pair that is disabled and soft-deleted. The second
// is the only place the "enabled, non-deleted" wording in all three rubrics is
// observable at all — before it, removing either flag from the filter left the
// whole repository's test suite green.
//
// One state is the not-checkable route with no transport failure anywhere: both
// calls return 200 and the repo simply has no default branch. That is the
// difference between "the API broke" and "the data says nothing is protected",
// which a matrix built only from 403s would never separate.
//
// Verified by injection rather than assumed — see the commit message for which
// states caught which mutation.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	const repoID = "repo-a-id"
	const otherRepoID = "repo-b-id"
	const branch = "refs/heads/main"

	reposOK := func(repos ...map[string]any) adofixture.Response {
		return adofixture.Response{
			Status: http.StatusOK,
			Body:   map[string]any{"count": len(repos), "value": repos},
		}
	}
	policiesOK := func(policies ...map[string]any) adofixture.Response {
		return adofixture.Response{
			Status: http.StatusOK,
			Body:   map[string]any{"count": len(policies), "value": policies},
		}
	}
	forbidden := adofixture.Response{Status: http.StatusForbidden, Body: map[string]any{"message": "denied"}}

	// The two repos exist in every state so a policy scoped to otherRepoID is
	// a real, well-formed policy on a real sibling repo rather than a dangling
	// id — the scope-mismatch path is worth exercising against something the
	// project actually contains.
	bothRepos := reposOK(
		map[string]any{"id": repoID, "name": "repo-a", "defaultBranch": branch},
		map[string]any{"id": otherRepoID, "name": "repo-b", "defaultBranch": branch},
	)
	onScope := repoScope(branch, "Exact", repoID)
	// withFlag flips exactly one of the two flags matchingPolicies filters on,
	// leaving type, scope, blocking and approver count identical to the passing
	// fixtures. The shared builders hardcode isEnabled:true/isDeleted:false, so
	// without this nothing in the file could reach a policy that is well-formed
	// and still must be ignored.
	withFlag := func(policy map[string]any, key string, value bool) map[string]any {
		out := make(map[string]any, len(policy))
		for k, v := range policy {
			out[k] = v
		}
		out[key] = value
		return out
	}

	fixedNotCheckable := func(m map[string]model.Status) map[string]model.Status {
		m[idForcePushBlocked] = model.StatusNotCheckable
		m[idDeletionBlocked] = model.StatusNotCheckable
		m[idAdminEnforced] = model.StatusNotCheckable
		return m
	}

	states := []rubricState{
		{
			name:  "both tracked policy types scoped to the default branch, both blocking, no creator self-vote",
			repos: bothRepos,
			policies: policiesOK(
				minReviewersPolicy(onScope, 2, true, false),
				buildValidationPolicy(onScope, true),
			),
			want: fixedNotCheckable(map[string]model.Status{
				idProtectionExists:     model.StatusVerifiedPass,
				idRequiredReviews:      model.StatusVerifiedPass,
				idRequiredStatusChecks: model.StatusVerifiedPass,
			}),
		},
		{
			// Type split, half one. A blocking Build policy satisfies
			// protection-exists and required-status-checks and must NOT
			// satisfy required-reviews: a reviewers check that counted any
			// tracked-type policy would pass here.
			name:     "only a Build policy, blocking",
			repos:    bothRepos,
			policies: policiesOK(buildValidationPolicy(onScope, true)),
			want: fixedNotCheckable(map[string]model.Status{
				idProtectionExists:     model.StatusVerifiedPass,
				idRequiredReviews:      model.StatusVerifiedFail,
				idRequiredStatusChecks: model.StatusVerifiedPass,
			}),
		},
		{
			// Type split, the exact reverse of state 2.
			name:     "only a Minimum approval count policy, blocking, no creator self-vote",
			repos:    bothRepos,
			policies: policiesOK(minReviewersPolicy(onScope, 1, true, false)),
			want: fixedNotCheckable(map[string]model.Status{
				idProtectionExists:     model.StatusVerifiedPass,
				idRequiredReviews:      model.StatusVerifiedPass,
				idRequiredStatusChecks: model.StatusVerifiedFail,
			}),
		},
		{
			// Blocking-axis split: both types present, only the reviewers
			// policy degraded — and degraded by creatorVoteCounts rather than
			// isBlocking, which is required-reviews' second, distinct route to
			// partial and the one required-status-checks has no analogue for.
			name:  "reviewers policy blocking but the author's own vote counts; Build policy blocking",
			repos: bothRepos,
			policies: policiesOK(
				minReviewersPolicy(onScope, 1, true, true),
				buildValidationPolicy(onScope, true),
			),
			want: fixedNotCheckable(map[string]model.Status{
				idProtectionExists:     model.StatusVerifiedPass,
				idRequiredReviews:      model.StatusPartial,
				idRequiredStatusChecks: model.StatusVerifiedPass,
			}),
		},
		{
			// required-reviews' first route to partial (nothing blocking at
			// all), reached alongside required-status-checks' only route to it.
			name:  "neither policy is blocking",
			repos: bothRepos,
			policies: policiesOK(
				minReviewersPolicy(onScope, 1, false, false),
				buildValidationPolicy(onScope, false),
			),
			want: fixedNotCheckable(map[string]model.Status{
				idProtectionExists:     model.StatusVerifiedPass,
				idRequiredReviews:      model.StatusPartial,
				idRequiredStatusChecks: model.StatusPartial,
			}),
		},
		{
			// Blocking-axis split, the reverse of state 4: both types present,
			// only the Build policy degraded. A status-checks check reading the
			// reviewers policy's isBlocking would pass here.
			name:  "reviewers policy fully blocking, Build policy non-blocking",
			repos: bothRepos,
			policies: policiesOK(
				minReviewersPolicy(onScope, 1, true, false),
				buildValidationPolicy(onScope, false),
			),
			want: fixedNotCheckable(map[string]model.Status{
				idProtectionExists:     model.StatusVerifiedPass,
				idRequiredReviews:      model.StatusVerifiedPass,
				idRequiredStatusChecks: model.StatusPartial,
			}),
		},
		{
			// The third split axis, and the only one that separates
			// protection-exists from required-reviews on the SAME policy:
			// a well-formed, enabled, blocking Minimum approval count policy
			// scoped to the default branch that requires zero approvers.
			// protection-exists counts it (it is a tracked type in scope);
			// required-reviews must not (it reads minimumApproverCount, and
			// zero approvers is no requirement at all). Added after a mutation
			// run found the >=1 boundary was unguarded by any test in the repo.
			name:  "a Minimum approval count policy requiring zero approvers",
			repos: bothRepos,
			policies: policiesOK(
				minReviewersPolicy(onScope, 0, true, false),
			),
			want: fixedNotCheckable(map[string]model.Status{
				idProtectionExists:     model.StatusVerifiedPass,
				idRequiredReviews:      model.StatusVerifiedFail,
				idRequiredStatusChecks: model.StatusVerifiedFail,
			}),
		},
		{
			// The all-fail state, reached by scope rather than by an empty
			// list: both policies are enabled, blocking and well-formed, and
			// are scoped to the sibling repo. An empty policy list would fail
			// too, without exercising the repositoryId comparison at all.
			name:  "both policies scoped to a different repository in the same project",
			repos: bothRepos,
			policies: policiesOK(
				minReviewersPolicy(repoScope(branch, "Exact", otherRepoID), 1, true, false),
				buildValidationPolicy(repoScope(branch, "Exact", otherRepoID), true),
			),
			want: fixedNotCheckable(map[string]model.Status{
				idProtectionExists:     model.StatusVerifiedFail,
				idRequiredReviews:      model.StatusVerifiedFail,
				idRequiredStatusChecks: model.StatusVerifiedFail,
			}),
		},
		{
			// The other way a well-formed policy must be ignored, and the only
			// state that exercises matchingPolicies' enabled/non-deleted filter
			// at all: both policies are correctly scoped to this repo's default
			// branch, blocking, and of a tracked type — one is merely disabled
			// and the other soft-deleted. Every rubric here says "no ENABLED,
			// NON-DELETED policy", and until this state that phrase described
			// behaviour no test could observe: dropping either flag from the
			// filter left the whole repository's suite green.
			name:  "the only matching policies are one disabled and one soft-deleted",
			repos: bothRepos,
			policies: policiesOK(
				withFlag(minReviewersPolicy(onScope, 1, true, false), "isEnabled", false),
				withFlag(buildValidationPolicy(onScope, true), "isDeleted", true),
			),
			want: fixedNotCheckable(map[string]model.Status{
				idProtectionExists:     model.StatusVerifiedFail,
				idRequiredReviews:      model.StatusVerifiedFail,
				idRequiredStatusChecks: model.StatusVerifiedFail,
			}),
		},
		{
			// Not-checkable with no transport failure: both calls return 200
			// and repo-a is an empty repository with no default branch. The
			// policies are the passing set from state 1, so nothing but the
			// missing branch can be producing this.
			name: "the in-scope repository has no default branch",
			repos: reposOK(
				map[string]any{"id": repoID, "name": "repo-a"},
				map[string]any{"id": otherRepoID, "name": "repo-b", "defaultBranch": branch},
			),
			policies: policiesOK(
				minReviewersPolicy(onScope, 1, true, false),
				buildValidationPolicy(onScope, true),
			),
			want: fixedNotCheckable(map[string]model.Status{
				idProtectionExists:     model.StatusNotCheckable,
				idRequiredReviews:      model.StatusNotCheckable,
				idRequiredStatusChecks: model.StatusNotCheckable,
			}),
		},
		{
			// The other not-checkable shape worth keeping distinct: the
			// repositories call succeeds and only the policy read is denied,
			// so this is not "the org is unreachable" — it is one of the two
			// reads failing.
			name:     "policy configurations denied, repositories readable",
			repos:    bothRepos,
			policies: forbidden,
			want: fixedNotCheckable(map[string]model.Status{
				idProtectionExists:     model.StatusNotCheckable,
				idRequiredReviews:      model.StatusNotCheckable,
				idRequiredStatusChecks: model.StatusNotCheckable,
			}),
		},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			results, err := newTestCollector(st.fixture()).Collect(context.Background(), collect.Scope{
				Org: testOrg, Project: testProject, Repos: []string{"repo-a"},
			})
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}

			got := map[string]model.Status{}
			for _, r := range results {
				if _, dup := got[r.CheckID]; dup {
					t.Errorf("%s emitted twice", r.CheckID)
				}
				got[r.CheckID] = r.Status
			}
			// Compared whole, in both directions: a missing key is as much a
			// defect as a wrong one, and a row count would show neither.
			for id, want := range st.want {
				if got[id] != want {
					t.Errorf("%s = %q, want %q", id, got[id], want)
				}
			}
			for id, status := range got {
				if _, expected := st.want[id]; !expected {
					t.Errorf("%s = %q, but this state expects no result for it", id, status)
				}
			}
			all = append(all, results...)
		})
	}

	collecttest.AssertRubricsMatchObservedBehaviour(t, "azuredevops", collectorID, all)
}
