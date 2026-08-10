package repoprotection

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// Bodies below are the shapes GitLab really returns, captured from a live
// project on 2026-08-10. Recorded rather than invented so the parsing is
// exercised against the real field names — including access_level_description,
// which is what makes a reason readable.
const (
	realProject = `{"path":"attestward","default_branch":"main",
		"only_allow_merge_if_pipeline_succeeds":%t,"allow_merge_on_skipped_pipeline":%s,
		"merge_method":"merge","merge_requests_enabled":true}`

	realProtectedBranch = `[{"id":1,"name":"main","allow_force_push":%t,"code_owner_approval_required":false,
		"push_access_levels":[{"access_level":40,"access_level_description":"Maintainers"}],
		"merge_access_levels":[{"access_level":40,"access_level_description":"Maintainers"}],
		"unprotect_access_levels":[]}]`

	realApprovals = `{"approvals_before_merge":%d,"merge_requests_author_approval":%t,
		"reset_approvals_on_push":true,"disable_overriding_approvers_per_merge_request":false}`
)

type routes struct {
	project, branches, approvals string
	// Per-endpoint status overrides, so a state matrix can reach the
	// not-checkable paths each check has for an unreadable dependency.
	approvalsStatus, projectStatus, branchesStatus int
}

// fail writes an error status for one endpoint if the state asks for it.
func fail(w http.ResponseWriter, code int) bool {
	if code != 0 && code != http.StatusOK {
		w.WriteHeader(code)
		_, _ = fmt.Fprint(w, `{"message":"error"}`)
		return true
	}
	return false
}

func collectWith(t *testing.T, r routes) []model.CheckResult {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(req.URL.Path, "/protected_branches"):
			if fail(w, r.branchesStatus) {
				return
			}
			_, _ = fmt.Fprint(w, r.branches)
		case strings.HasSuffix(req.URL.Path, "/approvals"):
			if r.approvalsStatus != 0 && r.approvalsStatus != 200 {
				w.WriteHeader(r.approvalsStatus)
				_, _ = fmt.Fprint(w, `{"message":"403 Forbidden"}`)
				return
			}
			_, _ = fmt.Fprint(w, r.approvals)
		default:
			if fail(w, r.projectStatus) {
				return
			}
			_, _ = fmt.Fprint(w, r.project)
		}
	}))
	t.Cleanup(srv.Close)

	c := NewForTest(srv.URL, "tok", func() (*gitlabcollect.Client, error) {
		return gitlabcollect.NewClient(srv.URL, "tok")
	})
	res, err := c.Collect(context.Background(), collect.Scope{Org: "grp", Repos: []string{"proj"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return res
}

func find(t *testing.T, res []model.CheckResult, id string) model.CheckResult {
	t.Helper()
	for _, r := range res {
		if r.CheckID == id {
			return r
		}
	}
	t.Fatalf("no result for %s", id)
	return model.CheckResult{}
}

func defaults() routes {
	return routes{
		project:   fmt.Sprintf(realProject, true, "false"),
		branches:  fmt.Sprintf(realProtectedBranch, false),
		approvals: fmt.Sprintf(realApprovals, 1, false),
	}
}

func TestProtectedDefaultBranchPasses(t *testing.T) {
	res := collectWith(t, defaults())
	// deletion-blocked is deliberately NOT here: it is partial by design,
	// because GitLab lets Maintainers delete protected branches via the UI.
	for _, id := range []string{idProtectionExists, idForcePushBlocked, idRequiredStatusChecks} {
		if got := find(t, res, id); got.Status != model.StatusVerifiedPass {
			t.Errorf("%s = %q, want verified-pass (%s)", id, got.Status, got.Reason)
		}
	}
}

func TestUnprotectedDefaultBranchFailsEveryDerivedCheck(t *testing.T) {
	r := defaults()
	r.branches = `[]`
	res := collectWith(t, r)
	for _, id := range []string{idProtectionExists, idForcePushBlocked, idDeletionBlocked} {
		if got := find(t, res, id); got.Status != model.StatusVerifiedFail {
			t.Errorf("%s = %q, want verified-fail when the branch is unprotected", id, got.Status)
		}
	}
}

func TestForcePushAllowedFails(t *testing.T) {
	r := defaults()
	r.branches = fmt.Sprintf(realProtectedBranch, true)
	if got := find(t, collectWith(t, r), idForcePushBlocked); got.Status != model.StatusVerifiedFail {
		t.Errorf("allow_force_push=true = %q, want verified-fail", got.Status)
	}
}

// TestSkippedPipelineDowngradesToPartial pins a gap that is easy to miss: a
// project can require pipelines to succeed AND accept a skipped pipeline as
// success, so a change that runs no jobs merges unchecked. Reporting that as
// a clean pass would overstate the control.
func TestSkippedPipelineDowngradesToPartial(t *testing.T) {
	r := defaults()
	r.project = fmt.Sprintf(realProject, true, "true")
	if got := find(t, collectWith(t, r), idRequiredStatusChecks); got.Status != model.StatusPartial {
		t.Errorf("allow_merge_on_skipped_pipeline=true = %q, want partial", got.Status)
	}
}

// TestAuthorSelfApprovalDowngradesToPartial pins the same principle for
// reviews: one required approval the author can supply themselves is not the
// control it appears to be.
func TestAuthorSelfApprovalIsNamedInTheReason(t *testing.T) {
	// required-reviews is partial for every readable value now (the field is
	// deprecated), so self-approval no longer changes the status — but it must
	// still be surfaced, because it is the difference between a gate and a
	// formality.
	r := defaults()
	r.approvals = fmt.Sprintf(realApprovals, 1, true)
	got := find(t, collectWith(t, r), idRequiredReviews)
	if got.Status != model.StatusPartial {
		t.Errorf("status = %q, want partial", got.Status)
	}
	if !strings.Contains(got.Reason, "author could supply that approval themselves") {
		t.Errorf("reason must name author self-approval, got: %s", got.Reason)
	}
}

// TestTierGatedApprovalsIsNotAFailure is the rule the whole platform rests on:
// a 403 means not entitled, and must never be read as "no review required".
func TestTierGatedApprovalsIsNotAFailure(t *testing.T) {
	r := defaults()
	r.approvalsStatus = http.StatusForbidden
	got := find(t, collectWith(t, r), idRequiredReviews)
	if got.Status != model.StatusNotCheckable {
		t.Errorf("403 on approvals = %q, want not-checkable — a paywalled endpoint is not evidence of an absent control", got.Status)
	}
	// The rest of the checks must survive: one gated endpoint should not sink
	// the branch evidence that was read successfully.
	if p := find(t, collectWith(t, r), idProtectionExists); p.Status != model.StatusVerifiedPass {
		t.Errorf("protection-exists = %q; a gated approvals read should not affect it", p.Status)
	}
}

func TestAdminEnforcedIsAlwaysNotCheckable(t *testing.T) {
	if got := find(t, collectWith(t, defaults()), idAdminEnforced); got.Status != model.StatusNotCheckable {
		t.Errorf("admin-enforced = %q, want not-checkable — GitLab does not model it", got.Status)
	}
}

func TestEmptyProjectIsNotAFailure(t *testing.T) {
	r := defaults()
	r.project = `{"path":"p","default_branch":null}`
	for _, got := range collectWith(t, r) {
		if got.Status == model.StatusVerifiedFail {
			t.Errorf("%s = verified-fail on an empty project; there is no branch to protect yet", got.CheckID)
		}
	}
}

// --- regression tests for the 2026-08-10 review findings -------------------

// TestWildcardRuleIsFound pins review finding 1a: a branch protected only by a
// wildcard rule has no exact-name entry, and matching by name fabricated three
// failures for a correctly protected repository.
func TestWildcardRuleIsFound(t *testing.T) {
	for _, pattern := range []string{"*", "ma*", "*ain", "m*n"} {
		r := defaults()
		r.branches = fmt.Sprintf(`[{"name":%q,"allow_force_push":false,"code_owner_approval_required":false,
			"push_access_levels":[{"access_level":40,"access_level_description":"Maintainers"}],
			"merge_access_levels":[{"access_level":40,"access_level_description":"Maintainers"}]}]`, pattern)
		if got := find(t, collectWith(t, r), idProtectionExists); got.Status != model.StatusVerifiedPass {
			t.Errorf("pattern %q: protection-exists = %q, want verified-pass", pattern, got.Status)
		}
	}
}

// TestMostPermissiveWildcardWins pins review finding 1b, the false PASS: GitLab
// applies the most permissive of several matching rules, so an exact rule
// forbidding force push alongside a wildcard allowing it means force push is
// allowed. Reading only the exact rule reported verified-pass.
func TestMostPermissiveWildcardWins(t *testing.T) {
	r := defaults()
	r.branches = `[
	  {"name":"main","allow_force_push":false,"push_access_levels":[],"merge_access_levels":[]},
	  {"name":"ma*","allow_force_push":true,"push_access_levels":[],"merge_access_levels":[]}]`
	if got := find(t, collectWith(t, r), idForcePushBlocked); got.Status != model.StatusVerifiedFail {
		t.Errorf("force-push = %q, want verified-fail: a wildcard rule permits it, so the branch is not protected "+
			"against force pushes and a pass would be fabricated evidence", got.Status)
	}
}

// TestNonMatchingWildcardIsIgnored guards the other direction — an over-eager
// matcher would attribute an unrelated rule to the default branch.
func TestNonMatchingWildcardIsIgnored(t *testing.T) {
	r := defaults()
	r.branches = `[{"name":"release/*","allow_force_push":true,"push_access_levels":[],"merge_access_levels":[]}]`
	if got := find(t, collectWith(t, r), idProtectionExists); got.Status != model.StatusVerifiedFail {
		t.Errorf("release/* must not match main: got %q, want verified-fail", got.Status)
	}
}

// TestDeletionIsPartialNotPass pins review finding 2. Protection blocks Git
// clients but a Maintainer can still delete via the UI, so verified-pass put a
// false statement into signed evidence.
func TestDeletionIsPartialNotPass(t *testing.T) {
	got := find(t, collectWith(t, defaults()), idDeletionBlocked)
	if got.Status != model.StatusPartial {
		t.Errorf("deletion-blocked = %q, want partial — GitLab lets Maintainers delete protected branches via the UI", got.Status)
	}
	if !strings.Contains(got.Reason, "web UI") {
		t.Errorf("reason must name the UI deletion path, got: %s", got.Reason)
	}
}

// TestDeprecatedApprovalsFieldNeverFails pins review finding 3.
// approvals_before_merge was deprecated in 12.3 and does not reflect approval
// rules, so a 0 is consistent with a rule this tier cannot expose.
func TestDeprecatedApprovalsFieldNeverFails(t *testing.T) {
	r := defaults()
	r.approvals = fmt.Sprintf(realApprovals, 0, false)
	// Assert the exact status, not merely "not a fail": a version that turned 0
	// into verified-pass would be the worse defect and would have slipped past
	// the looser assertion.
	if got := find(t, collectWith(t, r), idRequiredReviews); got.Status != model.StatusNotCheckable {
		t.Errorf("approvals_before_merge=0 = %q, want not-checkable — the field is deprecated and cannot "+
			"distinguish 'no review required' from 'a rule this tier cannot show'", got.Status)
	}
}

// TestApprovalsAboveZeroIsNotAPass pins the mirror image, which the first fix
// missed: if the field is untrustworthy at 0 it is untrustworthy at 2. On a
// Free namespace approvals_before_merge is accepted and ignored, so a pass
// there would assert an enforced gate that does not exist.
func TestApprovalsAboveZeroIsNotAPass(t *testing.T) {
	r := defaults()
	r.approvals = fmt.Sprintf(realApprovals, 2, false)
	if got := find(t, collectWith(t, r), idRequiredReviews); got.Status != model.StatusPartial {
		t.Errorf("approvals_before_merge=2 = %q, want partial. A pass asserts a gate that may not exist; a fail "+
			"asserts its absence. The deprecated field supports neither claim.", got.Status)
	}
}

// TestBranchPatternMatches pins the matcher directly. GitLab's wildcard crosses
// "/" (its own docs match *gitlab* against master/gitlab/production), so
// path.Match would be wrong here — which is why this is hand-rolled and why it
// needs its own table.
func TestBranchPatternMatches(t *testing.T) {
	cases := []struct {
		pattern, branch string
		want            bool
	}{
		{"main", "main", true}, {"main", "maint", false},
		{"*", "main", true}, {"ma*", "main", true}, {"*ain", "main", true},
		{"m*n", "main", true}, {"m*n", "mn", true}, {"m*n", "mainn", true},
		{"ma*x", "main", false}, {"release/*", "main", false},
		{"release/*", "release/1.0", true},
		{"*gitlab*", "master/gitlab/production", true}, // wildcard crosses "/"
		{"a*a", "aa", true}, {"a*a", "ab", false},
		{"", "main", false},
	}
	for _, c := range cases {
		if got := branchPatternMatches(c.pattern, c.branch); got != c.want {
			t.Errorf("branchPatternMatches(%q, %q) = %v, want %v", c.pattern, c.branch, got, c.want)
		}
	}
}

// TestCodeOwnerApprovalMergesPermissively pins review finding I1: GitLab
// requires code-owner approval if ANY matching rule enables it — the opposite
// of the force-push merge.
func TestCodeOwnerApprovalMergesPermissively(t *testing.T) {
	rules := []protectedBranch{
		{Name: "main", CodeOwnerApprovalRequired: false},
		{Name: "ma*", CodeOwnerApprovalRequired: true},
	}
	if eff := mergeMatchingRules(rules, "main"); eff == nil || !eff.CodeOwnerApprovalRequired {
		t.Error("code-owner approval must be required when any matching rule enables it")
	}
}

// TestRubricsMatchWhatTheCollectorCanActuallyEmit is the guard that would have
// caught this package's two documentation defects, and it caught a third.
//
// A rubric is what `attestward checks docs` publishes as the meaning of each
// result. Nothing previously tied it to the code, so when a check's behaviour
// was corrected the rubric kept confidently describing the OLD behaviour —
// twice in this file. deletion-blocked stopped emitting a pass but its rubric
// still explained one and asserted deletion was impossible; required-reviews
// stopped emitting pass and fail but its rubric still said it failed at zero
// approvals, which is the exact claim the code had just been fixed to stop
// making. Both were invisible because the code was right; only the published
// documentation lied.
//
// So this drives the collector across every fixture state the package models
// and compares the statuses actually observed against the statuses documented.
// A rubric entry for a status the collector cannot produce is a false promise
// to a reader; a status with no entry ships a conclusion with no stated basis.
//
// ⚠ Its limit is worth stating, because a third instance of the same defect was
// found in orgsecurity by review and would NOT have failed here: this compares
// which statuses are emitted, not whether their descriptions are true. A rubric
// whose wording rots while its status set stays valid — a pass that starts
// being reached by a second, undescribed route — passes this test. Nothing
// mechanical catches that; it needs a reader who checks the rubric whenever a
// status's entry conditions change.
func TestRubricsMatchWhatTheCollectorCanActuallyEmit(t *testing.T) {
	states := []routes{
		defaults(),
		{project: fmt.Sprintf(realProject, true, "false"), branches: `[]`, approvals: fmt.Sprintf(realApprovals, 0, false)},
		{project: fmt.Sprintf(realProject, false, "true"), branches: fmt.Sprintf(realProtectedBranch, true), approvals: fmt.Sprintf(realApprovals, 3, true)},
		{project: fmt.Sprintf(realProject, true, "false"), branches: fmt.Sprintf(realProtectedBranch, false), approvalsStatus: http.StatusForbidden},
		// Pipeline required but a SKIPPED pipeline satisfies it — the partial
		// state for required-status-checks. Its absence was found by this test
		// rather than by inspection, which is the point of comparing the rubric
		// against observed behaviour instead of against a reviewer's memory.
		{project: fmt.Sprintf(realProject, true, "true"), branches: fmt.Sprintf(realProtectedBranch, false), approvals: fmt.Sprintf(realApprovals, 1, false)},
		{projectStatus: http.StatusNotFound},
		{project: fmt.Sprintf(realProject, true, "false"), branchesStatus: http.StatusForbidden, approvals: fmt.Sprintf(realApprovals, 1, false)},
	}

	all := []model.CheckResult{}
	for _, st := range states {
		all = append(all, collectWith(t, st)...)
	}
	collecttest.AssertRubricsMatchObservedBehaviour(t, platform, collectorID, all)
}
