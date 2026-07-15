package repoprotection

import (
	"strings"
	"testing"

	ghgithub "github.com/google/go-github/v75/github"

	"github.com/sioakim/ssdf/internal/model"
)

func legacyProtection(opts ...func(*ghgithub.Protection)) *ghgithub.Protection {
	p := &ghgithub.Protection{}
	for _, o := range opts {
		o(p)
	}
	return p
}

func withReviews(count int) func(*ghgithub.Protection) {
	return func(p *ghgithub.Protection) {
		p.RequiredPullRequestReviews = &ghgithub.PullRequestReviewsEnforcement{RequiredApprovingReviewCount: count}
	}
}

func withEnforceAdmins(enabled bool) func(*ghgithub.Protection) {
	return func(p *ghgithub.Protection) {
		p.EnforceAdmins = &ghgithub.AdminEnforcement{Enabled: enabled}
	}
}

func withBlockedForcePushAndDeletion() func(*ghgithub.Protection) {
	return func(p *ghgithub.Protection) {
		p.AllowForcePushes = &ghgithub.AllowForcePushes{Enabled: false}
		p.AllowDeletions = &ghgithub.AllowDeletions{Enabled: false}
	}
}

func rulesetActor(actorType ghgithub.BypassActorType, mode ghgithub.BypassMode) *ghgithub.BypassActor {
	return &ghgithub.BypassActor{ActorType: &actorType, BypassMode: &mode}
}

func TestResolveEffectiveProtection_NeitherRegimePresent(t *testing.T) {
	eff := resolveEffectiveProtection(nil, nil, nil)
	if eff.exists {
		t.Error("exists = true, want false when neither legacy nor rules apply")
	}
	if eff.reviewRequired || eff.forcePushBlocked || eff.deletionBlocked || eff.adminEnforced {
		t.Errorf("expected every derived field false, got %+v", eff)
	}
}

func TestResolveEffectiveProtection_LegacyOnlyFullyProtected(t *testing.T) {
	legacy := legacyProtection(withReviews(2), withEnforceAdmins(true), withBlockedForcePushAndDeletion())
	legacy.RequiredStatusChecks = &ghgithub.RequiredStatusChecks{Contexts: &[]string{"ci/test", "ci/lint"}}

	eff := resolveEffectiveProtection(legacy, nil, nil)

	if !eff.exists {
		t.Error("exists = false, want true (legacy protection present)")
	}
	if !eff.reviewRequired || eff.reviewCount != 2 {
		t.Errorf("reviewRequired=%v reviewCount=%d, want true/2", eff.reviewRequired, eff.reviewCount)
	}
	if !eff.forcePushBlocked || !eff.deletionBlocked || !eff.adminEnforced {
		t.Errorf("expected force-push/deletion blocked and admin-enforced, got %+v", eff)
	}
	if len(eff.statusCheckNames) != 2 {
		t.Errorf("statusCheckNames = %v, want 2 entries", eff.statusCheckNames)
	}
}

func TestResolveEffectiveProtection_RulesetOnlyFullyProtected(t *testing.T) {
	rules := &ghgithub.BranchRules{
		PullRequest: []*ghgithub.PullRequestBranchRule{
			{BranchRuleMetadata: ghgithub.BranchRuleMetadata{RulesetID: 1}, Parameters: ghgithub.PullRequestRuleParameters{RequiredApprovingReviewCount: 1}},
		},
		RequiredStatusChecks: []*ghgithub.RequiredStatusChecksBranchRule{
			{BranchRuleMetadata: ghgithub.BranchRuleMetadata{RulesetID: 1}, Parameters: ghgithub.RequiredStatusChecksRuleParameters{
				RequiredStatusChecks: []*ghgithub.RuleStatusCheck{{Context: "build"}},
			}},
		},
		NonFastForward: []*ghgithub.BranchRuleMetadata{{RulesetID: 1}},
		Deletion:       []*ghgithub.BranchRuleMetadata{{RulesetID: 1}},
	}
	rulesets := map[int64]*ghgithub.RepositoryRuleset{1: {ID: int64Ptr(1)}} // no BypassActors

	eff := resolveEffectiveProtection(nil, rules, rulesets)

	if !eff.exists || !eff.reviewRequired || eff.reviewCount != 1 {
		t.Errorf("expected fully protected via ruleset, got %+v", eff)
	}
	if len(eff.statusCheckNames) != 1 || eff.statusCheckNames[0] != "build" {
		t.Errorf("statusCheckNames = %v, want [build]", eff.statusCheckNames)
	}
	if !eff.forcePushBlocked || !eff.deletionBlocked {
		t.Errorf("expected force-push/deletion blocked via ruleset, got %+v", eff)
	}
	if !eff.adminEnforced {
		t.Error("adminEnforced = false, want true (no bypass actors on the ruleset)")
	}
	if got := eff.existsVia; len(got) != 1 || got[0] != "ruleset" {
		t.Errorf("existsVia = %v, want [ruleset] only (no legacy protection at all)", got)
	}
}

func TestResolveEffectiveProtection_BothRegimesMaxReviewCountWins(t *testing.T) {
	legacy := legacyProtection(withReviews(1))
	rules := &ghgithub.BranchRules{
		PullRequest: []*ghgithub.PullRequestBranchRule{
			{BranchRuleMetadata: ghgithub.BranchRuleMetadata{RulesetID: 1}, Parameters: ghgithub.PullRequestRuleParameters{RequiredApprovingReviewCount: 3}},
		},
	}

	eff := resolveEffectiveProtection(legacy, rules, nil)

	if eff.reviewCount != 3 {
		t.Errorf("reviewCount = %d, want 3 (the stricter of the two regimes)", eff.reviewCount)
	}
	if len(eff.reviewVia) != 2 {
		t.Errorf("reviewVia = %v, want both legacy and ruleset recorded", eff.reviewVia)
	}
}

// TestResolveEffectiveProtection_AlwaysBypassDowngradesEvenWhenLegacyEnforces
// is the fix for a real bug caught before this ever shipped: an "always"
// bypass actor on a ruleset must downgrade admin-enforced even when legacy
// protection *independently* sets enforce_admins=true — an admin covered by
// that bypass actor can still circumvent the ruleset's rules regardless of
// what legacy separately enforces.
func TestResolveEffectiveProtection_AlwaysBypassDowngradesEvenWhenLegacyEnforces(t *testing.T) {
	legacy := legacyProtection(withEnforceAdmins(true))
	rules := &ghgithub.BranchRules{
		Deletion: []*ghgithub.BranchRuleMetadata{{RulesetID: 1}},
	}
	rulesets := map[int64]*ghgithub.RepositoryRuleset{
		1: {ID: int64Ptr(1), BypassActors: []*ghgithub.BypassActor{
			rulesetActor(ghgithub.BypassActorTypeOrganizationAdmin, ghgithub.BypassModeAlways),
		}},
	}

	eff := resolveEffectiveProtection(legacy, rules, rulesets)

	if eff.adminEnforced {
		t.Error("adminEnforced = true, want false — an always-mode bypass actor exists on a contributing ruleset")
	}
	if len(eff.bypassActors) != 1 {
		t.Errorf("bypassActors = %v, want 1 recorded (for Facts, even though it downgrades the check)", eff.bypassActors)
	}
}

// TestResolveEffectiveProtection_LegacyExemptionDowngradesEvenWhenRulesetContributes
// pins the mirror-image bug caught by review before this shipped: the fix
// above (an always-bypass ruleset actor downgrades adminEnforced even when
// legacy enforces) originally used a plain OR of "legacy enforces" and
// "ruleset contributes", which meant a ruleset contributing *anything*
// admin-relevant (even just a clean deletion-block, no bypass actors at
// all) produced a false verified-pass while legacy protection existed with
// enforce_admins=false — admins are exempt from whatever legacy itself
// enforces (e.g. required reviews) regardless of what the ruleset
// separately, cleanly binds them to. adminEnforced must require every
// contributing regime to bind admins, not just any one of them.
func TestResolveEffectiveProtection_LegacyExemptionDowngradesEvenWhenRulesetContributes(t *testing.T) {
	legacy := legacyProtection(withReviews(2), withEnforceAdmins(false))
	rules := &ghgithub.BranchRules{
		Deletion: []*ghgithub.BranchRuleMetadata{{RulesetID: 1}},
	}
	rulesets := map[int64]*ghgithub.RepositoryRuleset{1: {ID: int64Ptr(1)}} // no bypass actors at all

	eff := resolveEffectiveProtection(legacy, rules, rulesets)

	if eff.adminEnforced {
		t.Error("adminEnforced = true, want false — legacy exists with enforce_admins=false, so admins are exempt from its required reviews regardless of the ruleset's own clean deletion-block")
	}
}

// TestResolveEffectiveProtection_HasAlwaysBypassOnlyTrueForAlwaysMode
// proves hasAlwaysBypass distinguishes "any bypass actor present" from
// "an unconditional (always-mode) bypass actor present" — a scenario where
// legacy exempts admins and a ruleset separately contributes only a
// conditional (pull_request-mode) bypass actor must NOT set
// hasAlwaysBypass. See checkAdminEnforced's own doc comment (effective.go)
// for the bug this field exists to prevent: the old code treated any
// bypass actor as sufficient for a partial result, even a purely
// conditional one on a branch where nothing otherwise binds admins.
func TestResolveEffectiveProtection_HasAlwaysBypassOnlyTrueForAlwaysMode(t *testing.T) {
	legacy := legacyProtection(withReviews(2), withEnforceAdmins(false))
	rules := &ghgithub.BranchRules{
		Deletion: []*ghgithub.BranchRuleMetadata{{RulesetID: 1}},
	}
	rulesets := map[int64]*ghgithub.RepositoryRuleset{
		1: {ID: int64Ptr(1), BypassActors: []*ghgithub.BypassActor{
			rulesetActor(ghgithub.BypassActorTypeTeam, ghgithub.BypassModePullRequest),
		}},
	}

	eff := resolveEffectiveProtection(legacy, rules, rulesets)

	if eff.hasAlwaysBypass {
		t.Error("hasAlwaysBypass = true, want false — the only bypass actor present is pull_request-mode, not always-mode")
	}
	if len(eff.bypassActors) != 1 {
		t.Errorf("bypassActors = %v, want 1 (still recorded as a fact even though it's not always-mode)", eff.bypassActors)
	}
}

// TestCheckAdminEnforced_LegacyExemptionWithConditionalBypassStaysFail is a
// regression test for the exact bug issue #30's documentation pass found
// (writing an accurate rubric forced tracing this path precisely — see
// checkAdminEnforced's own doc comment in effective.go): legacy protection
// exists but exempts admins (enforce_admins=false), a ruleset separately
// contributes an admin-relevant rule, and that ruleset's only bypass actor
// is conditional (pull_request-mode, not always). Before the fix,
// checkAdminEnforced's switch matched on len(eff.bypassActors) > 0 alone,
// so this scenario reported partial with a hardcoded "unconditional
// (\"always\") bypass actor" reason — wrong on both counts: nothing here
// actually enforces admins (legacy exempts them, and the ruleset's binding
// is moot without legacy's cooperation — see
// TestResolveEffectiveProtection_LegacyExemptionDowngradesEvenWhenRulesetContributes),
// so the correct status is verified-fail, and the one bypass actor present
// isn't unconditional at all.
func TestCheckAdminEnforced_LegacyExemptionWithConditionalBypassStaysFail(t *testing.T) {
	legacy := legacyProtection(withReviews(2), withEnforceAdmins(false))
	rules := &ghgithub.BranchRules{
		Deletion: []*ghgithub.BranchRuleMetadata{{RulesetID: 1}},
	}
	rulesets := map[int64]*ghgithub.RepositoryRuleset{
		1: {ID: int64Ptr(1), BypassActors: []*ghgithub.BypassActor{
			rulesetActor(ghgithub.BypassActorTypeTeam, ghgithub.BypassModePullRequest),
		}},
	}
	eff := resolveEffectiveProtection(legacy, rules, rulesets)

	result := checkAdminEnforced("org", "repo", eff, nil, nil)

	if result.Status != model.StatusVerifiedFail {
		t.Errorf("Status = %q, want %q — a conditional-only bypass actor must not upgrade an otherwise-failing result to partial", result.Status, model.StatusVerifiedFail)
	}
	if strings.Contains(result.Reason, "unconditional") {
		t.Errorf("Reason = %q claims an unconditional bypass actor, but the only one present is pull_request-mode", result.Reason)
	}
}

func TestResolveEffectiveProtection_PullRequestModeBypassDoesNotDowngrade(t *testing.T) {
	rules := &ghgithub.BranchRules{
		Deletion: []*ghgithub.BranchRuleMetadata{{RulesetID: 1}},
	}
	rulesets := map[int64]*ghgithub.RepositoryRuleset{
		1: {ID: int64Ptr(1), BypassActors: []*ghgithub.BypassActor{
			rulesetActor(ghgithub.BypassActorTypeTeam, ghgithub.BypassModePullRequest),
		}},
	}

	eff := resolveEffectiveProtection(nil, rules, rulesets)

	if !eff.adminEnforced {
		t.Error("adminEnforced = false, want true — a pull_request-mode bypass actor still requires going through a PR")
	}
	if len(eff.bypassActors) != 1 {
		t.Errorf("bypassActors = %v, want 1 (still recorded as a fact even though it doesn't downgrade)", eff.bypassActors)
	}
}

func TestResolveEffectiveProtection_StatusCheckNamesMergedAndDeduped(t *testing.T) {
	legacy := legacyProtection()
	legacy.RequiredStatusChecks = &ghgithub.RequiredStatusChecks{Contexts: &[]string{"ci/test"}}
	rules := &ghgithub.BranchRules{
		RequiredStatusChecks: []*ghgithub.RequiredStatusChecksBranchRule{
			{BranchRuleMetadata: ghgithub.BranchRuleMetadata{RulesetID: 1}, Parameters: ghgithub.RequiredStatusChecksRuleParameters{
				RequiredStatusChecks: []*ghgithub.RuleStatusCheck{{Context: "ci/test"}, {Context: "ci/lint"}},
			}},
		},
	}

	eff := resolveEffectiveProtection(legacy, rules, nil)

	if len(eff.statusCheckNames) != 2 {
		t.Errorf("statusCheckNames = %v, want 2 unique entries (ci/test deduped across regimes)", eff.statusCheckNames)
	}
}

func TestResolveEffectiveProtection_LegacyExplicitlyAllowsForcePushAndDeletion(t *testing.T) {
	legacy := legacyProtection()
	legacy.AllowForcePushes = &ghgithub.AllowForcePushes{Enabled: true}
	legacy.AllowDeletions = &ghgithub.AllowDeletions{Enabled: true}

	eff := resolveEffectiveProtection(legacy, nil, nil)

	if eff.forcePushBlocked {
		t.Error("forcePushBlocked = true, want false — legacy explicitly allows force pushes and no ruleset applies")
	}
	if eff.deletionBlocked {
		t.Error("deletionBlocked = true, want false — legacy explicitly allows deletion and no ruleset applies")
	}
}

func int64Ptr(v int64) *int64 { return &v }
