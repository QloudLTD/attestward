package repoprotection

import (
	"fmt"
	"sort"

	ghgithub "github.com/google/go-github/v75/github"

	"github.com/sioakim/ssdf/internal/model"
)

// effectiveProtection is the merged result of legacy branch protection and
// rulesets for one branch. GitHub enforces both regimes simultaneously when
// both apply to the same branch (whichever is stricter governs the actual
// push/merge), so each field here is true if *either* regime provides it —
// "via" records which regime(s) actually did, for the Facts a reader can
// audit without re-deriving this logic themselves.
type effectiveProtection struct {
	exists    bool
	existsVia []string

	reviewRequired bool
	reviewCount    int
	dismissStale   bool
	reviewVia      []string

	statusCheckNames []string
	statusChecksVia  []string

	forcePushBlocked bool
	forcePushVia     []string

	deletionBlocked bool
	deletionVia     []string

	// adminEnforced is true only when at least one regime enforces admins
	// AND no bypass actor found anywhere has an unconditional ("always")
	// bypass mode. An "always" bypass actor on the ruleset side downgrades
	// this even if legacy independently sets enforce_admins=true — an admin
	// covered by that bypass actor can still circumvent the ruleset's
	// rules, regardless of what legacy protection separately enforces. A
	// "pull_request"-mode bypass actor still has to go through a PR and
	// isn't treated as defeating admin enforcement.
	adminEnforced bool
	adminVia      []string
	bypassActors  []string
}

func resolveEffectiveProtection(legacy *ghgithub.Protection, rules *ghgithub.BranchRules, rulesets map[int64]*ghgithub.RepositoryRuleset) effectiveProtection {
	var eff effectiveProtection

	legacyEnforcesAdmins := false
	if legacy != nil {
		legacyEnforcesAdmins = applyLegacy(&eff, legacy)
	}
	rulesetContributesAdmin, hasAlwaysBypass := false, false
	if rules != nil {
		rulesetContributesAdmin, hasAlwaysBypass = applyRules(&eff, rules, rulesets)
	}

	// adminEnforced requires EVERY contributing regime to bind admins, not
	// just any one of them: legacy protection existing with
	// enforce_admins=false means admins are exempt from whatever legacy
	// itself enforces (reviews, force-push/deletion blocks) even if a
	// ruleset separately, cleanly binds admins to its own rules — a
	// ruleset-side pass can't paper over a legacy-side exemption, the same
	// way an "always" ruleset bypass can't be papered over by legacy
	// enforcing admins (see hasAlwaysBypass below). Getting this backwards
	// (OR instead of requiring both sides) was a real pre-merge bug: it
	// fabricated a verified-pass whenever a ruleset contributed anything at
	// all, regardless of what legacy separately exempted admins from.
	legacyBindsAdmins := legacy == nil || legacyEnforcesAdmins
	somethingContributesAdmin := legacyEnforcesAdmins || rulesetContributesAdmin
	if somethingContributesAdmin && legacyBindsAdmins && !hasAlwaysBypass {
		eff.adminEnforced = true
	}
	if legacyEnforcesAdmins {
		eff.adminVia = appendUnique(eff.adminVia, "legacy")
	}
	if rulesetContributesAdmin && !hasAlwaysBypass {
		eff.adminVia = appendUnique(eff.adminVia, "ruleset")
	}

	sort.Strings(eff.statusCheckNames)
	sort.Strings(eff.bypassActors)
	return eff
}

// applyLegacy applies legacy branch-protection fields to eff and reports
// whether legacy protection itself enforces admins (enforce_admins=true) —
// the final admin-enforced determination also depends on ruleset bypass
// actors, resolved by the caller after applyRules runs.
func applyLegacy(eff *effectiveProtection, legacy *ghgithub.Protection) bool {
	eff.exists = true
	eff.existsVia = appendUnique(eff.existsVia, "legacy")

	if rpr := legacy.RequiredPullRequestReviews; rpr != nil && rpr.RequiredApprovingReviewCount >= 1 {
		eff.reviewRequired = true
		eff.reviewVia = appendUnique(eff.reviewVia, "legacy")
		if rpr.RequiredApprovingReviewCount > eff.reviewCount {
			eff.reviewCount = rpr.RequiredApprovingReviewCount
		}
		if rpr.DismissStaleReviews {
			eff.dismissStale = true
		}
	}

	if rsc := legacy.RequiredStatusChecks; rsc != nil {
		names := legacyStatusCheckNames(rsc)
		if len(names) > 0 {
			eff.statusCheckNames = appendUniqueAll(eff.statusCheckNames, names)
			eff.statusChecksVia = appendUnique(eff.statusChecksVia, "legacy")
		}
	}

	if legacy.AllowForcePushes == nil || !legacy.AllowForcePushes.Enabled {
		eff.forcePushBlocked = true
		eff.forcePushVia = appendUnique(eff.forcePushVia, "legacy")
	}

	if legacy.AllowDeletions == nil || !legacy.AllowDeletions.Enabled {
		eff.deletionBlocked = true
		eff.deletionVia = appendUnique(eff.deletionVia, "legacy")
	}

	return legacy.EnforceAdmins != nil && legacy.EnforceAdmins.Enabled
}

// legacyStatusCheckNames reads whichever of the deprecated Contexts or the
// newer Checks field is populated — go-github's own docs say only one of
// the two is ever set on a given response.
func legacyStatusCheckNames(rsc *ghgithub.RequiredStatusChecks) []string {
	if rsc.Checks != nil {
		names := make([]string, 0, len(*rsc.Checks))
		for _, c := range *rsc.Checks {
			if c != nil {
				names = append(names, c.Context)
			}
		}
		return names
	}
	if rsc.Contexts != nil {
		return *rsc.Contexts
	}
	return nil
}

// applyRules applies ruleset-derived fields to eff and reports whether any
// ruleset contributes an admin-relevant rule, plus whether an unconditional
// ("always") bypass actor was found among the rulesets contributing those
// rules. The final admin-enforced determination is resolved by the caller
// after this returns, since it also depends on legacy's own contribution.
func applyRules(eff *effectiveProtection, rules *ghgithub.BranchRules, rulesets map[int64]*ghgithub.RepositoryRuleset) (rulesetContributesAdmin, hasAlwaysBypass bool) {
	if len(rules.PullRequest) > 0 {
		eff.exists = true
		eff.existsVia = appendUnique(eff.existsVia, "ruleset")
		for _, r := range rules.PullRequest {
			if r.Parameters.RequiredApprovingReviewCount < 1 {
				continue
			}
			eff.reviewRequired = true
			eff.reviewVia = appendUnique(eff.reviewVia, "ruleset")
			if r.Parameters.RequiredApprovingReviewCount > eff.reviewCount {
				eff.reviewCount = r.Parameters.RequiredApprovingReviewCount
			}
			if r.Parameters.DismissStaleReviewsOnPush {
				eff.dismissStale = true
			}
		}
	}

	if len(rules.RequiredStatusChecks) > 0 {
		var names []string
		for _, r := range rules.RequiredStatusChecks {
			for _, c := range r.Parameters.RequiredStatusChecks {
				if c != nil {
					names = append(names, c.Context)
				}
			}
		}
		if len(names) > 0 {
			eff.exists = true
			eff.existsVia = appendUnique(eff.existsVia, "ruleset")
			eff.statusCheckNames = appendUniqueAll(eff.statusCheckNames, names)
			eff.statusChecksVia = appendUnique(eff.statusChecksVia, "ruleset")
		}
	}

	if len(rules.NonFastForward) > 0 {
		eff.exists = true
		eff.existsVia = appendUnique(eff.existsVia, "ruleset")
		eff.forcePushBlocked = true
		eff.forcePushVia = appendUnique(eff.forcePushVia, "ruleset")
	}

	if len(rules.Deletion) > 0 {
		eff.exists = true
		eff.existsVia = appendUnique(eff.existsVia, "ruleset")
		eff.deletionBlocked = true
		eff.deletionVia = appendUnique(eff.deletionVia, "ruleset")
	}

	ids := relevantRulesetIDs(rules)
	if len(ids) == 0 {
		return false, false
	}
	for id := range ids {
		rs := rulesets[id]
		if rs == nil {
			continue
		}
		for _, actor := range rs.BypassActors {
			eff.bypassActors = append(eff.bypassActors, describeBypassActor(actor))
			if actor.BypassMode != nil && *actor.BypassMode == ghgithub.BypassModeAlways {
				hasAlwaysBypass = true
			}
		}
	}
	return true, hasAlwaysBypass
}

func describeBypassActor(actor *ghgithub.BypassActor) string {
	actorType := "unknown"
	if actor.ActorType != nil {
		actorType = string(*actor.ActorType)
	}
	mode := "unknown"
	if actor.BypassMode != nil {
		mode = string(*actor.BypassMode)
	}
	return fmt.Sprintf("%s (%s)", actorType, mode)
}

func appendUnique(s []string, v string) []string {
	for _, existing := range s {
		if existing == v {
			return s
		}
	}
	return append(s, v)
}

func appendUniqueAll(s []string, vs []string) []string {
	for _, v := range vs {
		s = appendUnique(s, v)
	}
	return s
}

func checkProtectionExists(org, repo string, eff effectiveProtection, prov []model.Provenance) model.CheckResult {
	const id = "C02.branch.protection-exists"
	status, reason := model.StatusVerifiedFail, "default branch has no legacy branch protection and no ruleset applies to it"
	if eff.exists {
		status, reason = model.StatusVerifiedPass, fmt.Sprintf("default branch is protected via: %v", eff.existsVia)
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"protected_via": eff.existsVia},
	}
}

func checkRequiredReviews(org, repo string, eff effectiveProtection, prov []model.Provenance) model.CheckResult {
	const id = "C02.branch.required-reviews"
	status, reason := model.StatusVerifiedFail, "default branch does not require an approving review before merge"
	if eff.reviewRequired {
		status = model.StatusVerifiedPass
		reason = fmt.Sprintf("default branch requires %d approving review(s)", eff.reviewCount)
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"required_approving_review_count": eff.reviewCount,
			"dismiss_stale_reviews":           eff.dismissStale,
			"via":                             eff.reviewVia,
		},
	}
}

func checkRequiredStatusChecks(org, repo string, eff effectiveProtection, prov []model.Provenance) model.CheckResult {
	const id = "C02.branch.required-status-checks"
	status, reason := model.StatusVerifiedFail, "default branch does not require any status checks before merge"
	if len(eff.statusCheckNames) > 0 {
		status = model.StatusVerifiedPass
		reason = fmt.Sprintf("default branch requires %d status check(s)", len(eff.statusCheckNames))
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"required_status_check_names": eff.statusCheckNames,
			"via":                         eff.statusChecksVia,
		},
	}
}

func checkForcePushBlocked(org, repo string, eff effectiveProtection, prov []model.Provenance) model.CheckResult {
	const id = "C02.branch.force-push-blocked"
	status, reason := model.StatusVerifiedFail, "default branch allows force pushes"
	if eff.forcePushBlocked {
		status, reason = model.StatusVerifiedPass, "default branch blocks force pushes"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"via": eff.forcePushVia},
	}
}

func checkDeletionBlocked(org, repo string, eff effectiveProtection, prov []model.Provenance) model.CheckResult {
	const id = "C02.branch.deletion-blocked"
	status, reason := model.StatusVerifiedFail, "default branch allows deletion"
	if eff.deletionBlocked {
		status, reason = model.StatusVerifiedPass, "default branch blocks deletion"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"via": eff.deletionVia},
	}
}

func checkAdminEnforced(org, repo string, eff effectiveProtection, prov []model.Provenance, bypassLookupErr error) model.CheckResult {
	const id = "C02.branch.admin-enforced"
	if bypassLookupErr != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not fetch ruleset bypass-actor details: %v", bypassLookupErr),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}
	status, reason := model.StatusVerifiedFail, "default branch protections do not apply to admins"
	switch {
	case eff.adminEnforced && len(eff.bypassActors) == 0:
		status, reason = model.StatusVerifiedPass, "default branch protections apply to admins with no bypass actors"
	case eff.adminEnforced:
		status = model.StatusPartial
		reason = fmt.Sprintf("default branch protections apply to admins, but %d conditional bypass actor(s) exist", len(eff.bypassActors))
	case len(eff.bypassActors) > 0:
		status = model.StatusPartial
		reason = "default branch has an unconditional (\"always\") bypass actor"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"via": eff.adminVia, "bypass_actors": eff.bypassActors},
	}
}
