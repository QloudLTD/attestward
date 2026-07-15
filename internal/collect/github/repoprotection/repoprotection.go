// Package repoprotection implements C02 repo-protection: branch protection
// and ruleset posture on each in-scope repo's default branch (SSDF PS.1) —
// the code-integrity and separation-of-duties controls the CISA form's
// second cluster asks the signer to attest to.
//
// v0.1 checks only the default branch. The issue this package was built
// against also mentions "release branches", but collect.Scope carries no
// release-branch-pattern concept — only ReleaseTagPattern, for release
// *tags* (an unrelated thing C07 will use), not branches. Adding one is a
// Scope-schema change that reaches beyond a single collector; tracked as a
// follow-up rather than guessed at here.
package repoprotection

import (
	"context"
	"fmt"
	"net/http"

	ghgithub "github.com/google/go-github/v75/github"

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/model"
)

const collectorID = "C02.repo-protection"

var checkTitles = map[string]string{
	"C02.branch.protection-exists":      "Default branch has protection (legacy branch protection or a ruleset)",
	"C02.branch.required-reviews":       "Default branch requires at least one approving review before merge",
	"C02.branch.required-status-checks": "Default branch requires status checks before merge",
	"C02.branch.force-push-blocked":     "Default branch blocks force pushes",
	"C02.branch.deletion-blocked":       "Default branch blocks branch deletion",
	"C02.branch.admin-enforced":         "Default branch protections apply to admins (no unconditional bypass actor)",
}

// checkIDs is checkTitles' keys in a fixed order, so init()'s registration
// order and allNotCheckable's result order are deterministic — map
// iteration order isn't, and an evidence pack's whole point is to diff
// cleanly across runs of the same scan.
var checkIDs = []string{
	"C02.branch.protection-exists",
	"C02.branch.required-reviews",
	"C02.branch.required-status-checks",
	"C02.branch.force-push-blocked",
	"C02.branch.deletion-blocked",
	"C02.branch.admin-enforced",
}

var checkRemediations = map[string]string{
	"C02.branch.protection-exists": "Repo Settings -> Rules -> Rulesets (or the legacy Settings -> " +
		"Branches -> Branch protection rules) -> add a rule targeting the default branch.",
	"C02.branch.required-reviews": "In that ruleset/protection rule, enable \"Require a pull request " +
		"before merging\" with at least 1 required approving review.",
	"C02.branch.required-status-checks": "In that ruleset/protection rule, enable \"Require status checks " +
		"to pass before merging\" and select the CI checks that must pass.",
	"C02.branch.force-push-blocked": "In a ruleset, enable \"Block force pushes\"; in legacy branch " +
		"protection, leave \"Allow force pushes\" unchecked.",
	"C02.branch.deletion-blocked": "In a ruleset, enable \"Restrict deletions\"; in legacy branch " +
		"protection, leave \"Allow deletions\" unchecked.",
	"C02.branch.admin-enforced": "For a ruleset, set Enforcement status to \"Active\" (not \"Evaluate\") " +
		"and remove every bypass actor entirely — even one scoped to \"Pull request only\" caps this " +
		"check at partial, not a full pass. For legacy branch protection, check \"Do not allow bypassing " +
		"the above settings\" (Include administrators). Where both legacy protection and a ruleset apply " +
		"to the same branch, both must independently bind admins for this check to pass.",
}

// sharedNotCheckableRubric is the not-checkable explanation shared by the
// five binary checks (see checkRubrics below): every one of them bottoms
// out at the same three upstream reads in collectRepo, and none of them
// depends on anything else. Deliberately calls out that a 404 specifically
// on the legacy branch-protection read is NOT this outcome — collectRepo
// treats it as "no legacy protection configured", a normal, legitimate
// input that still lets the other regime (a ruleset) determine the actual
// status.
const sharedNotCheckableRubric = "the repo read failed, the repo has no default branch, the legacy " +
	"branch-protection read failed with anything other than a 404 (a 404 there just means \"no legacy " +
	"protection configured\", not an error), or the rules-for-branch read failed (403/404/other API error)"

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce. Five of the six checks are binary pass/fail (plus
// not-checkable) — each reduces to one boolean field on the merged
// effectiveProtection (see effective.go's resolveEffectiveProtection).
// admin-enforced is the one exception: it can genuinely produce `partial`,
// for either of two distinct reasons (see checkAdminEnforced), both
// spelled out below rather than collapsed into one vague sentence.
var checkRubrics = map[string]map[model.Status]string{
	"C02.branch.protection-exists": {
		model.StatusVerifiedPass: "legacy branch protection is configured on the default branch, or at " +
			"least one ruleset rule applies to it (`effectiveProtection.exists`, via GetBranchProtection " +
			"succeeding or GetRulesForBranch returning at least one active rule this collector tracks)",
		model.StatusVerifiedFail: "default branch has no legacy branch protection and no ruleset applies to it",
		model.StatusNotCheckable: sharedNotCheckableRubric,
	},
	"C02.branch.required-reviews": {
		model.StatusVerifiedPass: "legacy protection's `required_approving_review_count` is >= 1, or a " +
			"ruleset's pull-request rule sets `required_approving_review_count` >= 1 (whichever regime " +
			"requires more reviews sets the reported count)",
		model.StatusVerifiedFail: "neither legacy protection nor any ruleset requires an approving review",
		model.StatusNotCheckable: sharedNotCheckableRubric,
	},
	"C02.branch.required-status-checks": {
		model.StatusVerifiedPass: "legacy protection or a ruleset names at least one required status check",
		model.StatusVerifiedFail: "neither regime names any required status check",
		model.StatusNotCheckable: sharedNotCheckableRubric,
	},
	"C02.branch.force-push-blocked": {
		model.StatusVerifiedPass: "legacy protection disables `allow_force_pushes` (or leaves the field " +
			"unset, which GitHub defaults to disabled), or a ruleset has an active non-fast-forward rule",
		model.StatusVerifiedFail: "force pushes are allowed by both regimes",
		model.StatusNotCheckable: sharedNotCheckableRubric,
	},
	"C02.branch.deletion-blocked": {
		model.StatusVerifiedPass: "legacy protection disables `allow_deletions` (or leaves the field unset), " +
			"or a ruleset has an active deletion rule",
		model.StatusVerifiedFail: "branch deletion is allowed by both regimes",
		model.StatusNotCheckable: sharedNotCheckableRubric,
	},
	"C02.branch.admin-enforced": {
		model.StatusVerifiedPass: "every regime that contributes any protection also enforces it against " +
			"admins (legacy's `enforce_admins` is true, if legacy protection exists at all; any ruleset " +
			"contributing a relevant rule has zero bypass actors) — and no bypass actor exists on any " +
			"ruleset contributing a relevant rule (only rulesets behind the pull-request/status-check/" +
			"force-push/deletion rules this collector tracks are inspected; a bypass actor on an unrelated " +
			"ruleset, e.g. one that only sets a commit-message pattern, doesn't affect this check)",
		model.StatusPartial: "either (a) admins are bound by every contributing regime, but at least one " +
			"conditional (non-\"always\"-mode, e.g. \"pull_request\"-only) bypass actor exists on a " +
			"relevant ruleset, or (b) an unconditional (\"always\"-mode) bypass actor exists on a " +
			"relevant ruleset — this alone caps the check at partial regardless of what legacy separately " +
			"enforces",
		model.StatusVerifiedFail: "no regime fully enforces admins — either nothing contributes " +
			"admin-relevant protection at all, or legacy protection exists but exempts admins " +
			"(`enforce_admins` is false) even though a ruleset separately would bind them — and no " +
			"unconditional (\"always\"-mode) bypass actor is present either; any conditional bypass " +
			"actor(s) present don't change this outcome, since admins already aren't bound by every " +
			"contributing regime",
		model.StatusNotCheckable: sharedNotCheckableRubric + ", or the ruleset bypass-actor lookup itself " +
			"failed (GET .../rulesets/{ruleset_id})",
	},
}

// checkEndpoints lists which REST endpoint(s) actually back each check's
// status. All six checks depend on the same three upstream reads (default
// branch resolution, legacy protection, ruleset rules); admin-enforced
// additionally depends on a per-ruleset bypass-actor lookup that the other
// five never trigger (see fetchRulesetsForBypassActors's own doc comment
// for why only that one check needs it).
var sharedEndpoints = []string{
	"GET /repos/{owner}/{repo}",
	"GET /repos/{owner}/{repo}/branches/{branch}/protection",
	"GET /repos/{owner}/{repo}/rules/branches/{branch}",
}

var checkEndpoints = map[string][]string{
	"C02.branch.protection-exists":      sharedEndpoints,
	"C02.branch.required-reviews":       sharedEndpoints,
	"C02.branch.required-status-checks": sharedEndpoints,
	"C02.branch.force-push-blocked":     sharedEndpoints,
	"C02.branch.deletion-blocked":       sharedEndpoints,
	"C02.branch.admin-enforced": append(append([]string{}, sharedEndpoints...),
		"GET /repos/{owner}/{repo}/rulesets/{ruleset_id}?includes_parents=true"),
}

const fixtureRef = "internal/collect/github/repoprotection/repoprotection_test.go"

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:          id,
			Title:       checkTitles[id],
			Collector:   collectorID,
			TokenScope:  "repo (classic) or Administration: read-only (fine-grained)",
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			FixtureRef:  fixtureRef,
		})
	}
}

// Collector implements C02 repo-protection.
type Collector struct {
	token string

	// newClientForTest overrides how each repo's Client is constructed —
	// production code never sets it (New leaves it nil and Collect falls
	// back to ghcollect.NewClient); tests use it to point every per-repo
	// client at an httptest.Server, the same role scanDeps' injected fields
	// play in cmd/attestor/scan.go.
	newClientForTest func(token string) *ghcollect.Client
}

// New returns a C02 collector authenticated with token. Unlike a collector
// that makes one call per Collect() (e.g. org-security), this one fans out
// per-repo via ghcollect.ForEachRepo's concurrent worker pool — so a single
// shared *ghcollect.Client would interleave different repos' calls into one
// Provenance() log, making a "snapshot before, diff after" attribution (the
// pattern org-security uses) attribute the wrong entries to the wrong repo.
// Each repo gets its own freshly constructed Client instead, so its
// provenance is naturally isolated and needs no slicing.
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

// Collect implements collect.Collector. Like org-security, it never returns
// a non-nil top-level error for a per-repo API failure — those become
// not-checkable results for each of the six specific check IDs, scoped to
// that repo, so the rollup can still resolve them.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	repoResults := ghcollect.ForEachRepo(ctx, scope.Repos, ghcollect.DefaultConcurrency, func(ctx context.Context, repo string) ([]model.CheckResult, error) {
		client := c.newClient()
		return collectRepo(ctx, client, scope.Org, repo), nil
	})

	var all []model.CheckResult
	for _, r := range repoResults {
		if r.Err != nil {
			// The callback above never returns a non-nil error itself, so
			// this is only ever ctx.Err() from ForEachRepo — a scan
			// canceled before this repo's turn came up. Surface it as
			// not-checkable per repo rather than silently dropping the repo
			// from the pack.
			all = append(all, allNotCheckable(scope.Org, r.Repo, fmt.Sprintf("scan canceled before this repo's checks ran: %v", r.Err), []model.Provenance{})...)
			continue
		}
		all = append(all, r.Value...)
	}
	if all == nil {
		all = []model.CheckResult{}
	}
	return all, nil
}

// collectRepo resolves effective branch protection for one repo's default
// branch and emits all six CheckResults. It never returns an error; every
// failure becomes a not-checkable result for the affected check(s).
func collectRepo(ctx context.Context, client *ghcollect.Client, org, repo string) []model.CheckResult {
	repository, resp, err := client.REST.Repositories.Get(ctx, org, repo)
	if err != nil {
		return allNotCheckable(org, repo, notCheckableReason(resp, err, org, repo), client.Provenance())
	}
	branch := repository.GetDefaultBranch()
	if branch == "" {
		return allNotCheckable(org, repo, "repository has no default branch (empty repository?)", client.Provenance())
	}

	legacy, legacyResp, legacyErr := client.REST.Repositories.GetBranchProtection(ctx, org, repo, branch)
	if legacyErr != nil {
		if legacyResp == nil || legacyResp.StatusCode != http.StatusNotFound {
			// A real error (permission denied, etc.) — distinct from "no
			// legacy protection configured", which GitHub reports as a 404
			// on this endpoint and which this collector treats as a
			// legitimate, non-error input to the merge below (many repos
			// are ruleset-only, with zero legacy protection).
			return allNotCheckable(org, repo, notCheckableReason(legacyResp, legacyErr, org, repo), client.Provenance())
		}
		legacy = nil
	}

	rules, rulesResp, rulesErr := client.REST.Repositories.GetRulesForBranch(ctx, org, repo, branch, nil)
	if rulesErr != nil {
		return allNotCheckable(org, repo, notCheckableReason(rulesResp, rulesErr, org, repo), client.Provenance())
	}

	rulesets, bypassLookupErr := fetchRulesetsForBypassActors(ctx, client, org, repo, rules)

	eff := resolveEffectiveProtection(legacy, rules, rulesets)
	prov := client.Provenance()

	results := []model.CheckResult{
		checkProtectionExists(org, repo, eff, prov),
		checkRequiredReviews(org, repo, eff, prov),
		checkRequiredStatusChecks(org, repo, eff, prov),
		checkForcePushBlocked(org, repo, eff, prov),
		checkDeletionBlocked(org, repo, eff, prov),
		checkAdminEnforced(org, repo, eff, prov, bypassLookupErr),
	}
	return results
}

// fetchRulesetsForBypassActors fetches full ruleset details (bypass actors
// aren't included in GetRulesForBranch's effective-rules view) for every
// ruleset ID referenced by an active rule this collector cares about. It
// returns whatever it could fetch plus the first error encountered, if any
// — a partial map lets the five non-admin checks still resolve even if one
// ruleset lookup fails; checkAdminEnforced is the only one that needs to
// know about the failure.
func fetchRulesetsForBypassActors(ctx context.Context, client *ghcollect.Client, org, repo string, rules *ghgithub.BranchRules) (map[int64]*ghgithub.RepositoryRuleset, error) {
	ids := relevantRulesetIDs(rules)
	if len(ids) == 0 {
		return nil, nil
	}
	out := make(map[int64]*ghgithub.RepositoryRuleset, len(ids))
	var firstErr error
	for id := range ids {
		rs, _, err := client.REST.Repositories.GetRuleset(ctx, org, repo, id, true)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out[id] = rs
	}
	return out, firstErr
}

// relevantRulesetIDs collects the ruleset IDs behind every active rule in
// the four categories this collector's checks depend on (pull request
// review, required status checks, force-push block, deletion block) — a
// ruleset that only sets e.g. a commit-message pattern is irrelevant here
// and its ID is deliberately not looked up.
func relevantRulesetIDs(rules *ghgithub.BranchRules) map[int64]struct{} {
	ids := map[int64]struct{}{}
	if rules == nil {
		return ids
	}
	for _, r := range rules.PullRequest {
		ids[r.RulesetID] = struct{}{}
	}
	for _, r := range rules.RequiredStatusChecks {
		ids[r.RulesetID] = struct{}{}
	}
	for _, r := range rules.NonFastForward {
		ids[r.RulesetID] = struct{}{}
	}
	for _, r := range rules.Deletion {
		ids[r.RulesetID] = struct{}{}
	}
	return ids
}

func notCheckableReason(resp *ghgithub.Response, err error, org, repo string) string {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to read protection settings on %s/%s", org, repo)
		case http.StatusNotFound:
			return fmt.Sprintf("%s/%s not found, or not visible to this token", org, repo)
		}
	}
	return fmt.Sprintf("could not query %s/%s: %v", org, repo, err)
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
