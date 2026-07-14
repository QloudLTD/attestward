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

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:          id,
			Title:       checkTitles[id],
			Collector:   collectorID,
			TokenScope:  "repo (classic) or Administration: read-only (fine-grained)",
			Remediation: checkRemediations[id],
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
