package repoprotection

import (
	"context"
	"net/http"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "github.com/sioakim/attestward/internal/collect/github"
)

// RequiredStatusCheckNames fetches legacy branch protection and
// ruleset-derived rules for branch and returns the same merged set of
// required status-check context names (and which regime(s) contributed
// them) that this package's own C02.branch.required-status-checks check
// uses internally.
//
// It exists because collectors are independent (collect.Collector's doc
// comment: no collector sees another's CheckResults, they only share
// collect.Scope), so a collector that needs to know "is check X required"
// — e.g. C06 sca-history's dependency-review check — can't read C02's
// Facts and must make its own API call instead. This reuses
// resolveEffectiveProtection's tested merge logic rather than duplicating
// it, so both collectors agree on what "required" means without two
// independently-maintained copies drifting apart. It does not fetch
// per-ruleset bypass-actor detail (bypassLookupErr's concern in
// collectRepo) since that's irrelevant to status-check names.
func RequiredStatusCheckNames(ctx context.Context, client *ghcollect.Client, org, repo, branch string) (names []string, via []string, resp *ghgithub.Response, err error) {
	legacy, legacyResp, legacyErr := client.REST.Repositories.GetBranchProtection(ctx, org, repo, branch)
	if legacyErr != nil {
		if legacyResp == nil || legacyResp.StatusCode != http.StatusNotFound {
			return nil, nil, legacyResp, legacyErr
		}
		legacy = nil
	}

	rules, rulesResp, rulesErr := client.REST.Repositories.GetRulesForBranch(ctx, org, repo, branch, nil)
	if rulesErr != nil {
		return nil, nil, rulesResp, rulesErr
	}

	eff := resolveEffectiveProtection(legacy, rules, nil)
	return eff.statusCheckNames, eff.statusChecksVia, nil, nil
}
