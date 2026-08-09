// Package repoprotection implements C02 repo-protection for a self-hosted
// Gogs instance — the Gogs twin of internal/collect/github/repoprotection
// and its Azure DevOps sibling, registered under the same six check IDs
// (see collectorID's own comment on why that's required, not incidental).
//
// Every one of the six checks is always not-checkable here, and for a
// reason stronger than "this build doesn't read it yet": Gogs has no API
// surface for branch protection at all. GET /repos/{owner}/{repo}/
// branches/{branch}/protection 404s on Gogs 0.15 — verified live on 2026-08-03 — even
// though Gogs' own web UI does let an admin protect a branch. So
// "protection exists" (and everything downstream of it — required
// reviews, required status checks, force-push blocking, deletion
// blocking, admin enforcement) can never be answered verified-pass or
// verified-fail here. Reporting verified-fail would assert the absence of
// a control that may well be configured through the UI; this package never
// does that. This is the codebase's recurring defect class in reverse —
// rather than a value silently defaulting on error and being asserted as
// a confirmed observation, the temptation here would be to assert an
// absence the tool never actually observed. Both are the same mistake.
//
// This package still makes real API calls, though, because knowing
// "protection is unknowable" is not the same as knowing nothing: GET
// /repos/{owner}/{repo} (private/fork/mirror/empty/default_branch), GET
// /repos/{owner}/{repo}/branches (does the repo's own default branch
// actually exist?), and GET /repos/{owner}/{repo}/collaborators (who has
// write access) are all genuinely readable, verified live against Gogs
// 0.15. None of them can ever flip a check's status away from
// not-checkable, but they distinguish a normal resolved repo from one that
// doesn't exist, is empty, or whose default_branch is inconsistent with
// its own branch list — and they populate Facts with real, observed
// values (including whether the repo is a mirror, which matters: a
// mirror's real protection posture lives on its upstream, not here) rather
// than leaving every result equally uninformative.
//
// The branch-protection endpoint itself is deliberately never called: its
// 404 is a fixed, already-verified fact about this platform (like C10
// vdp's privateReportingID/securityPolicyOrgID checks, and the Azure
// DevOps twin's three ACL-governed checks), not a per-scan observation
// worth re-confirming on every repo at the cost of a guaranteed-useless
// provenance entry in every pack this tool produces.
package repoprotection

import (
	"context"
	"fmt"
	"net/http"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gogscollect "gitlab.com/sioakeim/attestward/internal/collect/gogs"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// collectorID must equal the GitHub and Azure DevOps twins' Collector
// string exactly — collect.Register panics if two platforms register the
// same check ID under different Collector strings, and internal/checksref
// groups a check's per-platform subsections by this same identity.
const collectorID = "C02.repo-protection"

// platform is the registry key this package registers under, and what
// scopeRef stamps onto every result so a pack reader can tell a Gogs
// result from a GitHub or Azure DevOps one sharing the same check ID.
const platform = "gogs"

const (
	idProtectionExists     = "C02.branch.protection-exists"
	idRequiredReviews      = "C02.branch.required-reviews"
	idRequiredStatusChecks = "C02.branch.required-status-checks"
	idForcePushBlocked     = "C02.branch.force-push-blocked"
	idDeletionBlocked      = "C02.branch.deletion-blocked"
	idAdminEnforced        = "C02.branch.admin-enforced"
)

// checkIDs is checkTitles' keys in a fixed order, so init()'s registration
// order and allNotCheckable's result order are deterministic — mirrors the
// GitHub and Azure DevOps twins' identical rationale.
var checkIDs = []string{
	idProtectionExists,
	idRequiredReviews,
	idRequiredStatusChecks,
	idForcePushBlocked,
	idDeletionBlocked,
	idAdminEnforced,
}

var checkTitles = map[string]string{
	idProtectionExists:     "Default branch has protection configured",
	idRequiredReviews:      "Default branch requires at least one approving review before merge",
	idRequiredStatusChecks: "Default branch requires status checks before merge",
	idForcePushBlocked:     "Default branch blocks force pushes",
	idDeletionBlocked:      "Default branch blocks branch deletion",
	idAdminEnforced:        "Default branch protections apply to admins (no unconditional bypass actor)",
}

// checkFocus names, in prose, what each check would measure if Gogs
// exposed it — shared by platformLimitationReason (the per-scan Reason)
// and checkRubrics (the static per-check documentation), so the two can
// never drift apart into describing different things.
var checkFocus = map[string]string{
	idProtectionExists:     "whether any branch protection exists at all",
	idRequiredReviews:      "whether the default branch requires an approving review before merge",
	idRequiredStatusChecks: "whether the default branch requires status checks before merge",
	idForcePushBlocked:     "whether force pushes to the default branch are blocked",
	idDeletionBlocked:      "whether deleting the default branch is blocked",
	idAdminEnforced:        "whether these protections bind admins with no unconditional bypass",
}

var checkRemediations = map[string]string{
	idProtectionExists: "Configure branch protection for the default branch in the Gogs web UI (repo Settings " +
		"-> Branches) and confirm it there — Gogs' API has no endpoint that reports whether protection exists " +
		"at all, so this tool cannot verify the result.",
	idRequiredReviews: "In the Gogs web UI's branch-protection settings for the default branch, require at " +
		"least one approving review, and confirm it there — this tool cannot read review requirements back " +
		"from the API.",
	idRequiredStatusChecks: "In the Gogs web UI's branch-protection settings for the default branch, require " +
		"the relevant status checks, and confirm it there — this tool cannot read status-check requirements " +
		"back from the API.",
	idForcePushBlocked: "In the Gogs web UI's branch-protection settings for the default branch, disable force " +
		"pushes, and confirm it there — this tool cannot read force-push settings back from the API.",
	idDeletionBlocked: "In the Gogs web UI's branch-protection settings for the default branch, disable branch " +
		"deletion, and confirm it there — this tool cannot read deletion settings back from the API.",
	idAdminEnforced: "In the Gogs web UI's branch-protection settings for the default branch, ensure no user " +
		"or team (including admins) is exempted, and confirm it there — this tool cannot read bypass/enforcement " +
		"settings back from the API.",
}

// checkRubrics gives each check's own concrete meaning for the only status
// it can ever produce. All six are always not-checkable — see the package
// doc comment for why — so unlike the GitHub and Azure DevOps twins, none
// of these entries describes a verified-pass/fail/partial condition that
// simply never arises here.
var checkRubrics = map[string]map[model.Status]string{
	idProtectionExists: {
		model.StatusNotCheckable: notCheckableAlwaysRubric(idProtectionExists),
	},
	idRequiredReviews: {
		model.StatusNotCheckable: notCheckableAlwaysRubric(idRequiredReviews),
	},
	idRequiredStatusChecks: {
		model.StatusNotCheckable: notCheckableAlwaysRubric(idRequiredStatusChecks),
	},
	idForcePushBlocked: {
		model.StatusNotCheckable: notCheckableAlwaysRubric(idForcePushBlocked),
	},
	idDeletionBlocked: {
		model.StatusNotCheckable: notCheckableAlwaysRubric(idDeletionBlocked),
	},
	idAdminEnforced: {
		model.StatusNotCheckable: notCheckableAlwaysRubric(idAdminEnforced),
	},
}

// notCheckableAlwaysRubric builds the static Rubric text for id's only
// reachable status. It documents both the common case (a resolved repo
// whose protection genuinely cannot be observed) and the narrower cases
// (an unreadable repo, an empty repo, or a default_branch inconsistent
// with the repo's own branch list) that produce the same status via a
// more specific per-scan Reason — see platformLimitationReason and
// allNotCheckable.
func notCheckableAlwaysRubric(id string) string {
	return "always — Gogs exposes no API for " + checkFocus[id] + ": GET .../branches/{branch}/protection " +
		"404s on Gogs 0.15 (verified 2026-08-03), and no other endpoint carries this data. The control may " +
		"still be configured through the Gogs web UI; this only means it is not observable through the API. " +
		"A repo that could not be read at all, is empty, or whose default_branch is missing from its own " +
		"branch list produces the same not-checkable status, via a different, more specific Reason"
}

// sharedEndpoints backs every one of this package's checks: not because
// any of them determine a check's status (none of the six ever leave
// not-checkable), but because they determine which of the several
// not-checkable Reasons is reported, and they populate every result's
// Facts. The branch-protection endpoint itself is deliberately absent —
// see the package doc comment for why it is never called at all.
var sharedEndpoints = []string{
	"GET /repos/{owner}/{repo}",
	"GET /repos/{owner}/{repo}/branches",
	"GET /repos/{owner}/{repo}/collaborators",
}

var checkEndpoints = map[string][]string{
	idProtectionExists:     sharedEndpoints,
	idRequiredReviews:      sharedEndpoints,
	idRequiredStatusChecks: sharedEndpoints,
	idForcePushBlocked:     sharedEndpoints,
	idDeletionBlocked:      sharedEndpoints,
	idAdminEnforced:        sharedEndpoints,
}

// tokenScope is shared verbatim by all six checks, matching C10 vdp's
// identical text: Gogs tokens carry the full permissions of the issuing
// account and cannot be scoped down, so least privilege here is about
// which account issues the token, not about narrowing the token itself.
const tokenScope = "any Gogs personal access token that can read the repo. Gogs tokens are not scopable — " +
	"every token carries the full permissions of the account that issued it — so least privilege here means " +
	"using an account with read-only access to the repos in scope, not narrowing the token itself"

const fixtureRef = "internal/collect/gogs/repoprotection/repoprotection_test.go"

func init() {
	for _, id := range checkIDs {
		collect.Register(collect.CheckMeta{
			ID:          id,
			Platform:    platform,
			Title:       checkTitles[id],
			Collector:   collectorID,
			TokenScope:  tokenScope,
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			FixtureRef:  fixtureRef,
		})
	}
}

// Collector implements C02 repo-protection against a Gogs instance.
type Collector struct {
	baseURL string
	token   string

	// newClient builds one Client per repo, so each repo's provenance is
	// exactly the calls made for that repo — mirrors C10 vdp's identical
	// per-repo Client isolation. Overridden in tests to terminate the
	// transport chain in a fixture.
	newClient func() (*gogscollect.Client, error)
}

// New builds the collector against the Gogs instance at baseURL,
// authenticated with token.
func New(baseURL, token string) *Collector {
	c := &Collector{baseURL: baseURL, token: token}
	c.newClient = func() (*gogscollect.Client, error) { return gogscollect.NewClient(baseURL, token) }
	return c
}

// NewForTest builds a collector whose per-repo Clients terminate in the
// caller's transport (typically gogsfixture.New()), exercising the real
// auth, provenance and retry layers.
func NewForTest(baseURL, token string, newClient func() (*gogscollect.Client, error)) *Collector {
	return &Collector{baseURL: baseURL, token: token, newClient: newClient}
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. Repos are processed sequentially,
// matching C10 vdp: this platform has no ForEachRepo helper, and a Gogs
// instance is typically a single self-hosted server where fanning out
// buys throughput at the cost of hammering something one team runs.
//
// It never returns a non-nil top-level error for a per-repo API failure:
// one unreachable repo must not cost the scan every other repo's
// evidence.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	var all []model.CheckResult

	for _, repo := range scope.Repos {
		if err := ctx.Err(); err != nil {
			reason := fmt.Sprintf("scan canceled before this repo's checks ran: %v", err)
			all = append(all, allNotCheckable(scope.Org, repo, reason, nil, nil)...)
			continue
		}

		client, err := c.newClient()
		if err != nil {
			reason := fmt.Sprintf("could not build a client for this repo: %v", err)
			all = append(all, allNotCheckable(scope.Org, repo, reason, nil, nil)...)
			continue
		}
		all = append(all, collectRepo(ctx, client, scope.Org, repo)...)
	}
	if all == nil {
		all = []model.CheckResult{}
	}
	return all, nil
}

// repoRaw is the subset of Gogs' Repository shape this package needs,
// from GET /repos/{owner}/{repo}. Verified live against Gogs 0.15 on
// 2026-08-03: private, fork, mirror, empty and default_branch are all
// present as documented.
type repoRaw struct {
	Private       bool   `json:"private"`
	Fork          bool   `json:"fork"`
	Mirror        bool   `json:"mirror"`
	Empty         bool   `json:"empty"`
	DefaultBranch string `json:"default_branch"`
}

// branchRaw is the subset of Gogs' Branch shape this package needs, from
// GET /repos/{owner}/{repo}/branches. It carries no protection field —
// Gogs' branches list, unlike GitHub's, says nothing about protection at
// all.
type branchRaw struct {
	Name string `json:"name"`
}

// collaboratorRaw is the subset of Gogs' collaborator shape this package
// needs, from GET /repos/{owner}/{repo}/collaborators.
type collaboratorRaw struct {
	Login string `json:"login"`
}

// collectRepo resolves one repo's state and emits all six CheckResults for
// it. Every one of the six is always not-checkable (see the package doc
// comment); what varies is which Reason is reported and what Facts
// accompany it.
func collectRepo(ctx context.Context, client *gogscollect.Client, org, repo string) []model.CheckResult {
	info, err := fetchRepo(ctx, client, org, repo)
	if err != nil {
		return allNotCheckable(org, repo, repoErrReason(err, org, repo), client.Provenance(), nil)
	}

	if info.Empty || info.DefaultBranch == "" {
		reason := "repository is empty; it has no default branch to protect"
		return allNotCheckable(org, repo, reason, client.Provenance(), baseFacts(info))
	}

	branches, err := fetchBranches(ctx, client, org, repo)
	if err != nil {
		reason := fmt.Sprintf("could not confirm the default branch exists: %v", err)
		return allNotCheckable(org, repo, reason, client.Provenance(), baseFacts(info))
	}
	if !branchExists(branches, info.DefaultBranch) {
		reason := fmt.Sprintf("default branch %q is not present in this repository's own branch list — "+
			"cannot even confirm the branch exists, let alone its protection", info.DefaultBranch)
		return allNotCheckable(org, repo, reason, client.Provenance(), baseFacts(info))
	}

	facts := baseFacts(info)
	if count, err := fetchCollaboratorCount(ctx, client, org, repo); err == nil {
		facts["write_collaborator_count"] = count
	}

	prov := client.Provenance()
	results := make([]model.CheckResult, 0, len(checkIDs))
	for _, id := range checkIDs {
		results = append(results, model.CheckResult{
			CheckID:    id,
			Title:      checkTitles[id],
			Status:     model.StatusNotCheckable,
			Reason:     platformLimitationReason(id, info),
			Scope:      scopeRef(org, repo),
			Provenance: prov,
			Facts:      facts,
		})
	}
	return results
}

// baseFacts carries the repo-level observations that hold regardless of
// which not-checkable Reason a given repo ends up with — populated as
// soon as the repo itself resolves, since all of it is real, observed
// data even when the default branch can't be confirmed to exist.
func baseFacts(info repoRaw) map[string]any {
	facts := map[string]any{
		"private": info.Private,
		"fork":    info.Fork,
		"mirror":  info.Mirror,
	}
	if info.DefaultBranch != "" {
		facts["default_branch"] = info.DefaultBranch
	}
	return facts
}

// platformLimitationReason is the Reason for the common case: the repo
// and its default branch both resolved fine, and the only thing standing
// between this check and an answer is that Gogs has no API for it. It
// calls out a mirror explicitly — a mirrored repo's real protection
// posture lives on its upstream, not here, which is a materially
// different attestation story from an ordinary repo Gogs simply can't
// report on.
func platformLimitationReason(id string, info repoRaw) string {
	reason := fmt.Sprintf("Gogs exposes no API for %s on the default branch (%q) — GET "+
		".../branches/{branch}/protection 404s on this platform (verified against Gogs 0.15); it may still be "+
		"configured through the web UI, but this tool cannot observe it", checkFocus[id], info.DefaultBranch)
	if info.Mirror {
		reason += "; this repo is also a mirror, so its real protection posture (if any) lives on the " +
			"upstream repository, not here"
	}
	return reason
}

// allNotCheckable produces a not-checkable result for every check ID, all
// sharing the same reason, provenance and facts — used for the early-exit
// paths (a repo that couldn't be read, is empty, or has a
// branch-list-inconsistent default_branch), where the underlying cause is
// the same for all six checks and unrelated to any one check's own focus.
func allNotCheckable(org, repo, reason string, prov []model.Provenance, facts map[string]any) []model.CheckResult {
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
			Scope:      scopeRef(org, repo),
			Provenance: prov,
			Facts:      facts,
		})
	}
	return out
}

func scopeRef(org, repo string) model.ScopeRef {
	return model.ScopeRef{Org: org, Repo: repo, Platform: platform}
}

// fetchRepo reads GET /repos/{owner}/{repo}.
func fetchRepo(ctx context.Context, client *gogscollect.Client, org, repo string) (repoRaw, error) {
	var out repoRaw
	err := gogscollect.GetJSON(ctx, client, fmt.Sprintf("/repos/%s/%s", org, repo), nil, &out)
	return out, err
}

// fetchBranches reads GET /repos/{owner}/{repo}/branches — the full list,
// not the single-branch endpoint, since what this package needs is
// whether the repo's own default_branch value actually appears in it.
func fetchBranches(ctx context.Context, client *gogscollect.Client, org, repo string) ([]branchRaw, error) {
	var out []branchRaw
	err := gogscollect.GetJSON(ctx, client, fmt.Sprintf("/repos/%s/%s/branches", org, repo), nil, &out)
	return out, err
}

// fetchCollaboratorCount reads GET /repos/{owner}/{repo}/collaborators and
// returns how many collaborators have write access. A failure here is
// never fatal to the surrounding checks — see collectRepo, which simply
// omits the fact rather than escalating to a not-checkable-for-error
// path, since no check's status ever depends on this value.
func fetchCollaboratorCount(ctx context.Context, client *gogscollect.Client, org, repo string) (int, error) {
	var out []collaboratorRaw
	err := gogscollect.GetJSON(ctx, client, fmt.Sprintf("/repos/%s/%s/collaborators", org, repo), nil, &out)
	if err != nil {
		return 0, err
	}
	return len(out), nil
}

func branchExists(branches []branchRaw, name string) bool {
	for _, b := range branches {
		if b.Name == name {
			return true
		}
	}
	return false
}

// repoErrReason turns a fetchRepo failure into a Reason string, naming the
// exact permission/existence problem when err is a *gogscollect.StatusError
// with a 403 or 404 status — mirrors the GitHub twin's notCheckableReason.
func repoErrReason(err error, org, repo string) string {
	if code, ok := gogscollect.StatusCodeOf(err); ok {
		switch code {
		case http.StatusNotFound:
			return fmt.Sprintf("%s/%s not found, or not visible to this token", org, repo)
		case http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to read %s/%s", org, repo)
		}
	}
	return fmt.Sprintf("could not read repository %s/%s: %v", org, repo, err)
}
