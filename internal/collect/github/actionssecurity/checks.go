package actionssecurity

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sioakim/ssdf/internal/model"
)

const (
	checkPinnedID           = "C08.actions.pinned"
	checkTokenPermissionsID = "C08.actions.token-permissions"
	checkPRTargetID         = "C08.actions.pull-request-target"
	checkOIDCID             = "C08.actions.oidc-vs-secrets"
	checkSelfHostedID       = "C08.actions.self-hosted"
)

func notCheckableResult(id, org, repo, reason string, prov []model.Provenance) model.CheckResult {
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
	}
}

func splitActionRefLocal(uses string) (slug, ref string) {
	slug, ref, _ = strings.Cut(uses, "@")
	return slug, ref
}

// -----------------------------------------------------------------------
// C08.actions.pinned
// -----------------------------------------------------------------------

// isFirstPartyActionsSlug reports whether slug is under the GitHub-owned
// "actions/" namespace — the only namespace issue #20's rubric tolerates a
// mutable major-version tag on (capping at partial rather than a hard
// fail). Everything else, including other GitHub-owned orgs like
// "github/", is treated as third-party here — matching the issue's rubric
// literally rather than inventing a broader "trusted publishers" list.
func isFirstPartyActionsSlug(slug string) bool {
	return strings.HasPrefix(slug, "actions/")
}

var shaRefPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

func isFullSHA(ref string) bool {
	return shaRefPattern.MatchString(ref)
}

// externalActionRef reports whether uses is a reference this check should
// evaluate for pinning — excluding Docker Hub image refs ("docker://...",
// a different addressing scheme with no "pin to a commit SHA" concept in
// the same sense) and local composite actions ("./path", already pinned
// by the repo's own commit, not by a separate ref).
func externalActionRef(uses string) bool {
	return uses != "" && !strings.HasPrefix(uses, "docker://") && !strings.HasPrefix(uses, "./") && strings.Contains(uses, "@")
}

type actionRefFinding struct {
	File  string
	Line  int
	Uses  string
	Slug  string
	Ref   string
	Class string // "third-party" | "first-party"
}

func gatherActionRefs(u workflowUnit) []actionRefFinding {
	finder := newLineFinder(u.Raw)
	var out []actionRefFinding
	for _, jobName := range sortedJobNames(u.Parsed.Jobs) {
		job := u.Parsed.Jobs[jobName]
		var refs []string
		if job.Uses != "" {
			refs = append(refs, job.Uses)
		}
		for _, step := range job.Steps {
			if step.Uses != "" {
				refs = append(refs, step.Uses)
			}
		}
		for _, uses := range refs {
			if !externalActionRef(uses) {
				continue
			}
			slug, ref := splitActionRefLocal(uses)
			class := "third-party"
			if isFirstPartyActionsSlug(slug) {
				class = "first-party"
			}
			out = append(out, actionRefFinding{File: u.Label, Line: finder.Find(uses), Uses: uses, Slug: slug, Ref: ref, Class: class})
		}
	}
	return out
}

func actionRefFindingsToFacts(refs []actionRefFinding) []map[string]any {
	out := make([]map[string]any, 0, len(refs))
	for _, r := range refs {
		out = append(out, map[string]any{"file": r.File, "line": r.Line, "uses": r.Uses, "slug": r.Slug, "ref": r.Ref, "class": r.Class})
	}
	return out
}

func unresolvedToFacts(items []unresolvedExternalWorkflow) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, u := range items {
		out = append(out, map[string]any{"file": u.FromFile, "line": u.Line, "ref": u.Ref})
	}
	return out
}

// checkPinned implements issue #20's rubric exactly: a third-party
// action/reusable-workflow reference not pinned to a full 40-char commit
// SHA is a hard fail; a first-party actions/* reference on a mutable
// major-version tag is tolerated but caps the result at partial.
func checkPinned(org, repo string, units []workflowUnit, unresolvedExternal []unresolvedExternalWorkflow, prov []model.Provenance) model.CheckResult {
	if len(units) == 0 {
		return notCheckableResult(checkPinnedID, org, repo, "no GitHub Actions workflow files found on the default branch", prov)
	}

	var allRefs []actionRefFinding
	for _, u := range units {
		allRefs = append(allRefs, gatherActionRefs(u)...)
	}

	unresolvedFacts := unresolvedToFacts(unresolvedExternal)

	if len(allRefs) == 0 {
		return model.CheckResult{
			CheckID: checkPinnedID, Title: checkTitles[checkPinnedID], Status: model.StatusVerifiedPass,
			Reason: "no external action or reusable-workflow references found; nothing to pin",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
			Facts: map[string]any{"unresolved_external_workflows": unresolvedFacts},
		}
	}

	var thirdPartyUnpinned, firstPartyUnpinned []actionRefFinding
	for _, r := range allRefs {
		if isFullSHA(r.Ref) {
			continue
		}
		if r.Class == "first-party" {
			firstPartyUnpinned = append(firstPartyUnpinned, r)
		} else {
			thirdPartyUnpinned = append(thirdPartyUnpinned, r)
		}
	}

	status := model.StatusVerifiedPass
	reason := "every third-party action and reusable-workflow reference is pinned to a full-length commit SHA"
	switch {
	case len(thirdPartyUnpinned) > 0:
		status = model.StatusVerifiedFail
		reason = fmt.Sprintf("%d third-party action/reusable-workflow reference(s) are not pinned to a full-length commit SHA", len(thirdPartyUnpinned))
	case len(firstPartyUnpinned) > 0:
		status = model.StatusPartial
		reason = fmt.Sprintf("every third-party reference is SHA-pinned, but %d first-party actions/* reference(s) use a mutable tag instead of a SHA", len(firstPartyUnpinned))
	}

	return model.CheckResult{
		CheckID: checkPinnedID, Title: checkTitles[checkPinnedID], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"third_party_unpinned":          actionRefFindingsToFacts(thirdPartyUnpinned),
			"first_party_unpinned":          actionRefFindingsToFacts(firstPartyUnpinned),
			"unresolved_external_workflows": unresolvedFacts,
		},
	}
}

// -----------------------------------------------------------------------
// C08.actions.token-permissions
// -----------------------------------------------------------------------

func isWriteAll(v any) bool {
	s, ok := v.(string)
	return ok && strings.EqualFold(strings.TrimSpace(s), "write-all")
}

type permissionsFinding struct {
	File    string
	Line    int
	JobName string // "" for a workflow with no jobs parsed
	Verdict string // "explicit" | "explicit-write-all" | "missing"
}

// analyzeWorkflowPermissions judges every job in u against the
// effective (job-level, falling back to workflow-level) permissions:
// block — a job inherits the workflow-level block only when it declares
// no block of its own.
func analyzeWorkflowPermissions(u workflowUnit) []permissionsFinding {
	finder := newLineFinder(u.Raw)
	workflowExplicit := u.Parsed.Permissions != nil
	workflowWriteAll := isWriteAll(u.Parsed.Permissions)

	if len(u.Parsed.Jobs) == 0 {
		if !workflowExplicit {
			return []permissionsFinding{{File: u.Label, Verdict: "missing"}}
		}
		verdict := "explicit"
		if workflowWriteAll {
			verdict = "explicit-write-all"
		}
		return []permissionsFinding{{File: u.Label, Line: finder.Find("permissions:"), Verdict: verdict}}
	}

	var out []permissionsFinding
	for _, jobName := range sortedJobNames(u.Parsed.Jobs) {
		job := u.Parsed.Jobs[jobName]
		jobExplicit := job.Permissions != nil
		effectiveExplicit := jobExplicit || workflowExplicit
		effectiveWriteAll := isWriteAll(job.Permissions) || (!jobExplicit && workflowWriteAll)

		verdict := "missing"
		line := finder.Find(jobName + ":")
		if effectiveExplicit {
			verdict = "explicit"
			if effectiveWriteAll {
				verdict = "explicit-write-all"
			}
			if jobExplicit {
				line = finder.Find("permissions:")
			}
		}
		out = append(out, permissionsFinding{File: u.Label, Line: line, JobName: jobName, Verdict: verdict})
	}
	return out
}

func permissionsFindingsToFacts(findings []permissionsFinding) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, map[string]any{"file": f.File, "line": f.Line, "job": f.JobName, "verdict": f.Verdict})
	}
	return out
}

// checkTokenPermissions implements issue #20's rubric: an explicit
// permissions: block (workflow- or job-level) is required; its absence
// means the job runs with the ambient default GITHUB_TOKEN permissions,
// which this check flags. defaultWorkflowPermission is collected purely
// as context (the repo/org setting that determines how risky an absent
// block actually is) — never as a substitute for an explicit block, per
// the issue's own wording ("absence ... flagged; ... setting collected as
// context fact").
func checkTokenPermissions(org, repo string, units []workflowUnit, defaultWorkflowPermission string, defaultWorkflowPermissionKnown bool, prov []model.Provenance) model.CheckResult {
	if len(units) == 0 {
		return notCheckableResult(checkTokenPermissionsID, org, repo, "no GitHub Actions workflow files found on the default branch", prov)
	}

	var allFindings []permissionsFinding
	for _, u := range units {
		allFindings = append(allFindings, analyzeWorkflowPermissions(u)...)
	}

	missing, writeAll := 0, 0
	for _, f := range allFindings {
		switch f.Verdict {
		case "missing":
			missing++
		case "explicit-write-all":
			writeAll++
		}
	}

	status := model.StatusVerifiedPass
	reason := "every workflow declares explicit permissions (workflow- or job-level)"
	switch {
	case missing > 0 && missing == len(allFindings):
		status = model.StatusVerifiedFail
		reason = "no workflow declares an explicit permissions: block; every job relies on the default GITHUB_TOKEN permissions"
	case missing > 0:
		status = model.StatusPartial
		reason = fmt.Sprintf("%d of %d job(s)/workflow(s) declare explicit permissions; the rest rely on the default GITHUB_TOKEN permissions", len(allFindings)-missing, len(allFindings))
	case writeAll > 0:
		status = model.StatusPartial
		reason = fmt.Sprintf("every job declares explicit permissions, but %d declare write-all rather than a scoped, least-privilege set", writeAll)
	}

	facts := map[string]any{"findings": permissionsFindingsToFacts(allFindings)}
	if defaultWorkflowPermissionKnown {
		facts["repo_default_workflow_permissions"] = defaultWorkflowPermission
	}

	return model.CheckResult{
		CheckID: checkTokenPermissionsID, Title: checkTitles[checkTokenPermissionsID], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov, Facts: facts,
	}
}

// -----------------------------------------------------------------------
// C08.actions.pull-request-target
// -----------------------------------------------------------------------

// prHeadRefPattern matches an expression referencing the PR head commit or
// branch: the full `github.event.pull_request.head.{sha,ref}` form, or
// GitHub's documented shorthand context alias `github.head_ref` (available
// on both pull_request and pull_request_target, equivalent to
// `github.event.pull_request.head.ref` for checkout purposes and commonly
// used exactly this way in practice). This still only recognizes an
// actions/checkout `with.ref` expressing the dangerous pattern — a `run:`
// step doing `git fetch`/`git checkout` of the PR head, or a forked/renamed
// checkout action, is outside what static YAML analysis without a
// dataflow engine can see; that's a real, deliberate scope limit, not
// something this pattern is meant to catch.
var prHeadRefPattern = regexp.MustCompile(`pull_request\.head\.(sha|ref)|\bhead_ref\b`)

func findCheckoutOfPRHead(u workflowUnit) (uses string, line int, found bool) {
	finder := newLineFinder(u.Raw)
	for _, jobName := range sortedJobNames(u.Parsed.Jobs) {
		job := u.Parsed.Jobs[jobName]
		for _, step := range job.Steps {
			slug, _ := splitActionRefLocal(step.Uses)
			if slug != "actions/checkout" {
				continue
			}
			ref, _ := step.With["ref"].(string)
			if prHeadRefPattern.MatchString(ref) {
				return step.Uses, finder.Find(step.Uses), true
			}
		}
	}
	return "", 0, false
}

// checkPullRequestTarget implements issue #20's rubric: pull_request_target
// combined with a checkout of the PR head commit/branch is the well-known
// "pwn request" pattern — the job runs in the base repo's context (secrets,
// a token that can be write-scoped) against attacker-controlled code. Bare
// pull_request_target usage without a detected head checkout is still
// risky by design (GitHub itself documents this), so it caps at partial
// rather than being waved through as a pass.
func checkPullRequestTarget(org, repo string, units []workflowUnit, prov []model.Provenance) model.CheckResult {
	if len(units) == 0 {
		return notCheckableResult(checkPRTargetID, org, repo, "no GitHub Actions workflow files found on the default branch", prov)
	}

	var dangerous, bare []map[string]any
	for _, u := range units {
		if !triggerNames(u.Parsed.On)["pull_request_target"] {
			continue
		}
		if uses, line, ok := findCheckoutOfPRHead(u); ok {
			dangerous = append(dangerous, map[string]any{"file": u.Label, "line": line, "uses": uses})
		} else {
			bare = append(bare, map[string]any{"file": u.Label})
		}
	}

	status := model.StatusVerifiedPass
	reason := "no workflow triggers on pull_request_target"
	switch {
	case len(dangerous) > 0:
		status = model.StatusVerifiedFail
		reason = "at least one pull_request_target workflow checks out the PR head commit/branch — this combination runs attacker-controlled code with base-repo secrets and token access"
	case len(bare) > 0:
		status = model.StatusPartial
		reason = "pull_request_target is used without a detected checkout of the PR head — still a risky trigger by design, but no confirmed exploit pattern found"
	}

	return model.CheckResult{
		CheckID: checkPRTargetID, Title: checkTitles[checkPRTargetID], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"dangerous": dangerous, "bare_usage": bare},
	}
}

// -----------------------------------------------------------------------
// C08.actions.oidc-vs-secrets
// -----------------------------------------------------------------------

func nonEmptyParam(with map[string]any, key string) bool {
	v, ok := with[key]
	if !ok {
		return false
	}
	s, isStr := v.(string)
	if !isStr {
		return true
	}
	return strings.TrimSpace(s) != ""
}

// classifyCloudLoginStep recognizes the three official cloud-login actions
// named in issue #20 and classifies each by the OIDC vs. long-lived-secret
// parameter it sees set. A static-credential parameter always wins over an
// OIDC one if both are somehow present — the presence of a long-lived
// secret is the fact this check cares about, regardless of what else is
// also configured.
func classifyCloudLoginStep(slug string, with map[string]any) (cloud, verdict string, matched bool) {
	var oidc, static bool
	switch slug {
	case "aws-actions/configure-aws-credentials":
		cloud = "aws"
		oidc = nonEmptyParam(with, "role-to-assume")
		static = nonEmptyParam(with, "aws-access-key-id") || nonEmptyParam(with, "aws-secret-access-key")
	case "azure/login":
		cloud = "azure"
		oidc = nonEmptyParam(with, "client-id") && nonEmptyParam(with, "tenant-id")
		static = nonEmptyParam(with, "creds")
	case "google-github-actions/auth":
		cloud = "gcp"
		oidc = nonEmptyParam(with, "workload_identity_provider")
		static = nonEmptyParam(with, "credentials_json")
	default:
		return "", "", false
	}
	switch {
	case static:
		return cloud, "static", true
	case oidc:
		return cloud, "oidc", true
	default:
		return cloud, "ambiguous", true
	}
}

type cloudLoginFinding struct {
	File    string
	Line    int
	Cloud   string
	Uses    string
	Verdict string
}

func cloudLoginFindingsToFacts(findings []cloudLoginFinding) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, map[string]any{"file": f.File, "line": f.Line, "cloud": f.Cloud, "uses": f.Uses, "verdict": f.Verdict})
	}
	return out
}

// checkOIDCvsSecrets implements issue #20's rubric: a deploy-ish step
// using one of the three official cloud-login actions should authenticate
// via OIDC (an ephemeral, per-run credential) rather than a long-lived
// static secret stored in the repo/org. A repo with no such step at all
// has nothing this check can evaluate — not-checkable, not a pass, since
// "no cloud deployment detected" isn't itself a security property.
func checkOIDCvsSecrets(org, repo string, units []workflowUnit, prov []model.Provenance) model.CheckResult {
	var findings []cloudLoginFinding
	for _, u := range units {
		finder := newLineFinder(u.Raw)
		for _, jobName := range sortedJobNames(u.Parsed.Jobs) {
			for _, step := range u.Parsed.Jobs[jobName].Steps {
				if step.Uses == "" {
					continue
				}
				slug, _ := splitActionRefLocal(step.Uses)
				cloud, verdict, matched := classifyCloudLoginStep(slug, step.With)
				if !matched {
					continue
				}
				findings = append(findings, cloudLoginFinding{File: u.Label, Line: finder.Find(step.Uses), Cloud: cloud, Uses: step.Uses, Verdict: verdict})
			}
		}
	}

	if len(findings) == 0 {
		return notCheckableResult(checkOIDCID, org, repo, "no cloud-deployment login action (AWS/Azure/GCP) detected in any workflow", prov)
	}

	static, ambiguous := 0, 0
	for _, f := range findings {
		switch f.Verdict {
		case "static":
			static++
		case "ambiguous":
			ambiguous++
		}
	}

	status := model.StatusVerifiedPass
	reason := "every detected cloud-deployment login uses OIDC, not long-lived static credentials"
	switch {
	case static > 0:
		status = model.StatusVerifiedFail
		reason = fmt.Sprintf("%d cloud-deployment login step(s) use long-lived static credentials instead of OIDC", static)
	case ambiguous > 0:
		status = model.StatusPartial
		reason = fmt.Sprintf("%d cloud-deployment login step(s) have neither a recognized OIDC parameter nor a recognized static-credential parameter set", ambiguous)
	}

	return model.CheckResult{
		CheckID: checkOIDCID, Title: checkTitles[checkOIDCID], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"logins": cloudLoginFindingsToFacts(findings)},
	}
}

// -----------------------------------------------------------------------
// C08.actions.self-hosted
// -----------------------------------------------------------------------

func runsOnSelfHosted(runsOn any) bool {
	switch v := runsOn.(type) {
	case string:
		return v == "self-hosted"
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == "self-hosted" {
				return true
			}
		}
	}
	return false
}

// checkSelfHosted implements issue #20's rubric: self-hosted runner usage
// is only flagged (capped at partial) on a public repository, where any
// external contributor's pull request is a potential path to the runner —
// on a private repo, that specific attack vector doesn't apply, so usage
// there is recorded as a fact but doesn't fail the check.
func checkSelfHosted(org, repo string, units []workflowUnit, private bool, prov []model.Provenance) model.CheckResult {
	if len(units) == 0 {
		return notCheckableResult(checkSelfHostedID, org, repo, "no GitHub Actions workflow files found on the default branch", prov)
	}

	var findings []map[string]any
	for _, u := range units {
		finder := newLineFinder(u.Raw)
		for _, jobName := range sortedJobNames(u.Parsed.Jobs) {
			job := u.Parsed.Jobs[jobName]
			if !runsOnSelfHosted(job.RunsOn) {
				continue
			}
			findings = append(findings, map[string]any{"file": u.Label, "job": jobName, "line": finder.Find(jobName + ":")})
		}
	}

	status := model.StatusVerifiedPass
	reason := "no self-hosted runner usage detected"
	switch {
	case len(findings) > 0 && !private:
		status = model.StatusPartial
		reason = "self-hosted runner(s) are used on a public repository — an external contributor's pull request is a potential path to them"
	case len(findings) > 0:
		reason = "self-hosted runner(s) are used, but the repository is private — the public-fork attack vector this check flags does not apply"
	}

	return model.CheckResult{
		CheckID: checkSelfHostedID, Title: checkTitles[checkSelfHostedID], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"self_hosted_jobs": findings, "repo_private": private},
	}
}
