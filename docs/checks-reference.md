# Checks Reference

> **GENERATED — do not hand-edit.** Regenerate with `attestward checks docs` from
> `mappings/*.yaml` and each collector's registered check metadata. A pull request that
> changes mapping or registry data without regenerating this file fails CI's drift check
> (`attestward checks docs --check`, which renders in memory and compares against this file
> without writing).

Source data:

- SSDF mapping: NIST SP 800-218, mapping version `1.13.0`, retrieved 2026-07-13 — [https://csrc.nist.gov/pubs/sp/800/218/final](https://csrc.nist.gov/pubs/sp/800/218/final)
- CISA SSDA form mapping: mapping version `1.0.0`, retrieved 2026-07-13 — [https://www.cisa.gov/sites/default/files/2024-03/Self-Attestation-Common-Form-03082024-FINAL.pdf](https://www.cisa.gov/sites/default/files/2024-03/Self-Attestation-Common-Form-03082024-FINAL.pdf)

No wall-clock generation timestamp is recorded here on purpose: this file is regenerated
byte-for-byte identical from unchanged input, which is what lets CI's drift check compare it
against a plain diff rather than tolerate spurious churn.

Each check's "SSDF task(s)" cites the task ID and quotes the task's verbatim text below its
own section, plus the source link above — that's the cross-link to SP 800-218 this file
provides. It's deliberately not a deep link into a specific SP 800-218 page or section: the
publication is a PDF with no addressable per-task anchors, so a fabricated page/section
number would be a citation this tool can't actually stand behind (see this repo's own rule
against inventing SSDF citations).

## Contents

- [C01.org-security](#c01org-security)
- [C02.repo-protection](#c02repo-protection)
- [C03.env-separation](#c03env-separation)
- [C04.secrets-hygiene](#c04secrets-hygiene)
- [C05.sast-history](#c05sast-history)
- [C06.sca-history](#c06sca-history)
- [C07.provenance](#c07provenance)
- [C08.actions-security](#c08actions-security)
- [C09.audit-logging](#c09audit-logging)
- [C10.vdp](#c10vdp)
- [Self-Attestation Questions](#self-attestation-questions)

---

## C01.org-security

### `C01.org.2fa-required`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — Org requires two-factor authentication

- **Token permission:** vso.graph (Graph Users - List)
- **Fixture:** `internal/collect/azuredevops/orgsecurity/orgsecurity_test.go`
- **API endpoint(s):** `GET vssps.dev.azure.com/{org}/_apis/graph/users`

**Status rubric:**

- **verified-fail:** at least one org identity returned by the Graph Users list (subjectKind=="user") has origin=="msa" — a Microsoft/personal account, which sits entirely outside any Microsoft Entra tenant's MFA/Conditional Access enforcement, so 2FA cannot be assumed for that member at all (the exact count is recorded in Facts; member names/identities are deliberately never recorded)
- **partial:** no org identity has origin=="msa", at least one has origin=="aad", and none have any other unrecognized origin among subjectKind=="user" entries (origin=="vsts" service identities are excluded from this count entirely, not treated as unrecognized — see Facts.vsts_service_identity_count) — every human identity this tool could classify authenticates via Microsoft Entra ID. This states only what was verified, not full MFA enforcement: that lives in Microsoft Entra Conditional Access, a surface no vso.* PAT scope reaches, so this cannot exceed partial (epic #34 open decision 3)
- **not-checkable:** the Graph Users list (GET vssps.dev.azure.com/{org}/_apis/graph/users) couldn't be read (403/404/other API error); or it read successfully but at least one subjectKind=="user" identity has an origin this tool doesn't classify as aad or msa (e.g. GitHub-linked "ghb" accounts — see Facts.other_origin_user_count), so it can't assert the org is uniformly Entra-backed; or zero identities with a recognized human origin were found at all, leaving nothing to evaluate

**Remediation:** Azure DevOps has no direct "require 2FA" organization toggle. MFA enforcement is a Microsoft Entra ID Conditional Access policy applied to the tenant backing this org: in the Microsoft Entra admin center, create (or verify) a Conditional Access policy requiring MFA for all users, and migrate any Microsoft Account (MSA, origin=msa) members to Entra-backed (aad) identities — Organization Settings -> Users, or by moving the org under a Microsoft Entra tenant if it isn't backed by one already. If this check instead reports not-checkable because members have an origin this tool doesn't recognize (e.g. GitHub-linked "ghb" accounts), the same migration to an Entra-backed (aad) identity removes the ambiguity, independent of whatever this tool later decides that origin should count as.

#### github — Org requires two-factor authentication

- **Token permission:** read:org
- **Fixture:** `internal/collect/github/orgsecurity/orgsecurity_test.go`
- **API endpoint(s):** `GET /orgs/{org}`

**Status rubric:**

- **verified-fail:** the org's `two_factor_requirement_enabled` field is false
- **not-checkable:** the org couldn't be read (403/404/other API error), or its API response omitted `two_factor_requirement_enabled`
- **verified-pass:** the org's `two_factor_requirement_enabled` field is true

**Remediation:** Org Settings -> Authentication security -> check "Require two-factor authentication for everyone in the [org] organization". Any member without 2FA enabled will be removed from the org when this is turned on, so resolve C01.org.members-without-2fa first.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

### `C01.org.default-repo-permission`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PS.1.1` (practice `PS.1`: Protect All Forms of Code from Unauthorized Access and Tampering)
- **CISA form cluster(s):** 2, 4

#### azuredevops — Default repository permission for members

- **Token permission:** none — default repository permission has no vso.* scope; ADO exposes no org-level field for it at all (see this check's Rubric)
- **Fixture:** `internal/collect/azuredevops/orgsecurity/orgsecurity_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — Azure DevOps has no single org-level default-repository-permission field; repository access is governed per security-group/ACL (_apis/accesscontrollists), out of scope for v0.2 (issue #34's non-goals) — there is no API this tool calls to determine a default permission

**Remediation:** Not remediable via this tool: Azure DevOps grants default repository access through security groups and ACLs (Project Settings -> Permissions, and per-repository Security tabs), not a single org-level field. Review the "Project Collection Valid Users" / per-project "Contributors" group's default permissions directly in the ADO UI.

#### github — Default repository permission for members

- **Token permission:** read:org
- **Fixture:** `internal/collect/github/orgsecurity/orgsecurity_test.go`
- **API endpoint(s):** `GET /orgs/{org}`

**Status rubric:**

- **verified-fail:** the org's `default_repository_permission` field is anything other than "read" or "none" (i.e. "write" or "admin" today, per GitHub's documented enum for this field — the check itself only tests for the two passing values, not an exhaustive fail list)
- **not-checkable:** the org couldn't be read (403/404/other API error), or its API response omitted `default_repository_permission`
- **verified-pass:** the org's `default_repository_permission` field is "read" or "none"

**Remediation:** Org Settings -> Member privileges -> Base permissions -> set to "Read" or "No permission" so members don't get write access to every repo by default.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PS.1.1`:** Store all forms of code – including source code, executable code, and configuration-as-code – based on the principle of least privilege so that only authorized personnel, tools, services, etc. have access.

---

### `C01.org.members-can-create-public`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PS.1.1` (practice `PS.1`: Protect All Forms of Code from Unauthorized Access and Tampering)
- **CISA form cluster(s):** 2, 4

#### azuredevops — Whether members can create public projects

- **Token permission:** vso.project (Projects - List)
- **Fixture:** `internal/collect/azuredevops/orgsecurity/orgsecurity_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/_apis/projects`

**Status rubric:**

- **verified-fail:** at least one project returned by GET dev.azure.com/{org}/_apis/projects has visibility=="public" (Facts records which project(s) and how many)
- **not-checkable:** either the org's project list couldn't be read (403/404/other API error), or it read successfully but zero projects are currently public — a policy that disallows public projects and a policy that allows it but is simply unused look identical from this endpoint alone (the org-policy setting itself lives behind an undocumented API this tool does not call), so a genuine pass can't be told apart from an unused allowance

**Remediation:** Organization Settings -> Policies -> turn off "Allow public projects" (or, per project, set visibility to Private under Project Settings -> Overview) so members can't create or keep a publicly visible project without an explicit, separately reviewed change.

#### github — Whether members can create public repositories

- **Token permission:** read:org
- **Fixture:** `internal/collect/github/orgsecurity/orgsecurity_test.go`
- **API endpoint(s):** `GET /orgs/{org}`

**Status rubric:**

- **verified-fail:** the org's `members_can_create_public_repositories` field is true
- **not-checkable:** the org couldn't be read (403/404/other API error), or its API response omitted `members_can_create_public_repositories`
- **verified-pass:** the org's `members_can_create_public_repositories` field is false

**Remediation:** Org Settings -> Member privileges -> Repository creation -> uncheck "Public" so members can't create public repositories without an explicit visibility change reviewed separately.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PS.1.1`:** Store all forms of code – including source code, executable code, and configuration-as-code – based on the principle of least privilege so that only authorized personnel, tools, services, etc. have access.

---

### `C01.org.members-without-2fa`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — Count of members without two-factor authentication

- **Token permission:** none — per-user MFA registration state has no vso.* scope at all; it lives in Microsoft Entra ID / Microsoft Graph, a separate service with its own (non-ADO) auth model
- **Fixture:** `internal/collect/azuredevops/orgsecurity/orgsecurity_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — per-user two-factor/MFA registration state lives in Microsoft Entra ID / Microsoft Graph, a different API and service than anything a vso.* PAT scope reaches; no Azure DevOps endpoint exposes it. Facts carries msa_user_count as context only, borrowed from the same Graph Users call C01.org.2fa-required makes (see that check's own Endpoints) when that call succeeded — it is not evidence this check itself gathered

**Remediation:** Not remediable via this tool: per-user MFA registration state is a Microsoft Entra ID / Microsoft Graph concept, not exposed through any Azure DevOps API or vso.* PAT scope. Review MFA registration in the Microsoft Entra admin center (Users -> Per-user MFA, or the Conditional Access sign-in logs) instead.

#### github — Count of members without two-factor authentication

- **Token permission:** read:org
- **Fixture:** `internal/collect/github/orgsecurity/orgsecurity_test.go`
- **API endpoint(s):** `GET /orgs/{org}/members?filter=2fa_disabled`

**Status rubric:**

- **verified-fail:** GET /orgs/{org}/members?filter=2fa_disabled returned one or more members (the count is recorded in Facts; member names/logins are deliberately never recorded — see the collector's own doc comment)
- **not-checkable:** the members list couldn't be read (403/404/other API error)
- **verified-pass:** GET /orgs/{org}/members?filter=2fa_disabled returned zero members

**Remediation:** Org People page -> filter by "Two-factor authentication: Disabled" -> have each flagged member enable 2FA under their own Settings -> Password and authentication, or remove/suspend members who won't comply. Then enable C01.org.2fa-required so new members can't rejoin without it.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

## C02.repo-protection

### `C02.branch.admin-enforced`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PS.1.1` (practice `PS.1`: Protect All Forms of Code from Unauthorized Access and Tampering)
- **CISA form cluster(s):** 2, 4

#### azuredevops — Default branch protections apply to admins (no unconditional bypass permission)

- **Token permission:** vso.security_manage — same scope, and the same no-read-only-variant story, as C02.branch.force-push-blocked (see this check's Rubric)
- **Fixture:** `internal/collect/azuredevops/repoprotection/repoprotection_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — Azure DevOps' bypass model here is the "Bypass policies when completing pull requests" and "Bypass policies when pushing" Git repository security permissions (ACLs), not policy configuration data, out of scope for v0.2 (issue #34's non-goals); a future ACL-reading story would read these permission bits directly

**Remediation:** Project Settings -> Repositories -> [repo] -> Security -> for every group/user that shouldn't be exempt (including admins), set both "Bypass policies when completing pull requests" and "Bypass policies when pushing" to Deny (not just unset/inherited) at the repository or branch level.

#### github — Default branch protections apply to admins (no unconditional bypass actor)

- **Token permission:** repo (classic) or Administration: read-only (fine-grained)
- **Fixture:** `internal/collect/github/repoprotection/repoprotection_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/branches/{branch}/protection`, `GET /repos/{owner}/{repo}/rules/branches/{branch}`, `GET /repos/{owner}/{repo}/rulesets/{ruleset_id}?includes_parents=true`

**Status rubric:**

- **verified-fail:** no regime fully enforces admins — either nothing contributes admin-relevant protection at all, or legacy protection exists but exempts admins (`enforce_admins` is false) even though a ruleset separately would bind them — and no unconditional ("always"-mode) bypass actor is present either; any conditional bypass actor(s) present don't change this outcome, since admins already aren't bound by every contributing regime
- **partial:** either (a) admins are bound by every contributing regime, but at least one conditional (non-"always"-mode, e.g. "pull_request"-only) bypass actor exists on a relevant ruleset, or (b) an unconditional ("always"-mode) bypass actor exists on a relevant ruleset — this alone caps the check at partial regardless of what legacy separately enforces
- **not-checkable:** the repo read failed, the repo has no default branch, the legacy branch-protection read failed with anything other than a 404 (a 404 there just means "no legacy protection configured", not an error), or the rules-for-branch read failed (403/404/other API error), or the ruleset bypass-actor lookup itself failed (GET .../rulesets/{ruleset_id})
- **verified-pass:** every regime that contributes any protection also enforces it against admins (legacy's `enforce_admins` is true, if legacy protection exists at all; any ruleset contributing a relevant rule has zero bypass actors) — and no bypass actor exists on any ruleset contributing a relevant rule (only rulesets behind the pull-request/status-check/force-push/deletion rules this collector tracks are inspected; a bypass actor on an unrelated ruleset, e.g. one that only sets a commit-message pattern, doesn't affect this check)

**Remediation:** For a ruleset, set Enforcement status to "Active" (not "Evaluate") and remove every bypass actor entirely — even one scoped to "Pull request only" caps this check at partial, not a full pass. For legacy branch protection, check "Do not allow bypassing the above settings" (Include administrators). Where both legacy protection and a ruleset apply to the same branch, both must independently bind admins for this check to pass.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PS.1.1`:** Store all forms of code – including source code, executable code, and configuration-as-code – based on the principle of least privilege so that only authorized personnel, tools, services, etc. have access.

---

### `C02.branch.deletion-blocked`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PS.1.1` (practice `PS.1`: Protect All Forms of Code from Unauthorized Access and Tampering)
- **CISA form cluster(s):** 2, 4

#### azuredevops — Default branch blocks branch deletion

- **Token permission:** vso.security_manage — same scope, and the same no-read-only-variant story, as C02.branch.force-push-blocked (see this check's Rubric)
- **Fixture:** `internal/collect/azuredevops/repoprotection/repoprotection_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — Azure DevOps has no permission distinct from "Force push (rewrite history, delete branches and tags)" for deleting a branch (confirmed against Microsoft's own Git branch-permissions documentation, which states this one permission is also required to delete a branch) — an ACL, not policy configuration data, out of scope for v0.2 (issue #34's non-goals)

**Remediation:** Azure DevOps has no permission distinct from "Force push (rewrite history, delete branches and tags)" for deleting a branch specifically — the same remediation as C02.branch.force-push-blocked (set that permission to Deny) closes this gap too.

#### github — Default branch blocks branch deletion

- **Token permission:** repo (classic) or Administration: read-only (fine-grained)
- **Fixture:** `internal/collect/github/repoprotection/repoprotection_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/branches/{branch}/protection`, `GET /repos/{owner}/{repo}/rules/branches/{branch}`

**Status rubric:**

- **verified-fail:** branch deletion is allowed by both regimes
- **not-checkable:** the repo read failed, the repo has no default branch, the legacy branch-protection read failed with anything other than a 404 (a 404 there just means "no legacy protection configured", not an error), or the rules-for-branch read failed (403/404/other API error)
- **verified-pass:** legacy protection disables `allow_deletions` (or leaves the field unset), or a ruleset has an active deletion rule

**Remediation:** In a ruleset, enable "Restrict deletions"; in legacy branch protection, leave "Allow deletions" unchecked.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PS.1.1`:** Store all forms of code – including source code, executable code, and configuration-as-code – based on the principle of least privilege so that only authorized personnel, tools, services, etc. have access.

---

### `C02.branch.force-push-blocked`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PS.1.1` (practice `PS.1`: Protect All Forms of Code from Unauthorized Access and Tampering)
- **CISA form cluster(s):** 2, 4

#### azuredevops — Default branch blocks force pushes

- **Token permission:** vso.security_manage — Azure DevOps has no read-only PAT scope for security permissions/ACLs at all (verified against Microsoft's own OAuth scopes reference: the Security category has exactly one scope, and it's read+write+manage); reading this permission at all would require a high-privilege scope in tension with PAT minimality, which is arguably the more honest story than a missing read-only variant this tool simply chose not to use (see this check's Rubric)
- **Fixture:** `internal/collect/azuredevops/repoprotection/repoprotection_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — Azure DevOps controls force pushes via the "Force push (rewrite history, delete branches and tags)" Git repository security permission (an ACL, not policy configuration data), out of scope for v0.2 (issue #34's non-goals); a future ACL-reading story would read this permission bit directly

**Remediation:** Project Settings -> Repositories -> [repo] -> Security (or the branch's own Security tab) -> for every group that shouldn't have it, set "Force push (rewrite history, delete branches and tags)" to Deny (not just unset/inherited).

#### github — Default branch blocks force pushes

- **Token permission:** repo (classic) or Administration: read-only (fine-grained)
- **Fixture:** `internal/collect/github/repoprotection/repoprotection_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/branches/{branch}/protection`, `GET /repos/{owner}/{repo}/rules/branches/{branch}`

**Status rubric:**

- **verified-fail:** force pushes are allowed by both regimes
- **not-checkable:** the repo read failed, the repo has no default branch, the legacy branch-protection read failed with anything other than a 404 (a 404 there just means "no legacy protection configured", not an error), or the rules-for-branch read failed (403/404/other API error)
- **verified-pass:** legacy protection disables `allow_force_pushes` (or leaves the field unset, which GitHub defaults to disabled), or a ruleset has an active non-fast-forward rule

**Remediation:** In a ruleset, enable "Block force pushes"; in legacy branch protection, leave "Allow force pushes" unchecked.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PS.1.1`:** Store all forms of code – including source code, executable code, and configuration-as-code – based on the principle of least privilege so that only authorized personnel, tools, services, etc. have access.

---

### `C02.branch.protection-exists`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PS.1.1` (practice `PS.1`: Protect All Forms of Code from Unauthorized Access and Tampering)
- **CISA form cluster(s):** 2, 4

#### azuredevops — Default branch has an enabled branch policy

- **Token permission:** vso.code (Repositories - List, Policy Configurations - List)
- **Fixture:** `internal/collect/azuredevops/repoprotection/repoprotection_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/git/repositories`, `GET dev.azure.com/{org}/{project}/_apis/policy/configurations`

**Status rubric:**

- **verified-fail:** no enabled, non-deleted policy configuration of a tracked type is scoped to this repo's default branch
- **not-checkable:** the project's repositories couldn't be read (403/404/other API error), the named repository wasn't found in the project, the repository has no default branch (an empty repository), or the project's policy configurations couldn't be read (403/404/other API error)
- **verified-pass:** at least one enabled, non-deleted policy configuration of a tracked type (Minimum approval count, fa4e907d-c16b-4a4c-9dfa-4906e5d171dd; or Build, 0609b952-1397-4640-95ec-e00a01b2c241) is scoped, via settings.scope[], to this repo's default branch — a project-wide entry (repositoryId==null) or a repo-specific entry (repositoryId equal) whose refName matches exactly, as a prefix, or via matchKind=="DefaultBranch" (which always matches a repo's own default branch by definition — the shape Azure DevOps's project-level "Protect the default branch of each repository" cross-repository policy emits)

**Remediation:** Project Settings -> Repositories -> [repo] -> Policies (or Repos -> Branches -> ... -> Branch policies) -> add a branch policy (minimum number of reviewers and/or build validation) scoped to the default branch.

#### github — Default branch has protection (legacy branch protection or a ruleset)

- **Token permission:** repo (classic) or Administration: read-only (fine-grained)
- **Fixture:** `internal/collect/github/repoprotection/repoprotection_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/branches/{branch}/protection`, `GET /repos/{owner}/{repo}/rules/branches/{branch}`

**Status rubric:**

- **verified-fail:** default branch has no legacy branch protection and no ruleset applies to it
- **not-checkable:** the repo read failed, the repo has no default branch, the legacy branch-protection read failed with anything other than a 404 (a 404 there just means "no legacy protection configured", not an error), or the rules-for-branch read failed (403/404/other API error)
- **verified-pass:** legacy branch protection is configured on the default branch, or at least one ruleset rule applies to it (`effectiveProtection.exists`, via GetBranchProtection succeeding or GetRulesForBranch returning at least one active rule this collector tracks)

**Remediation:** Repo Settings -> Rules -> Rulesets (or the legacy Settings -> Branches -> Branch protection rules) -> add a rule targeting the default branch.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PS.1.1`:** Store all forms of code – including source code, executable code, and configuration-as-code – based on the principle of least privilege so that only authorized personnel, tools, services, etc. have access.

---

### `C02.branch.required-reviews`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PS.1.1` (practice `PS.1`: Protect All Forms of Code from Unauthorized Access and Tampering)
- **CISA form cluster(s):** 2, 4

#### azuredevops — Default branch requires at least one approving review before merge

- **Token permission:** vso.code (Repositories - List, Policy Configurations - List)
- **Fixture:** `internal/collect/azuredevops/repoprotection/repoprotection_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/git/repositories`, `GET dev.azure.com/{org}/{project}/_apis/policy/configurations`

**Status rubric:**

- **verified-fail:** no enabled, non-deleted Minimum approval count policy scoped to the default branch requires >=1 approver
- **partial:** at least one matching Minimum approval count policy requires >=1 approver, but no single matching policy is both blocking and free of creatorVoteCounts: either every blocking matching policy has creatorVoteCounts==true (the PR author's own vote counts toward its own requirement), or no matching policy is blocking at all (isBlocking==false everywhere, so the requirement can be overridden at PR completion) — never both framed as "overridable" when a blocking policy exists, since a blocking policy's own requirement can't be overridden regardless of a weaker sibling
- **not-checkable:** the project's repositories couldn't be read (403/404/other API error), the named repository wasn't found in the project, the repository has no default branch (an empty repository), or the project's policy configurations couldn't be read (403/404/other API error)
- **verified-pass:** at least one matching, enabled, non-deleted Minimum approval count policy (fa4e907d-c16b-4a4c-9dfa-4906e5d171dd) scoped to the default branch individually has minimumApproverCount >= 1, isBlocking==true, and creatorVoteCounts==false — Azure DevOps enforces every matching policy simultaneously, so one policy meeting the full bar is a genuine, unbypassable requirement even if a separate, weaker matching policy also applies (the same either-regime-provides-it convention the GitHub twin's effective-protection merge uses)

**Remediation:** In that branch policy blade, enable "Require a minimum number of reviewers", set it to at least 1, set the policy to Required (blocking, not Optional), and leave "Allow requesters to approve their own changes" (creatorVoteCounts) unchecked.

#### github — Default branch requires at least one approving review before merge

- **Token permission:** repo (classic) or Administration: read-only (fine-grained)
- **Fixture:** `internal/collect/github/repoprotection/repoprotection_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/branches/{branch}/protection`, `GET /repos/{owner}/{repo}/rules/branches/{branch}`

**Status rubric:**

- **verified-fail:** neither legacy protection nor any ruleset requires an approving review
- **partial:** a review is required (as above), but legacy branch protection also names at least one specific user, team, or app in `bypass_pull_request_allowances` who can skip the review requirement entirely — a ruleset's own bypass actors have no separate effect here (bypassing a ruleset's rule already bypasses its review requirement, and that's captured by C02.branch.admin-enforced instead)
- **not-checkable:** the repo read failed, the repo has no default branch, the legacy branch-protection read failed with anything other than a 404 (a 404 there just means "no legacy protection configured", not an error), or the rules-for-branch read failed (403/404/other API error)
- **verified-pass:** legacy protection's `required_approving_review_count` is >= 1, or a ruleset's pull-request rule sets `required_approving_review_count` >= 1 (whichever regime requires more reviews sets the reported count), and legacy protection names no `bypass_pull_request_allowances`

**Remediation:** In that ruleset/protection rule, enable "Require a pull request before merging" with at least 1 required approving review, and leave legacy branch protection's "Allow specified actors to bypass required pull requests" empty — or remove any users/teams/apps already listed there.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PS.1.1`:** Store all forms of code – including source code, executable code, and configuration-as-code – based on the principle of least privilege so that only authorized personnel, tools, services, etc. have access.

---

### `C02.branch.required-status-checks`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PS.1.1` (practice `PS.1`: Protect All Forms of Code from Unauthorized Access and Tampering)
- **CISA form cluster(s):** 2, 4

#### azuredevops — Default branch requires build validation before merge

- **Token permission:** vso.code (Repositories - List, Policy Configurations - List)
- **Fixture:** `internal/collect/azuredevops/repoprotection/repoprotection_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/git/repositories`, `GET dev.azure.com/{org}/{project}/_apis/policy/configurations`

**Status rubric:**

- **verified-fail:** no enabled, non-deleted Build policy is scoped to the default branch
- **partial:** at least one matching Build policy is scoped to the default branch, but every matching Build policy is non-blocking (isBlocking==false) — a failing or missing build does not block merge for any of them
- **not-checkable:** the project's repositories couldn't be read (403/404/other API error), the named repository wasn't found in the project, the repository has no default branch (an empty repository), or the project's policy configurations couldn't be read (403/404/other API error)
- **verified-pass:** at least one matching, enabled, non-deleted Build policy (0609b952-1397-4640-95ec-e00a01b2c241) scoped to the default branch is individually blocking (isBlocking==true) — Azure DevOps enforces every matching policy simultaneously, so one blocking policy is a genuine requirement even if a separate, non-blocking matching policy also applies

**Remediation:** In that branch policy blade, add a "Build validation" policy pointing at the build pipeline that must pass, and set it to Required (blocking), not Optional.

#### github — Default branch requires status checks before merge

- **Token permission:** repo (classic) or Administration: read-only (fine-grained)
- **Fixture:** `internal/collect/github/repoprotection/repoprotection_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/branches/{branch}/protection`, `GET /repos/{owner}/{repo}/rules/branches/{branch}`

**Status rubric:**

- **verified-fail:** neither regime names any required status check
- **not-checkable:** the repo read failed, the repo has no default branch, the legacy branch-protection read failed with anything other than a 404 (a 404 there just means "no legacy protection configured", not an error), or the rules-for-branch read failed (403/404/other API error)
- **verified-pass:** legacy protection or a ruleset names at least one required status check

**Remediation:** In that ruleset/protection rule, enable "Require status checks to pass before merging" and select the CI checks that must pass.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PS.1.1`:** Store all forms of code – including source code, executable code, and configuration-as-code – based on the principle of least privilege so that only authorized personnel, tools, services, etc. have access.

---

## C03.env-separation

### `C03.env.branch-policy`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — Production-like environments restrict which branches can deploy

- **Token permission:** vso.environment_manage (Environments - List, see C03.env.exists' own caveat) plus vso.build (Check Configurations - List)
- **Fixture:** `internal/collect/azuredevops/envseparation/envseparation_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/distributedtask/environments`, `GET dev.azure.com/{org}/{project}/_apis/pipelines/checks/configurations?resourceType=environment&resourceId={envId}&$expand=settings`

**Status rubric:**

- **verified-fail:** at least one production-like environment has no non-disabled Task Check configuration at all — a confident, definitive absence of any branch restriction
- **partial:** one or more environments exist, but none match the production-like naming heuristic (`prod`* prefix, case-insensitive) — a human reviewer should judge whether one of them is actually production before this check can evaluate anything. Separately — when every production-like environment has at least one Task Check, but at least one Task Check's settings couldn't be confidently interpreted per the verified-pass entry's [fixture-verify] caveat — the conservative fallback issue #151 specifies: "a task check exists but its branch-control settings could not be interpreted"
- **not-checkable:** the project's environments list couldn't be read (403/404/other API error), or the project has zero environments configured at all, or a production-like environment's check configurations couldn't be read (403/404/other API error)
- **verified-pass:** every production-like environment has a non-disabled Task Check configuration (type id fe1de3ee-a436-41b4-bb20-f6eb4cb879a7) whose $expand=settings payload could be confidently interpreted as a real, non-wildcard allowed-branches restriction — [fixture-verify]: this settings schema is undocumented by Microsoft, so the interpretation is a corroborated-but-unconfirmed best guess (see taskCheckSettingsRaw's own doc comment) pending a recorded real response

**Remediation:** Open the production-like environment -> Approvals and checks -> Add check -> Branch control -> set "Allowed branches" to a real restrictive list (e.g. refs/heads/main), not the task's "*" (no restriction) default.

#### github — Production-like environments restrict which branches/tags can deploy

- **Token permission:** repo (classic) or Actions: read-only (fine-grained)
- **Fixture:** `internal/collect/github/envseparation/envseparation_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/environments`

**Status rubric:**

- **verified-fail:** at least one production-like environment allows deployment from any branch (no `deployment_branch_policy` set, or one with both `protected_branches` and `custom_branch_policies` false)
- **partial:** one or more environments exist, but none match the production-like naming heuristic (`prod`* prefix, case-insensitive) — a human reviewer should judge whether one of them is actually production before this check can evaluate anything
- **not-checkable:** the environments list couldn't be read (403/plan-gated/other API error), or the repo has zero environments configured at all
- **verified-pass:** every production-like environment's `deployment_branch_policy` restricts deployment to protected branches, a custom branch/tag allowlist, or both

**Remediation:** Open the production-like environment -> Settings -> Deployment branches and tags -> change from "No restriction" to "Protected branches only" or a "Selected branches and tags" allowlist.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

### `C03.env.exists`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — A production-like environment exists

- **Token permission:** vso.environment_manage — Environments - List has no documented read-only PAT scope at all; the only documented scope for this read endpoint is manage-level
- **Fixture:** `internal/collect/azuredevops/envseparation/envseparation_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/distributedtask/environments`

**Status rubric:**

- **partial:** one or more environments exist, but none match the production-like naming heuristic (`prod`* prefix, case-insensitive) — a human reviewer should judge whether one of them is actually production before this check can evaluate anything
- **not-checkable:** the project's environments list couldn't be read (403/404/other API error), or the project has zero environments configured at all
- **verified-pass:** at least one environment's name matches the production-like heuristic (`prod`* prefix, case-insensitive)

**Remediation:** Pipelines -> Environments -> New environment -> name it "production" (or any prod*/production variant — this check's name heuristic is case-insensitive) so deployments can be routed through it.

#### github — A production-like environment exists

- **Token permission:** repo (classic) or Actions: read-only (fine-grained)
- **Fixture:** `internal/collect/github/envseparation/envseparation_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/environments`

**Status rubric:**

- **partial:** one or more environments exist, but none match the production-like naming heuristic (`prod`* prefix, case-insensitive) — a human reviewer should judge whether one of them is actually production before this check can evaluate anything
- **not-checkable:** the environments list couldn't be read (403/plan-gated/other API error), or the repo has zero environments configured at all
- **verified-pass:** at least one environment's name matches the production-like heuristic (`prod`* prefix, case-insensitive)

**Remediation:** Repo Settings -> Environments -> New environment -> name it "production" (or any prod*/production variant — this check's name heuristic is case-insensitive) so deployments can be routed through it.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

### `C03.env.protection-rules`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — Production-like environments have at least one protection check

- **Token permission:** vso.environment_manage (Environments - List, see C03.env.exists' own caveat) plus vso.build (Check Configurations - List)
- **Fixture:** `internal/collect/azuredevops/envseparation/envseparation_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/distributedtask/environments`, `GET dev.azure.com/{org}/{project}/_apis/pipelines/checks/configurations?resourceType=environment&resourceId={envId}&$expand=settings`

**Status rubric:**

- **verified-fail:** at least one production-like environment has zero non-disabled check configurations
- **partial:** one or more environments exist, but none match the production-like naming heuristic (`prod`* prefix, case-insensitive) — a human reviewer should judge whether one of them is actually production before this check can evaluate anything
- **not-checkable:** the project's environments list couldn't be read (403/404/other API error), or the project has zero environments configured at all, or a production-like environment's check configurations couldn't be read (403/404/other API error)
- **verified-pass:** every production-like environment has at least one non-disabled check configuration of any type (GET .../_apis/pipelines/checks/configurations?resourceType=environment&resourceId={id} returns at least one entry with isDisabled!=true)

**Remediation:** Open the production-like environment -> "..." (kebab menu) -> Approvals and checks -> Add check -> configure at least one check (Approval, Branch control, Business hours, Invoke Azure Function, etc.).

#### github — Production-like environments have at least one protection rule

- **Token permission:** repo (classic) or Actions: read-only (fine-grained)
- **Fixture:** `internal/collect/github/envseparation/envseparation_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/environments`

**Status rubric:**

- **verified-fail:** at least one production-like environment has zero protection rules
- **partial:** one or more environments exist, but none match the production-like naming heuristic (`prod`* prefix, case-insensitive) — a human reviewer should judge whether one of them is actually production before this check can evaluate anything
- **not-checkable:** the environments list couldn't be read (403/plan-gated/other API error), or the repo has zero environments configured at all
- **verified-pass:** every production-like environment has at least one protection rule (any type — the environment's `ProtectionRules` list is non-empty)

**Remediation:** Open the production-like environment -> Settings -> Deployment protection rules -> add at least one rule (required reviewers or a wait timer).

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

### `C03.env.required-reviewers`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — Production-like environments require reviewer approval before deployment

- **Token permission:** vso.environment_manage (Environments - List, see C03.env.exists' own caveat) plus vso.build (Check Configurations - List)
- **Fixture:** `internal/collect/azuredevops/envseparation/envseparation_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/distributedtask/environments`, `GET dev.azure.com/{org}/{project}/_apis/pipelines/checks/configurations?resourceType=environment&resourceId={envId}&$expand=settings`

**Status rubric:**

- **verified-fail:** at least one production-like environment lacks a non-disabled Approval check configuration
- **partial:** one or more environments exist, but none match the production-like naming heuristic (`prod`* prefix, case-insensitive) — a human reviewer should judge whether one of them is actually production before this check can evaluate anything
- **not-checkable:** the project's environments list couldn't be read (403/404/other API error), or the project has zero environments configured at all, or a production-like environment's check configurations couldn't be read (403/404/other API error)
- **verified-pass:** every production-like environment has a non-disabled Approval check configuration (type id 8c6f20a7-a545-4486-9777-f762fafe0d4d)

**Remediation:** Open the production-like environment -> Approvals and checks -> Add check -> Approvals -> add at least one approver.

#### github — Production-like environments require reviewer approval before deployment

- **Token permission:** repo (classic) or Actions: read-only (fine-grained)
- **Fixture:** `internal/collect/github/envseparation/envseparation_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/environments`

**Status rubric:**

- **verified-fail:** at least one production-like environment lacks a `required_reviewers` rule, or has one configured with zero reviewers
- **partial:** one or more environments exist, but none match the production-like naming heuristic (`prod`* prefix, case-insensitive) — a human reviewer should judge whether one of them is actually production before this check can evaluate anything
- **not-checkable:** the environments list couldn't be read (403/plan-gated/other API error), or the repo has zero environments configured at all
- **verified-pass:** every production-like environment has a `required_reviewers`-type protection rule with at least one reviewer configured

**Remediation:** Open the production-like environment -> Settings -> Deployment protection rules -> add "Required reviewers" and select who must approve a deployment.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

## C04.secrets-hygiene

### `C04.deps.dependabot-alerts`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PW.4.4` (practice `PW.4`: Reuse Existing, Well-Secured Software When Feasible Instead of Duplicating Functionality)
- **CISA form cluster(s):** 2, 3, 4

#### azuredevops — Dependency scanning (GHAzDO Code Security) is enabled

- **Token permission:** vso.advsec (Repo Enablement - Get)
- **Fixture:** `internal/collect/azuredevops/secretshygiene/secretshygiene_test.go`
- **API endpoint(s):** `GET advsec.dev.azure.com/{org}/{project}/_apis/management/repositories/{repository}/enablement?includeAllProperties=true`

**Status rubric:**

- **verified-fail:** codeSecurityFeatures.codeSecurityEnabled is false
- **not-checkable:** the repo enablement fetch itself failed with a non-licensing error (403/404/other API error not attributable to GHAzDO licensing — see the not-checkable entry for the advsec-unavailable case specifically); or the call failed with a response azuredevops.IsAdvSecGated treats specially (403 or 404) — GHAzDO not being licensed/enabled for this org/project is ruled out as the cause (observed 2026-07-23 against dev.azure.com/seciq: an unlicensed org/project's enablement endpoints read HTTP 200 with every flag false/null instead, not 403/404 at all); a 403 most likely means the token lacks the vso.advsec scope, though other permission causes (tenant conditional access, an IP allow-list, project-level denial, an org policy restricting PAT access) can't be excluded from the response alone; what actually produces a 404 remains genuinely unconfirmed [fixture-verify] — neither is asserted as more than that
- **verified-pass:** codeSecurityFeatures.codeSecurityEnabled is true (dependency scanning is part of the Code Security plan)

**Remediation:** Project Settings -> Repositories -> [repo] -> Security -> GitHub Advanced Security -> enable Code Security (this enables dependency scanning as part of the Code Security plan).

#### github — Dependabot vulnerability alerts are enabled

- **Token permission:** repo (classic); fine-grained equivalent requires repo admin-level read access (security_and_analysis and vulnerability-alerts are both admin-only visible) — exact fine-grained permission category not independently verified against GitHub's docs, unlike the other entries in this table; org check additionally needs org owner or security manager
- **Fixture:** `internal/collect/github/secretshygiene/secretshygiene_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/vulnerability-alerts`

**Status rubric:**

- **verified-fail:** GetVulnerabilityAlerts returned 404 — go-github folds this into (enabled=false, err=nil), a real, meaningful "off" state rather than an error
- **not-checkable:** the repo fetch itself failed (403/404/other API error); or GetVulnerabilityAlerts returned a genuine error (403 permission-denied, etc.) distinct from the honest-404-disabled case above
- **verified-pass:** GetVulnerabilityAlerts returned 204 (enabled)

**Remediation:** Repo Settings -> Code security -> enable "Dependabot alerts".

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PW.4.4`:** Verify that acquired commercial, open-source, and all other third-party software components comply with the requirements, as defined by the organization, throughout their life cycles.

---

### `C04.org.security-defaults`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — Org enables Code Security/Secret Protection features by default for new repos

- **Token permission:** vso.advsec (Org Enablement - Get)
- **Fixture:** `internal/collect/azuredevops/secretshygiene/secretshygiene_test.go`
- **API endpoint(s):** `GET advsec.dev.azure.com/{org}/_apis/management/enablement?includeAllProperties=true`

**Status rubric:**

- **verified-fail:** at least one of the four on-create-default fields is false
- **not-checkable:** the org enablement fetch failed with a non-licensing error (403/404/other API error); or the call failed with a response azuredevops.IsAdvSecGated treats specially (403 or 404) — GHAzDO not being licensed/enabled for this org/project is ruled out as the cause (observed 2026-07-23 against dev.azure.com/seciq: an unlicensed org/project's enablement endpoints read HTTP 200 with every flag false/null instead, not 403/404 at all); a 403 most likely means the token lacks the vso.advsec scope, though other permission causes (tenant conditional access, an IP allow-list, project-level denial, an org policy restricting PAT access) can't be excluded from the response alone; what actually produces a 404 remains genuinely unconfirmed [fixture-verify] — neither is asserted as more than that; or the response decoded successfully but omitted enablementOnCreateSettings entirely — never assumed to mean every on-create default is off
- **verified-pass:** all four of enablementOnCreateSettings.enableCodeSecurityOnCreate, enableSecretProtectionOnCreate, enableBlockPushesOnCreate, and enableDependencyScanningInjectionOnCreate are true

**Remediation:** Organization Settings -> GitHub Advanced Security -> enable Code Security, Secret Protection, block-pushes-on-create, AND dependency-scanning-injection-on-create for newly created repositories — all four must be on for this check to pass, so every repo created going forward starts protected instead of relying on each repo owner to enable them individually.

#### github — Org enables secret/dependency security features by default for new repos

- **Token permission:** repo (classic); fine-grained equivalent requires repo admin-level read access (security_and_analysis and vulnerability-alerts are both admin-only visible) — exact fine-grained permission category not independently verified against GitHub's docs, unlike the other entries in this table; org check additionally needs org owner or security manager
- **Fixture:** `internal/collect/github/secretshygiene/secretshygiene_test.go`
- **API endpoint(s):** `GET /orgs/{org}`

**Status rubric:**

- **verified-fail:** at least one of the four security-default-for-new-repos fields is false
- **not-checkable:** the org fetch failed (403/404/other API error), or all four fields came back nil (token lacks org owner or security manager permission to view them)
- **verified-pass:** all four of secret_scanning_enabled_for_new_repositories, secret_scanning_push_protection_enabled_for_new_repositories, dependabot_alerts_enabled_for_new_repositories, and advanced_security_enabled_for_new_repositories are true

**Remediation:** Org Settings -> Code security -> enable secret scanning, push protection, Dependabot alerts, AND Advanced Security "for new repositories" — all four must be on for this check to pass — so every repo created going forward starts with them on, instead of relying on each repo owner to enable them individually.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

### `C04.secrets.advanced-security`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — GitHub Advanced Security for Azure DevOps is enabled where applicable

- **Token permission:** vso.advsec (Repo Enablement - Get)
- **Fixture:** `internal/collect/azuredevops/secretshygiene/secretshygiene_test.go`
- **API endpoint(s):** `GET advsec.dev.azure.com/{org}/{project}/_apis/management/repositories/{repository}/enablement?includeAllProperties=true`

**Status rubric:**

- **verified-fail:** codeSecurityEnabled and secretProtectionEnabled are not both true
- **not-checkable:** the repo enablement fetch itself failed with a non-licensing error (403/404/other API error not attributable to GHAzDO licensing — see the not-checkable entry for the advsec-unavailable case specifically); or the call failed with a response azuredevops.IsAdvSecGated treats specially (403 or 404) — GHAzDO not being licensed/enabled for this org/project is ruled out as the cause (observed 2026-07-23 against dev.azure.com/seciq: an unlicensed org/project's enablement endpoints read HTTP 200 with every flag false/null instead, not 403/404 at all); a 403 most likely means the token lacks the vso.advsec scope, though other permission causes (tenant conditional access, an IP allow-list, project-level denial, an org policy restricting PAT access) can't be excluded from the response alone; what actually produces a 404 remains genuinely unconfirmed [fixture-verify] — neither is asserted as more than that
- **verified-pass:** both codeSecurityFeatures.codeSecurityEnabled and secretProtectionFeatures.secretProtectionEnabled are true (post-unbundling GHAzDO is the combination of the Code Security and Secret Protection plans)

**Remediation:** Enable both Code Security and Secret Protection for the repo (Project Settings -> Repositories -> [repo] -> Security -> GitHub Advanced Security) — post-unbundling GHAzDO is the combination of these two plans, not a single toggle.

#### github — GitHub Advanced Security is enabled where applicable

- **Token permission:** repo (classic); fine-grained equivalent requires repo admin-level read access (security_and_analysis and vulnerability-alerts are both admin-only visible) — exact fine-grained permission category not independently verified against GitHub's docs, unlike the other entries in this table; org check additionally needs org owner or security manager
- **Fixture:** `internal/collect/github/secretshygiene/secretshygiene_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`

**Status rubric:**

- **verified-fail:** the repo is private and advanced_security.status is not "enabled"
- **not-checkable:** the repo fetch itself failed (403/404/other API error); or the repo is public (GHAS licensing only gates private-repo features, so this check doesn't apply the same way to a public repo, which gets the equivalent features free); or the repo fetch succeeded, but the response didn't include security_and_analysis at all (older org, or plan-gated) — never assumed off
- **verified-pass:** the repo's security_and_analysis.advanced_security.status is "enabled"

**Remediation:** Repo Settings -> Code security -> enable "GitHub Advanced Security" (requires a GHAS license on private repos; public repos get the equivalent features free without it). Since GitHub's 2025 GHAS unbundling, secret scanning and push protection can also be licensed and enabled independently via standalone Secret Protection, without this flag.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

### `C04.secrets.push-protection`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — Secret scanning push protection is active

- **Token permission:** vso.advsec (Repo Enablement - Get)
- **Fixture:** `internal/collect/azuredevops/secretshygiene/secretshygiene_test.go`
- **API endpoint(s):** `GET advsec.dev.azure.com/{org}/{project}/_apis/management/repositories/{repository}/enablement?includeAllProperties=true`

**Status rubric:**

- **verified-fail:** secretProtectionFeatures.blockPushes is false
- **not-checkable:** the repo enablement fetch itself failed with a non-licensing error (403/404/other API error not attributable to GHAzDO licensing — see the not-checkable entry for the advsec-unavailable case specifically); or the call failed with a response azuredevops.IsAdvSecGated treats specially (403 or 404) — GHAzDO not being licensed/enabled for this org/project is ruled out as the cause (observed 2026-07-23 against dev.azure.com/seciq: an unlicensed org/project's enablement endpoints read HTTP 200 with every flag false/null instead, not 403/404 at all); a 403 most likely means the token lacks the vso.advsec scope, though other permission causes (tenant conditional access, an IP allow-list, project-level denial, an org policy restricting PAT access) can't be excluded from the response alone; what actually produces a 404 remains genuinely unconfirmed [fixture-verify] — neither is asserted as more than that; or the response decoded successfully but blockPushes came back null even though includeAllProperties=true was requested — that field is only ever populated with that parameter set, so a null here means the request didn't actually carry it, not that push protection is off
- **verified-pass:** secretProtectionFeatures.blockPushes is true

**Remediation:** With Secret Protection enabled (see C04.secrets.scanning-enabled), also enable "Block pushes that expose secrets" so a push containing a detected secret is rejected before it lands.

#### github — Secret scanning push protection is active

- **Token permission:** repo (classic); fine-grained equivalent requires repo admin-level read access (security_and_analysis and vulnerability-alerts are both admin-only visible) — exact fine-grained permission category not independently verified against GitHub's docs, unlike the other entries in this table; org check additionally needs org owner or security manager
- **Fixture:** `internal/collect/github/secretshygiene/secretshygiene_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`

**Status rubric:**

- **verified-fail:** push protection reads "off" and either the repo is public (the feature is free, so "off" is a real gap) or the repo is private with GitHub Advanced Security licensed and enabled
- **not-checkable:** the repo fetch itself failed (403/404/other API error); or the repo fetch succeeded, but the response didn't include security_and_analysis at all (older org, or plan-gated) — never assumed off; or the repo is private, push protection reads "off", and Advanced Security isn't licensed/enabled on it — an unlicensed feature can't be faulted
- **verified-pass:** the repo's security_and_analysis.secret_scanning_push_protection.status is "enabled" (checked first, unconditionally — same rule as secrets.scanning-enabled)

**Remediation:** Repo Settings -> Code security -> under Secret scanning, enable "Push protection" so commits containing a detected secret are blocked before they land.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

### `C04.secrets.scanning-enabled`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — Secret scanning (GHAzDO Secret Protection) is active

- **Token permission:** vso.advsec (Repo Enablement - Get)
- **Fixture:** `internal/collect/azuredevops/secretshygiene/secretshygiene_test.go`
- **API endpoint(s):** `GET advsec.dev.azure.com/{org}/{project}/_apis/management/repositories/{repository}/enablement?includeAllProperties=true`

**Status rubric:**

- **verified-fail:** secretProtectionFeatures.secretProtectionEnabled is false
- **not-checkable:** the repo enablement fetch itself failed with a non-licensing error (403/404/other API error not attributable to GHAzDO licensing — see the not-checkable entry for the advsec-unavailable case specifically); or the call failed with a response azuredevops.IsAdvSecGated treats specially (403 or 404) — GHAzDO not being licensed/enabled for this org/project is ruled out as the cause (observed 2026-07-23 against dev.azure.com/seciq: an unlicensed org/project's enablement endpoints read HTTP 200 with every flag false/null instead, not 403/404 at all); a 403 most likely means the token lacks the vso.advsec scope, though other permission causes (tenant conditional access, an IP allow-list, project-level denial, an org policy restricting PAT access) can't be excluded from the response alone; what actually produces a 404 remains genuinely unconfirmed [fixture-verify] — neither is asserted as more than that
- **verified-pass:** secretProtectionFeatures.secretProtectionEnabled is true

**Remediation:** Project Settings -> Repositories -> [repo] -> Security -> GitHub Advanced Security -> enable Secret Protection. Requires a GHAzDO Secret Protection license (or the combined GHAzDO plan, pre-unbundling).

#### github — Secret scanning is active

- **Token permission:** repo (classic); fine-grained equivalent requires repo admin-level read access (security_and_analysis and vulnerability-alerts are both admin-only visible) — exact fine-grained permission category not independently verified against GitHub's docs, unlike the other entries in this table; org check additionally needs org owner or security manager
- **Fixture:** `internal/collect/github/secretshygiene/secretshygiene_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`

**Status rubric:**

- **verified-fail:** secret scanning reads "off" and either the repo is public (the feature is free, so "off" is a real gap) or the repo is private with GitHub Advanced Security licensed and enabled
- **not-checkable:** the repo fetch itself failed (403/404/other API error); or the repo fetch succeeded, but the response didn't include security_and_analysis at all (older org, or plan-gated) — never assumed off; or the repo is private, secret scanning reads "off", and Advanced Security isn't licensed/enabled on it — an unlicensed feature can't be faulted
- **verified-pass:** the repo's security_and_analysis.secret_scanning.status is "enabled" (checked first, unconditionally — a direct positive observation always wins over any licensing inference)

**Remediation:** Repo Settings -> Code security -> enable "Secret scanning". Free for public repos; on a private repo it needs a GitHub Advanced Security license, or (since GitHub's 2025 GHAS unbundling) a standalone GitHub Secret Protection license.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

### `C04.vars.secret-hygiene` — Variable groups don't store sensitive-named variables in plaintext

- **Token permission:** vso.variablegroups_read (Variable Groups - Get Variable Groups)
- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3
- **Fixture:** `internal/collect/azuredevops/secretshygiene/secretshygiene_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/distributedtask/variablegroups`

**Status rubric:**

- **verified-fail:** at least one variable with a sensitive-looking name is stored in plaintext (isSecret absent/false, value non-empty) — the offending variable and group names are recorded in Facts, never the value
- **not-checkable:** the project's variable groups list couldn't be read (403/404/other API error)
- **verified-pass:** no variable across every variable group in the project has both a name matching (?i)(password|passwd|secret|token|api[_-]?key|connectionstring) and isSecret absent/false with a non-empty value

**Remediation:** Open the flagged variable group (Pipelines -> Library) and mark every offending variable (name matching password/passwd/secret/token/api-key/connectionstring) as secret — the padlock icon next to its value — so Azure DevOps encrypts it at rest instead of storing it in plaintext.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

## C05.sast-history

### `C05.sast.cadence`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PW.7.2` (practice `PW.7`: Review and/or Analyze Human-Readable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements), `RV.1.2` (practice `RV.1`: Identify and Confirm Vulnerabilities on an Ongoing Basis)
- **CISA form cluster(s):** 3, 4

#### azuredevops — SAST run cadence over the lookback window

- **Token permission:** vso.build, vso.code, vso.advsec
- **Fixture:** `internal/collect/azuredevops/sasthistory/sasthistory_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/git/repositories`, `GET dev.azure.com/{org}/{project}/_apis/pipelines`, `GET dev.azure.com/{org}/{project}/_apis/build/definitions/{definitionId}`, `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/items`, `GET advsec.dev.azure.com/{org}/{project}/_apis/management/repositories/{repository}/enablement`, `GET dev.azure.com/{org}/{project}/_apis/build/builds`

**Status rubric:**

- **verified-fail:** a SAST tool is configured via a matched pipeline, but zero SAST builds were observed in the lookback window
- **partial:** one or more builds were observed, but only a low-confidence (pipeline/step-name-only) match identified the tool — not enough signal to confirm this cadence reflects genuine SAST activity
- **not-checkable:** the project's repositories or pipelines couldn't be read (403/other API error), the named repository wasn't found in the project, or resolving this repo's release tags failed (403/other API error) — collectRepo returns not-checkable for every check on the first such failure; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or no SAST tool is configured at all (no matched pipeline of any confidence, and GHAzDO CodeQL default setup does not read enabled) — nothing to compute cadence for; or a SAST tool is configured ONLY via GHAzDO CodeQL default setup, and this collector has no verified way to observe scan history for that mechanism via the Pipelines/Builds APIs it uses [fixture-verify, issue #34/#155's S9 pass] — see the package doc comment for why this collector doesn't assert a run count it can't verify; or the project's build history itself could not be fetched
- **verified-pass:** one or more SAST builds were observed in the lookback window, backed by at least a medium-confidence pipeline match or GHAzDO CodeQL default setup (not a low-confidence-only match)

**Remediation:** If zero SAST builds were observed in the lookback window, same fix as C05.sast.ran-per-release: confirm the pipeline runs on a schedule or on every push/PR to the default branch, not only on rare manual triggers. If builds WERE observed but this still reads partial, the match itself is low-confidence (pipeline/step-name-only) — same fix as C05.sast.tool-configured: use a recognized task/CLI, not just a pipeline name that sounds like SAST.

#### github — SAST run cadence over the lookback window

- **Token permission:** repo (classic) or Actions: read-only + Contents: read-only (fine-grained) — plus whatever fine-grained category gates the code-scanning default-setup endpoint specifically, not independently verified against GitHub's docs (see C04's TokenScope for the same kind of hedge, and why)
- **Fixture:** `internal/collect/github/sasthistory/sasthistory_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/actions/workflows`, `GET /repos/{owner}/{repo}/contents/{path}`, `GET /repos/{owner}/{repo}/code-scanning/default-setup`, `GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs`

**Status rubric:**

- **verified-fail:** a SAST tool is configured (workflow match or CodeQL default setup), but zero SAST runs were observed in the lookback window
- **partial:** one or more runs were observed, but only a low-confidence (workflow-name-only) match identified the tool — not enough signal to confirm this cadence reflects genuine SAST activity
- **not-checkable:** the repo fetch, the workflow listing, or the release listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on the first such failure, since none of them can be computed without this shared evidence; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or no SAST tool is configured at all (no workflow match of any confidence, and CodeQL default setup does not read "configured") — nothing to compute cadence for
- **verified-pass:** one or more SAST runs were observed in the lookback window, backed by at least a medium-confidence workflow match or CodeQL default setup (not a low-confidence-only match)

**Remediation:** If zero SAST runs were observed in the lookback window, same fix as C05.sast.ran-per-release: confirm the workflow runs on a schedule or on every push/PR to the default branch, not only on rare manual dispatch. If runs WERE observed but this still reads partial, the match itself is low-confidence (workflow-name-only) — same fix as C05.sast.tool-configured: use a recognized action/CLI, not just a workflow name that sounds like SAST.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PW.7.2`:** Perform the code review and/or code analysis based on the organization's secure coding standards, and record and triage all discovered issues and recommended remediations in the development team's workflow or issue tracking system.
> **`RV.1.2`:** Review, analyze, and/or test the software's code to identify or confirm the presence of previously undetected vulnerabilities.

---

### `C05.sast.default-setup`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PW.7.1` (practice `PW.7`: Review and/or Analyze Human-Readable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements), `RV.1.2` (practice `RV.1`: Identify and Confirm Vulnerabilities on an Ongoing Basis)
- **CISA form cluster(s):** 2, 3, 4

#### azuredevops — GHAzDO CodeQL default setup

- **Token permission:** vso.advsec
- **Fixture:** `internal/collect/azuredevops/sasthistory/sasthistory_test.go`
- **API endpoint(s):** `GET advsec.dev.azure.com/{org}/{project}/_apis/management/repositories/{repository}/enablement`

**Status rubric:**

- **verified-fail:** the GHAzDO repo-enablement query succeeded, but codeSecurityFeatures.codeQLEnabled reads false
- **not-checkable:** the project's repositories or pipelines couldn't be read (403/other API error), the named repository wasn't found in the project, or resolving this repo's release tags failed (403/other API error) — collectRepo returns not-checkable for every check on the first such failure; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or the GHAzDO repo-enablement query itself failed — a 404 (cause unconfirmed: observed 2026-07-23 against dev.azure.com/seciq that an unlicensed org/project reads HTTP 200 instead, ruling out licensing as the explanation [fixture-verify]), a 403 (most likely the token lacks the vso.advsec scope — that same observation rules out licensing as the cause, but other permission causes can't be excluded from the response alone; see azuredevops.IsAdvSecGated's own doc comment), or another API error
- **verified-pass:** the GHAzDO repo-enablement query succeeded and codeSecurityFeatures.codeQLEnabled reads true

**Remediation:** Repo -> Advanced Security -> Code scanning -> CodeQL -> Enable default setup.

#### github — CodeQL default setup is configured

- **Token permission:** repo (classic) or Actions: read-only + Contents: read-only (fine-grained) — plus whatever fine-grained category gates the code-scanning default-setup endpoint specifically, not independently verified against GitHub's docs (see C04's TokenScope for the same kind of hedge, and why)
- **Fixture:** `internal/collect/github/sasthistory/sasthistory_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/code-scanning/default-setup`

**Status rubric:**

- **verified-fail:** the default-setup query succeeded, but the state reads anything other than "configured" (e.g. "not-configured")
- **not-checkable:** the repo fetch, the workflow listing, or the release listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on the first such failure, since none of them can be computed without this shared evidence; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or the default-setup query itself failed (403/plan-gated/other API error)
- **verified-pass:** CodeQL default setup's state reads "configured"

**Remediation:** Repo Settings -> Security -> Advanced Security -> under Code Security, "CodeQL analysis" -> Set up -> Default (choose "Default", not "Advanced", unless a custom workflow is specifically needed).

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PW.7.1`:** Determine whether code review (a person looks directly at the code to find issues) and/or code analysis (tools are used to find issues in code, either in a fully automated way or in conjunction with a person) should be used, as defined by the organization.
> **`RV.1.2`:** Review, analyze, and/or test the software's code to identify or confirm the presence of previously undetected vulnerabilities.

---

### `C05.sast.ran-per-release`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PW.7.2` (practice `PW.7`: Review and/or Analyze Human-Readable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements), `RV.1.2` (practice `RV.1`: Identify and Confirm Vulnerabilities on an Ongoing Basis)
- **CISA form cluster(s):** 3, 4

#### azuredevops — A SAST tool ran for each release in the lookback window

- **Token permission:** vso.build, vso.code
- **Fixture:** `internal/collect/azuredevops/sasthistory/sasthistory_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/git/repositories`, `GET dev.azure.com/{org}/{project}/_apis/pipelines`, `GET dev.azure.com/{org}/{project}/_apis/build/definitions/{definitionId}`, `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/items`, `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/refs`, `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/annotatedtags/{objectId}`, `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/commits/{commitId}`, `GET dev.azure.com/{org}/{project}/_apis/build/builds`

**Status rubric:**

- **verified-fail:** at least one release in the lookback window has zero matched SAST builds at all (not even a failed one), and — when there are zero matched pipelines overall — every pipeline MatchPipelines inspected for this repo resolved cleanly (no same-repo skip)
- **partial:** one or more release tags matching the configured pattern could not be dated (their commit is always already known straight from the refs listing itself — it's only the date lookup that failed; this collector's own deliberate choice applies that unconditionally, not only to tags provably inside the lookback window — see the package doc comment); if that leaves nothing evaluable, the reason names the drop count directly, otherwise every evaluated release still succeeded but the exclusion caps the result at partial; or a matched SAST pipeline ran for every evaluated release, but not every build succeeded
- **not-checkable:** the project's repositories or pipelines couldn't be read (403/other API error), the named repository wasn't found in the project, or resolving this repo's release tags failed (403/other API error) — collectRepo returns not-checkable for every check on the first such failure; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or GHAzDO CodeQL default setup is this repo's ONLY SAST evidence (no signature-matched pipeline at all) — default-setup scans run invisibly to this collector's own build-matching, so this check has no verified way to observe them per release (issue #184, mirroring C06's identical injectionOnly guard); or there are zero matched pipelines and one or more of this repo's own pipelines could not be fully inspected (see Facts.skipped_pipelines) — the same evidence gap C05.sast.tool-configured itself goes not-checkable for, so this check does too rather than asserting a confident absence over it — when default setup is ALSO the sole evidence, that cause wins and is what this Reason names (the skip is still recorded in Facts, just not the stated cause), since the skip wording would otherwise contradict tool-configured's verified-pass for the identical evidence; or no release tag matches the configured pattern within the lookback window, and none of the tags that did match were dropped as unresolvable either — genuinely nothing to evaluate; or the project's build history itself could not be fetched
- **verified-pass:** a SAST pipeline ran successfully (at least one matched build whose result is "succeeded", case-insensitive) for every release in the lookback window, and every matching release tag was successfully dated

**Remediation:** Make sure the SAST pipeline's trigger actually fires on (or before) the commit each release tag points at — e.g. trigger on push to the release branch — and that any build that did fire completed with result=="succeeded" rather than failing or being canceled.

#### github — A SAST tool ran for each release in the lookback window

- **Token permission:** repo (classic) or Actions: read-only + Contents: read-only (fine-grained) — plus whatever fine-grained category gates the code-scanning default-setup endpoint specifically, not independently verified against GitHub's docs (see C04's TokenScope for the same kind of hedge, and why)
- **Fixture:** `internal/collect/github/sasthistory/sasthistory_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/actions/workflows`, `GET /repos/{owner}/{repo}/contents/{path}`, `GET /repos/{owner}/{repo}/releases`, `GET /repos/{owner}/{repo}/git/ref/{ref}`, `GET /repos/{owner}/{repo}/git/tags/{tag_sha}`, `GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs`

**Status rubric:**

- **verified-fail:** at least one release in the lookback window has zero matched SAST runs at all (not even a failed one), and — when there are zero matched workflows overall — every workflow MatchWorkflows inspected for this repo resolved cleanly (no same-repo skip)
- **partial:** one or more matching release tags published in the lookback window couldn't be resolved to a commit; if that leaves nothing evaluable, the reason names the drop count directly, otherwise every evaluated release still succeeded but the exclusion caps the result at partial; or a matched SAST tool ran for every evaluated release, but not every run succeeded
- **not-checkable:** the repo fetch, the workflow listing, or the release listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on the first such failure, since none of them can be computed without this shared evidence; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or no release tag matches the configured pattern within the lookback window, and none of the tags that did match were dropped as unresolvable either — genuinely nothing to evaluate; or there are zero matched workflows and one or more of this repo's own workflows could not be fully inspected (see Facts.skipped_workflows) — the same evidence gap C05.sast.tool-configured itself goes not-checkable for, so this check does too rather than asserting a confident absence over it
- **verified-pass:** a SAST tool ran successfully (at least one matched run whose conclusion is "success") for every release in the lookback window, and every matching release tag published in the lookback window resolved to a commit — an unresolvable tag published outside the window is out of scope, not a drop, so it doesn't block verified-pass

**Remediation:** Make sure the SAST workflow's trigger actually fires on (or before) the commit each release is cut from — e.g. trigger on push to the release branch, or on the release event itself — and that any run that did fire completed successfully rather than erroring out.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PW.7.2`:** Perform the code review and/or code analysis based on the organization's secure coding standards, and record and triage all discovered issues and recommended remediations in the development team's workflow or issue tracking system.
> **`RV.1.2`:** Review, analyze, and/or test the software's code to identify or confirm the presence of previously undetected vulnerabilities.

---

### `C05.sast.tool-configured`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PW.7.1` (practice `PW.7`: Review and/or Analyze Human-Readable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements), `RV.1.2` (practice `RV.1`: Identify and Confirm Vulnerabilities on an Ongoing Basis)
- **CISA form cluster(s):** 2, 3, 4

#### azuredevops — A SAST tool is configured

- **Token permission:** vso.build, vso.code (pipeline discovery and YAML fetch), vso.advsec (GHAzDO repo enablement)
- **Fixture:** `internal/collect/azuredevops/sasthistory/sasthistory_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/git/repositories`, `GET dev.azure.com/{org}/{project}/_apis/pipelines`, `GET dev.azure.com/{org}/{project}/_apis/build/definitions/{definitionId}`, `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/items`, `GET advsec.dev.azure.com/{org}/{project}/_apis/management/repositories/{repository}/enablement`

**Status rubric:**

- **verified-fail:** no pipeline match of any confidence was found, the GHAzDO repo-enablement query confirms codeQLEnabled reads false — including a 404 response, which this check treats as equivalent to "every enablement flag off" by deliberate policy (see isAdvSecNotFoundErr's own doc comment), not because a 404 is a confirmed "not available" fact: S9's 2026-07-23 live run against dev.azure.com/seciq showed an unlicensed org/project's enablement endpoint reads HTTP 200 with every flag false/null instead, so what actually produces a 404 here remains genuinely unconfirmed [fixture-verify] — but deliberately NOT a 403 (most likely the token lacks the vso.advsec scope — that response alone routes to not-checkable instead, see the next clause; found in review: an earlier version of this check treated any gated response, 403 included, as a confirmed fail, which could false-negative a licensed org whose token merely lacked the scope) — and every pipeline MatchPipelines inspected for this repo resolved cleanly (no same-repo skip) — a real absence, not an evidence gap
- **partial:** only a low-confidence (pipeline/step-name-only) match was found in any pipeline, and CodeQL default setup is not confirmed enabled — not enough signal alone to confirm a SAST tool is genuinely configured
- **not-checkable:** the project's repositories or pipelines couldn't be read (403/other API error), the named repository wasn't found in the project, or resolving this repo's release tags failed (403/other API error) — collectRepo returns not-checkable for every check on the first such failure; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or there is no pipeline-based evidence at all and the GHAzDO repo-enablement query itself failed with anything other than a 404 — including a 403 (most likely the token lacks the vso.advsec scope; licensing is ruled out as the cause — observed 2026-07-23 against dev.azure.com/seciq: an unlicensed org/project's enablement endpoint reads HTTP 200, not 403 — but other permission causes can't be excluded from the response alone) — an unresolved unknown, not a confirmed absence; or one or more of this repo's own pipelines could not be fully inspected (a build-definition fetch failure, an unresolved YAML path, a YAML fetch/parse failure, or an unresolved template reference — see Facts.skipped_pipelines) and the evidence gathered would otherwise have produced verified-fail — this check applies the honest not-checkable fix now rather than asserting a confident absence over incomplete evidence
- **verified-pass:** at least one matched pipeline reaches medium-or-high confidence (an ado_task or run-pattern match, not just a suggestive pipeline/step name), or GHAzDO's CodeQL default setup (codeSecurityFeatures.codeQLEnabled) reads true

**Remediation:** Enable GHAzDO CodeQL default setup (repo -> Advanced Security -> Code scanning -> CodeQL -> Enable default setup), or add a pipeline task using a recognized SAST task/CLI (see mappings/scanner-signatures.yaml for what this tool recognizes) — a pipeline whose name merely suggests SAST isn't enough on its own; it needs a matched task/CLI invocation to count as more than a low-confidence signal.

#### github — A SAST tool is configured

- **Token permission:** repo (classic) or Actions: read-only + Contents: read-only (fine-grained) — plus whatever fine-grained category gates the code-scanning default-setup endpoint specifically, not independently verified against GitHub's docs (see C04's TokenScope for the same kind of hedge, and why)
- **Fixture:** `internal/collect/github/sasthistory/sasthistory_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/actions/workflows`, `GET /repos/{owner}/{repo}/contents/{path}`, `GET /repos/{owner}/{repo}/code-scanning/default-setup`

**Status rubric:**

- **verified-fail:** no workflow match of any confidence was found, CodeQL default setup's state reads anything other than "configured" — including a legitimate plan-gated/not-found response to the default-setup query itself (a real "not available" fact, not an unknown) — and every workflow MatchWorkflows inspected for this repo resolved cleanly (no same-repo skip) — a real absence, not an evidence gap
- **partial:** only a low-confidence (workflow-name-only) match was found in any workflow, and CodeQL default setup is not confirmed configured — not enough signal alone to confirm a SAST tool is genuinely configured
- **not-checkable:** the repo fetch, the workflow listing, or the release listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on the first such failure, since none of them can be computed without this shared evidence; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or there is no workflow-based evidence at all and the CodeQL default-setup query itself failed with something other than a plan-gated/not-found response — an unresolved unknown, not a confirmed absence; or one or more of this repo's own workflows could not be fully inspected (a content fetch, decode, or parse failure — see Facts.skipped_workflows) and the evidence gathered would otherwise have produced verified-fail — this check applies the honest not-checkable fix now rather than asserting a confident absence over incomplete evidence
- **verified-pass:** at least one matched workflow reaches medium-or-high confidence (an action slug or CLI pattern, not just a suggestive workflow name), or CodeQL default setup's state reads "configured"

**Remediation:** Enable CodeQL default setup (repo Settings -> Security -> Advanced Security -> under Code Security, "CodeQL analysis" -> Set up -> Default), or add a workflow using a recognized SAST action/CLI (see mappings/scanner-signatures.yaml for what this tool recognizes) — a workflow whose name merely suggests SAST isn't enough on its own; it needs a matched action/CLI invocation to count as more than a low-confidence signal.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PW.7.1`:** Determine whether code review (a person looks directly at the code to find issues) and/or code analysis (tools are used to find issues in code, either in a fully automated way or in conjunction with a person) should be used, as defined by the organization.
> **`RV.1.2`:** Review, analyze, and/or test the software's code to identify or confirm the presence of previously undetected vulnerabilities.

---

## C06.sca-history

### `C06.sca.alerts-triaged`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PW.4.4` (practice `PW.4`: Reuse Existing, Well-Secured Software When Feasible Instead of Duplicating Functionality), `RV.2.1` (practice `RV.2`: Assess, Prioritize, and Remediate Vulnerabilities)
- **CISA form cluster(s):** 2, 3, 4

#### azuredevops — Open GHAzDO dependency-scanning alerts are triaged within the default window

- **Token permission:** vso.advsec (Alerts - List)
- **Fixture:** `internal/collect/azuredevops/scahistory/scahistory_test.go`
- **API endpoint(s):** `GET advsec.dev.azure.com/{org}/{project}/_apis/alert/repositories/{repository}/alerts?criteria.alertType=dependency&criteria.states=active&criteria.severities=critical`

**Status rubric:**

- **verified-fail:** the alerts query failed with HTTP 400 and typeKey AdvSecNotEnabledException — a confirmed signal GHAzDO dependency-scanning alerts are not enabled for this repository (observed 2026-07-23 against dev.azure.com/seciq), a real compliance gap rather than an unresolved unknown; matches the GitHub twin's identical treatment of its own confirmed-disabled signal
- **partial:** one or more active critical dependency-scanning alerts are open, and the oldest has been open longer than the 30-day triage window; or one or more active critical alerts were found but none of their firstSeenDate values could be parsed, so their age relative to the 30-day window is genuinely unknown
- **not-checkable:** the project's repositories or pipelines couldn't be read (403/other API error), or the named repository wasn't found in the project — collectRepo returns not-checkable for every check on the first such failure; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or the alerts query returned 404 — the cause is unconfirmed: S9's 2026-07-23 live run against dev.azure.com/seciq settled the confirmed-not-enabled signal as HTTP 400 with typeKey AdvSecNotEnabledException (see the verified-fail row above), not 404, so licensing/not-enabled is no longer a plausible explanation for a 404 here [fixture-verify: no recorded response covers what actually produces one]; or the alerts query failed with a 403 (ambiguous: either a missing vso.advsec scope or some other cause this collector can't distinguish from the response alone [fixture-verify: no recorded response covers a 403 from this endpoint]) or another API error
- **verified-pass:** the active-critical-alerts query succeeded, and no alert has been open longer than the 30-day triage window

**Remediation:** If GHAzDO dependency scanning is disabled entirely, enable it first (see C06.sca.tool-configured). Once enabled, triage: repo -> Advanced Security -> filter by Critical severity -> fix or dismiss (with a documented reason) any critical alert open longer than 30 days.

#### github — Open Dependabot alerts are triaged within the default window

- **Token permission:** repo (classic) or Actions: read-only + Contents: read-only (fine-grained), plus Administration: read-only (shared with C02, for the dependency-review required-status-check cross-check) and whatever fine-grained category gates Dependabot alerts specifically — not independently verified against GitHub's docs, same kind of hedge as C05's TokenScope
- **Fixture:** `internal/collect/github/scahistory/scahistory_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/dependabot/alerts`

**Status rubric:**

- **verified-fail:** Dependabot alerts are not enabled for this repository (the alerts endpoint returned 403 with a message confirming the feature itself is disabled, not a generic permission or not-found error)
- **partial:** one or more critical alerts are open, and the oldest has been open longer than the 30-day triage window
- **not-checkable:** the repo fetch or the workflow listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on either failure, since none of them can be computed without this shared evidence; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or the open-alerts fetch failed with something other than a confirmed "alerts disabled" 403 (a genuine permission denial, a 404, or another API error) — this collector can't distinguish those causes from GitHub's response alone
- **verified-pass:** the open-alerts fetch succeeded, and no critical alert has been open longer than the 30-day triage window

**Remediation:** If Dependabot alerts are disabled entirely, enable them first: repo Settings -> Code security -> enable "Dependabot alerts" (see C04.deps.dependabot-alerts). Once enabled, triage: Security -> Dependabot alerts -> filter by Critical severity -> fix or dismiss (with a documented reason) any critical alert open longer than 30 days.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PW.4.4`:** Verify that acquired commercial, open-source, and all other third-party software components comply with the requirements, as defined by the organization, throughout their life cycles.
> **`RV.2.1`:** Analyze each vulnerability to gather sufficient information about risk to plan its remediation or other risk response.

---

### `C06.sca.dependabot-config`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PW.4.4` (practice `PW.4`: Reuse Existing, Well-Secured Software When Feasible Instead of Duplicating Functionality)
- **CISA form cluster(s):** 2, 3, 4

#### azuredevops — Dependency-scan config covers the repo's detected ecosystems

- **Token permission:** n/a — no ADO evidence source exists for this check; see its Rubric
- **Fixture:** `internal/collect/azuredevops/scahistory/scahistory_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** the project's repositories or pipelines couldn't be read (403/other API error), or the named repository wasn't found in the project — collectRepo returns not-checkable for every check on the first such failure; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or (the common case) Azure DevOps has no per-repo Dependabot-config-file convention at all — GHAzDO dependency scanning is enablement-driven (see C06.sca.tool-configured), not configured via a checked-in file the way .github/dependabot.yml is on GitHub — this check has no ADO evidence source and reports not-checkable unconditionally, on every repo, regardless of any other evidence gathered

**Remediation:** Not applicable to Azure DevOps — GHAzDO dependency scanning is enablement-driven (Project Settings -> Repositories -> [repo] -> Security -> GitHub Advanced Security), not configured via a checked-in file; see C06.sca.tool-configured instead.

#### github — Dependabot config covers the repo's detected dependency ecosystems

- **Token permission:** repo (classic) or Actions: read-only + Contents: read-only (fine-grained), plus Administration: read-only (shared with C02, for the dependency-review required-status-check cross-check) and whatever fine-grained category gates Dependabot alerts specifically — not independently verified against GitHub's docs, same kind of hedge as C05's TokenScope
- **Fixture:** `internal/collect/github/scahistory/scahistory_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/actions/workflows`, `GET /repos/{owner}/{repo}/contents/{path}`

**Status rubric:**

- **verified-fail:** no Dependabot config exists at either accepted path, and one or more dependency ecosystems were detected
- **partial:** a Dependabot config exists, but one or more detected ecosystems are not covered by it
- **not-checkable:** the repo fetch or the workflow listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on either failure, since none of them can be computed without this shared evidence; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or the repo's root directory listing failed (403/plan-gated/other API error), so which ecosystems are in use couldn't be detected; or the Dependabot config fetch itself failed (permission denied, malformed YAML, or another API error); or no Dependabot config exists and no dependency manifests were detected either — nothing for Dependabot to cover
- **verified-pass:** a Dependabot config exists and covers every ecosystem detected from the repo's root-level manifests and/or its GitHub Actions workflows

**Remediation:** Extend `.github/dependabot.yml` with an `updates:` entry for each detected-but-uncovered ecosystem (see this finding's `uncovered_ecosystems` fact for exactly which ones).

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PW.4.4`:** Verify that acquired commercial, open-source, and all other third-party software components comply with the requirements, as defined by the organization, throughout their life cycles.

---

### `C06.sca.dependency-review`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PW.4.4` (practice `PW.4`: Reuse Existing, Well-Secured Software When Feasible Instead of Duplicating Functionality)
- **CISA form cluster(s):** 2, 3, 4

#### azuredevops — Dependency review is enforced as a required check on pull requests

- **Token permission:** n/a — no ADO evidence source exists for this check; see its Rubric
- **Fixture:** `internal/collect/azuredevops/scahistory/scahistory_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** the project's repositories or pipelines couldn't be read (403/other API error), or the named repository wasn't found in the project — collectRepo returns not-checkable for every check on the first such failure; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or (the common case) Azure DevOps has no pull-request dependency-review gate equivalent to GitHub's dependency-review-action — this check has no ADO evidence source and reports not-checkable unconditionally, on every repo, regardless of any other evidence gathered

**Remediation:** Not applicable to Azure DevOps — there is no pull-request dependency-review gate equivalent to GitHub's dependency-review-action; GHAzDO surfaces dependency-scanning alerts (see C06.sca.alerts-triaged) but does not block a PR merge on them.

#### github — Dependency review is enforced as a required check on pull requests

- **Token permission:** repo (classic) or Actions: read-only + Contents: read-only (fine-grained), plus Administration: read-only (shared with C02, for the dependency-review required-status-check cross-check) and whatever fine-grained category gates Dependabot alerts specifically — not independently verified against GitHub's docs, same kind of hedge as C05's TokenScope
- **Fixture:** `internal/collect/github/scahistory/scahistory_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/actions/workflows`, `GET /repos/{owner}/{repo}/contents/{path}`, `GET /repos/{owner}/{repo}/branches/{branch}/protection`, `GET /repos/{owner}/{repo}/rules/branches/{branch}`

**Status rubric:**

- **verified-fail:** no workflow matching the dependency-review-action signature (or equivalent) was detected in any workflow
- **partial:** a matched dependency-review workflow doesn't trigger on `pull_request`/`pull_request_target` events; or the required-status-check state couldn't be determined; or the workflow triggers on pull requests but no required status check name exactly matches its own name (a substring-only "loose" match, or no match at all, is never asserted as confirmed — GitHub's real check-run naming can't be derived precisely from the workflow name alone)
- **not-checkable:** the repo fetch or the workflow listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on either failure, since none of them can be computed without this shared evidence; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or a dependency-review workflow was detected, but re-fetching it to inspect its triggers failed
- **verified-pass:** a matched dependency-review-action (or equivalent SCA-category) workflow triggers on `pull_request`/`pull_request_target`, and its workflow name exactly (case-insensitively) matches one of the branch's required status check names

**Remediation:** Add a workflow using `actions/dependency-review-action` (or equivalent), make sure it triggers on `pull_request` (not just push), and add it as a required status check: repo Settings -> Rules -> Rulesets -> the branch's rule -> Require status checks to pass -> select the dependency-review workflow's check.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PW.4.4`:** Verify that acquired commercial, open-source, and all other third-party software components comply with the requirements, as defined by the organization, throughout their life cycles.

---

### `C06.sca.ran-per-release`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PW.4.4` (practice `PW.4`: Reuse Existing, Well-Secured Software When Feasible Instead of Duplicating Functionality), `RV.1.2` (practice `RV.1`: Identify and Confirm Vulnerabilities on an Ongoing Basis)
- **CISA form cluster(s):** 2, 3, 4

#### azuredevops — An SCA tool ran for each release in the lookback window

- **Token permission:** vso.build, vso.code
- **Fixture:** `internal/collect/azuredevops/scahistory/scahistory_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/git/repositories`, `GET dev.azure.com/{org}/{project}/_apis/pipelines`, `GET dev.azure.com/{org}/{project}/_apis/build/definitions/{definitionId}`, `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/items`, `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/refs`, `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/annotatedtags/{objectId}`, `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/commits/{commitId}`, `GET dev.azure.com/{org}/{project}/_apis/build/builds`

**Status rubric:**

- **verified-fail:** at least one release in the lookback window has zero matched SCA builds at all (not even a failed one), and — when there are zero matched pipelines overall — every pipeline MatchPipelines inspected for this repo resolved cleanly (no same-repo skip)
- **partial:** one or more release tags matching the configured pattern could not be dated (their commit is always already known straight from the refs listing itself — it's only the date lookup that failed; this collector's own deliberate choice, inherited from C05, applies that unconditionally, not only to tags provably inside the lookback window); if that leaves nothing evaluable, the reason names the drop count directly, otherwise every evaluated release still succeeded but the exclusion caps the result at partial; or a matched SCA pipeline ran for every evaluated release, but not every build succeeded
- **not-checkable:** the project's repositories or pipelines couldn't be read (403/other API error), or the named repository wasn't found in the project — collectRepo returns not-checkable for every check on the first such failure; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or resolving this repo's release tags failed (403/other API error) — unlike the four other checks in this package, this failure is local to this check alone (see the package doc comment's judgment call 6); or GHAzDO dependency scanning injection is this repo's ONLY SCA evidence (no signature-matched pipeline at all) — injected scanning runs invisibly to this collector's own build-matching, so this check has no verified way to observe it per release (see the package doc comment's judgment call 7); or there are zero matched pipelines and one or more of this repo's own pipelines could not be fully inspected (see Facts.skipped_pipelines) — the same evidence gap C06.sca.tool-configured itself goes not-checkable for, so this check does too rather than asserting a confident absence over it — when dependency scanning injection is ALSO the sole evidence, that cause wins and is what this Reason names (the skip is still recorded in Facts, just not the stated cause), since the skip wording would otherwise contradict tool-configured's verified-pass for the identical evidence (see the package doc comment's judgment call 7); or no release tag matches the configured pattern within the lookback window, and none of the tags that did match were dropped as unresolvable either — genuinely nothing to evaluate; or the project's build history itself could not be fetched
- **verified-pass:** an SCA pipeline ran successfully (at least one matched build whose result is "succeeded", case-insensitive) for every release in the lookback window, and every matching release tag was successfully dated

**Remediation:** Make sure the SCA pipeline's trigger actually fires on (or before) the commit each release tag points at — e.g. trigger on push to the release branch — and that any build that did fire completed with result=="succeeded" rather than failing or being canceled.

#### github — An SCA tool ran for each release in the lookback window

- **Token permission:** repo (classic) or Actions: read-only + Contents: read-only (fine-grained), plus Administration: read-only (shared with C02, for the dependency-review required-status-check cross-check) and whatever fine-grained category gates Dependabot alerts specifically — not independently verified against GitHub's docs, same kind of hedge as C05's TokenScope
- **Fixture:** `internal/collect/github/scahistory/scahistory_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/actions/workflows`, `GET /repos/{owner}/{repo}/contents/{path}`, `GET /repos/{owner}/{repo}/releases`, `GET /repos/{owner}/{repo}/git/ref/{ref}`, `GET /repos/{owner}/{repo}/git/tags/{tag_sha}`, `GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs`

**Status rubric:**

- **verified-fail:** at least one release in the lookback window has zero matched SCA runs at all (not even a failed one), and — when there are zero matched workflows and no Dependabot config — every workflow this collector inspected for this repo resolved cleanly (no same-repo skip)
- **partial:** release tags published in the lookback window matched but couldn't be resolved to a commit, so no release could be evaluated; or a matched SCA tool ran for every evaluated release, but not every run succeeded; or every evaluated release succeeded, but one or more matching release tags couldn't be resolved to a commit and were excluded from evaluation
- **not-checkable:** the repo fetch or the workflow listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on either failure, since none of them can be computed without this shared evidence; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or no workflow-based SCA tool was detected and the Dependabot config fetch itself failed — unknown whether Dependabot is this repo's sole SCA tool or absent entirely; or Dependabot is this repo's sole detected SCA tool, which has no per-release run history to evaluate here (see C06.sca.alerts-triaged instead); or there are zero matched workflows, no Dependabot config, and one or more of this repo's own workflows could not be fully inspected (see Facts.skipped_workflows) — the same evidence gap C06.sca.tool-configured itself goes not-checkable for, so this check does too rather than asserting a confident absence over it; or the release listing itself failed (403/plan-gated/other API error); or no release tag matches the configured pattern within the lookback window, and none of the tags that did match were dropped as unresolvable either — genuinely nothing to evaluate
- **verified-pass:** an SCA tool ran successfully (at least one matched run whose conclusion is "success") for every release in the lookback window, and every matching release tag published in the lookback window resolved to a commit

**Remediation:** Applies to a workflow-based SCA tool specifically (Dependabot has no per-release run history to check). Make sure the SCA workflow's trigger fires on the commit each release is cut from, and that any run that fired completed successfully.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PW.4.4`:** Verify that acquired commercial, open-source, and all other third-party software components comply with the requirements, as defined by the organization, throughout their life cycles.
> **`RV.1.2`:** Review, analyze, and/or test the software's code to identify or confirm the presence of previously undetected vulnerabilities.

---

### `C06.sca.tool-configured`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PW.4.4` (practice `PW.4`: Reuse Existing, Well-Secured Software When Feasible Instead of Duplicating Functionality), `RV.1.2` (practice `RV.1`: Identify and Confirm Vulnerabilities on an Ongoing Basis)
- **CISA form cluster(s):** 2, 3, 4

#### azuredevops — An SCA tool is configured

- **Token permission:** vso.build, vso.code (pipeline discovery and YAML fetch), vso.advsec (GHAzDO repo enablement)
- **Fixture:** `internal/collect/azuredevops/scahistory/scahistory_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/git/repositories`, `GET dev.azure.com/{org}/{project}/_apis/pipelines`, `GET dev.azure.com/{org}/{project}/_apis/build/definitions/{definitionId}`, `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/items`, `GET advsec.dev.azure.com/{org}/{project}/_apis/management/repositories/{repository}/enablement`

**Status rubric:**

- **verified-fail:** no pipeline match of any confidence was found, dependency scanning injection is not confirmed enabled, and every pipeline MatchPipelines inspected for this repo resolved cleanly (no same-repo skip) — a real absence, not an evidence gap
- **partial:** only a low-confidence (pipeline/step-name-only) match was found in any pipeline, and dependency scanning injection is not confirmed enabled — not enough signal alone to confirm an SCA tool is genuinely configured
- **not-checkable:** the project's repositories or pipelines couldn't be read (403/other API error), or the named repository wasn't found in the project — collectRepo returns not-checkable for every check on the first such failure; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or there is no pipeline-based evidence at all and the GHAzDO repo-enablement query itself failed with anything other than a 404 — including a 403 (most likely the token lacks the vso.advsec scope; licensing is ruled out as the cause — observed 2026-07-23 against dev.azure.com/seciq: an unlicensed org/project's enablement endpoint reads HTTP 200, not 403 — but other permission causes can't be excluded from the response alone) — an unresolved unknown, not a confirmed absence; or one or more of this repo's own pipelines could not be fully inspected (a build-definition fetch failure, an unresolved YAML path, a YAML fetch/parse failure, or an unresolved template reference — see Facts.skipped_pipelines) and the evidence gathered would otherwise have produced verified-fail — this check applies the honest not-checkable fix rather than asserting a confident absence over incomplete evidence
- **verified-pass:** at least one matched pipeline reaches medium-or-high confidence (an ado_task or run-pattern match, not just a suggestive pipeline/step name), or GHAzDO dependency scanning injection (codeSecurityFeatures.dependencyScanningInjectionEnabled) reads true

**Remediation:** Add a pipeline task using a recognized SCA action/CLI (see mappings/scanner-signatures.yaml), or enable GHAzDO dependency scanning (Project Settings -> Repositories -> [repo] -> Security -> GitHub Advanced Security -> enable Code Security, which includes dependency scanning injection) — a pipeline whose name merely suggests SCA isn't enough on its own; it needs a matched task/CLI invocation to count as more than a low-confidence signal.

#### github — An SCA tool is configured

- **Token permission:** repo (classic) or Actions: read-only + Contents: read-only (fine-grained), plus Administration: read-only (shared with C02, for the dependency-review required-status-check cross-check) and whatever fine-grained category gates Dependabot alerts specifically — not independently verified against GitHub's docs, same kind of hedge as C05's TokenScope
- **Fixture:** `internal/collect/github/scahistory/scahistory_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/actions/workflows`, `GET /repos/{owner}/{repo}/contents/{path}`

**Status rubric:**

- **verified-fail:** no workflow match of any confidence was found, the Dependabot config fetch succeeded but found either no config at either accepted path (`.github/dependabot.yml` or `.yaml`) or a config with no `updates:` entry setting a non-empty `package-ecosystem`, and every workflow this collector inspected for this repo resolved cleanly (no same-repo skip) — a real absence, not an evidence gap
- **partial:** only a low-confidence (workflow-name-only) match was found in any workflow, and Dependabot is not confirmed configured (no config at either accepted path, a config with no usable `updates:` entries, or the config fetch itself failed) — not enough signal alone to confirm an SCA tool is genuinely configured
- **not-checkable:** the repo fetch or the workflow listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on either failure, since none of them can be computed without this shared evidence; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or there is no workflow-based evidence at all and the Dependabot config fetch itself failed (permission denied, malformed YAML, or another API error) — an unresolved unknown, not a confirmed absence; or one or more of this repo's own workflows could not be fully inspected (a content fetch, decode, or parse failure — see Facts.skipped_workflows) and no Dependabot config was found, and the evidence gathered would otherwise have produced verified-fail — this check applies the honest not-checkable fix rather than asserting a confident absence over incomplete evidence
- **verified-pass:** at least one matched workflow reaches medium-or-high confidence (an action slug or CLI pattern, not just a suggestive workflow name), or a Dependabot config exists with at least one `updates:` entry that sets a non-empty `package-ecosystem`

**Remediation:** Add a `.github/dependabot.yml` with at least one `updates:` entry, or add a workflow using a recognized SCA action/CLI (see mappings/scanner-signatures.yaml) — a workflow whose name merely suggests SCA isn't enough on its own; it needs a matched action/CLI invocation.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PW.4.4`:** Verify that acquired commercial, open-source, and all other third-party software components comply with the requirements, as defined by the organization, throughout their life cycles.
> **`RV.1.2`:** Review, analyze, and/or test the software's code to identify or confirm the presence of previously undetected vulnerabilities.

---

## C07.provenance

### `C07.provenance.commit-linkage`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PS.3.2` (practice `PS.3`: Archive and Protect Each Software Release)
- **CISA form cluster(s):** 3

#### azuredevops — Release artifacts are traceable to a build on the release commit

- **Token permission:** vso.build, vso.code
- **Fixture:** `internal/collect/azuredevops/provenance/provenance_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/refs`, `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/annotatedtags/{objectId}`, `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/commits/{commitId}`, `GET dev.azure.com/{org}/{project}/_apis/build/builds`

**Status rubric:**

- **verified-fail:** at least one release in the lookback window has zero builds on its commit within the bounded search window — builds are fetched from the oldest evaluated release's own date minus a fixed 90-day grace window, not an unbounded history (see Facts.builds_search_start for the exact bound this run applied), so an unusually large gap between a release tag and the build/commit it names could in principle still be missed
- **partial:** one or more release tags matching the configured pattern could not be dated (their commit is always already known straight from the refs listing itself — it's only the date lookup that failed; see the package doc comment for why this collector applies C05/C06's unconditional-dropped-tag rule here too); if that leaves nothing evaluable, the reason names the drop count directly and no release's build coverage was evaluated at all; otherwise every evaluated release is still traceable to a build on its commit, but the exclusion caps the result at partial
- **not-checkable:** the project's repositories or pipelines couldn't be read (403/other API error), the named repository wasn't found in the project, or resolving this repo's release tags failed (403/other API error) — collectRepo returns not-checkable for both evidence checks on the first such failure; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or no release tag matches the configured pattern within the lookback window, and none of the tags that did match were dropped as unresolvable either — genuinely nothing to evaluate; or the project's build history itself could not be fetched
- **verified-pass:** every release in the lookback window has at least one build whose sourceVersion equals the release's own resolved commit SHA, within the bounded build search window (see Facts.builds_search_start)

**Remediation:** Make sure the pipeline that produces release assets is triggered by (or runs on) the same commit being tagged — e.g. a tag-created trigger, or the same branch build release automation consumes — rather than run manually against an unrelated commit.

#### github — Release artifacts are traceable to a workflow run on the release commit

- **Token permission:** repo (classic) or Contents: read-only (fine-grained) — plus whatever fine-grained category gates git ref/tag reads and the attestations endpoint specifically, not independently verified against GitHub's docs (see C05's TokenScope for the same kind of hedge, and why)
- **Fixture:** `internal/collect/github/provenance/provenance_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/releases`, `GET /repos/{owner}/{repo}/git/ref/{ref}`, `GET /repos/{owner}/{repo}/git/tags/{tag_sha}`, `GET /repos/{owner}/{repo}/actions/runs?head_sha={sha}`

**Status rubric:**

- **verified-fail:** at least one resolved release in the lookback window has zero workflow runs on its commit
- **partial:** every release with a resolved commit is traceable to a workflow run on it, but at least one release's commit could not be resolved (tag resolution failed) or its run listing itself failed — unresolved, not a confirmed pass or fail
- **not-checkable:** the repo fetch, the workflow listing, or the release listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on the first such failure, since none of them can be computed without this shared evidence; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or no releases match the configured release tag pattern within the lookback window
- **verified-pass:** every release in the lookback window has at least one workflow run (any workflow, any conclusion) whose HeadSHA equals the release's resolved commit

**Remediation:** Make sure the workflow that produces release assets is triggered by the same commit being tagged/released — e.g. `on: release: types: [published]` or a tag-push trigger — rather than run manually (workflow_dispatch) against an unrelated commit.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PS.3.2`:** Collect, safeguard, maintain, and share provenance data for all components of each software release (e.g., in a software bill of materials [SBOM]).

---

### `C07.provenance.workflow`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PS.3.2` (practice `PS.3`: Archive and Protect Each Software Release)
- **CISA form cluster(s):** 3

#### azuredevops — A provenance-generating tool is configured

- **Token permission:** vso.build, vso.code (pipeline discovery and YAML fetch)
- **Fixture:** `internal/collect/azuredevops/provenance/provenance_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/git/repositories`, `GET dev.azure.com/{org}/{project}/_apis/pipelines`, `GET dev.azure.com/{org}/{project}/_apis/build/definitions/{definitionId}`, `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/items`

**Status rubric:**

- **verified-fail:** no provenance-generating tool of any confidence was detected in any pipeline, and every pipeline MatchPipelines inspected for this repo resolved cleanly (no same-repo skip) — a real absence, not an evidence gap
- **partial:** only a low-confidence (pipeline/step-name-only) match was found — not enough signal alone to confirm a provenance tool is genuinely configured
- **not-checkable:** the project's repositories or pipelines couldn't be read (403/other API error), the named repository wasn't found in the project, or resolving this repo's release tags failed (403/other API error) — collectRepo returns not-checkable for both evidence checks on the first such failure; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or one or more of this repo's own pipelines could not be fully inspected (a build-definition fetch failure, an unresolved YAML path, a YAML fetch/parse failure, or an unresolved template reference — see Facts.skipped_pipelines) and the evidence gathered would otherwise have produced verified-fail — this check applies the honest not-checkable fix rather than asserting a confident absence over incomplete evidence
- **verified-pass:** at least one matched pipeline reaches medium-or-high confidence (an ado_task or run-pattern match — e.g. a cosign sign/sign-blob/attest invocation — not just a suggestive pipeline/step name)

**Remediation:** Add a provenance-generating step to the pipeline: Sigstore/cosign (a `cosign sign`/`sign-blob`/`attest` invocation), or a SLSA provenance generator — see mappings/scanner-signatures.yaml for what this tool recognizes. No ADO-native attestation task exists, so a pipeline whose name merely suggests provenance (e.g. "SLSA") isn't enough on its own; it needs a matched run-pattern invocation to count as more than a low-confidence signal.

#### github — A provenance-generating tool is configured

- **Token permission:** repo (classic) or Contents: read-only (fine-grained) — plus whatever fine-grained category gates git ref/tag reads and the attestations endpoint specifically, not independently verified against GitHub's docs (see C05's TokenScope for the same kind of hedge, and why)
- **Fixture:** `internal/collect/github/provenance/provenance_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/actions/workflows`, `GET /repos/{owner}/{repo}/contents/{path}`

**Status rubric:**

- **verified-fail:** no provenance-generating tool of any confidence was detected in any workflow, and every workflow runhistory.MatchWorkflows inspected for this repo resolved cleanly (no same-repo skip) — a real absence, not an evidence gap
- **partial:** only a low-confidence (workflow-name-only) match was found — not enough signal alone to confirm a provenance tool is genuinely configured
- **not-checkable:** the repo fetch, the workflow listing, or the release listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on the first such failure, since none of them can be computed without this shared evidence; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or one or more of this repo's own workflows could not be fully inspected (a content-fetch failure, a decode failure, or a YAML parse failure — see Facts.skipped_workflows) and the evidence gathered would otherwise have produced verified-fail — this check applies the honest not-checkable fix rather than asserting a confident absence over incomplete evidence
- **verified-pass:** at least one matched workflow reaches medium-or-high confidence (an action slug or CLI pattern recognized as Sigstore/cosign, a SLSA generator, or GitHub Attestations — not just a suggestive workflow name)

**Remediation:** Add a provenance-generating step to the release workflow: Sigstore/cosign, a SLSA provenance generator (slsa-framework/slsa-github-generator), or GitHub's native `actions/attest-build-provenance` action.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PS.3.2`:** Collect, safeguard, maintain, and share provenance data for all components of each software release (e.g., in a software bill of materials [SBOM]).

---

### `C07.release.checksums`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PS.2.1` (practice `PS.2`: Provide a Mechanism for Verifying Software Release Integrity)
- **CISA form cluster(s):** 2

#### azuredevops — Releases ship checksum assets

- **Token permission:** none — this check makes no API call of its own; Azure DevOps has no release-asset concept to query (see its own doc comment)
- **Fixture:** `internal/collect/azuredevops/provenance/provenance_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — Azure DevOps has no release-asset concept the way GitHub Releases does; Azure Artifacts is a package registry, not a release-asset store, and is out of scope for this collector (issue #153's own C07 spec)

**Remediation:** No remediation applicable via this tool: Azure DevOps has no release-asset concept the way GitHub Releases does. Azure Artifacts is a package registry, not a release-asset store, and is out of scope for this collector (issue #153's own C07 spec). Document any real checksum-publishing practice (e.g. via Azure Artifacts or an external release process) in the self-attestation questionnaire instead.

#### github — Releases ship checksum assets

- **Token permission:** repo (classic) or Contents: read-only (fine-grained) — plus whatever fine-grained category gates git ref/tag reads and the attestations endpoint specifically, not independently verified against GitHub's docs (see C05's TokenScope for the same kind of hedge, and why)
- **Fixture:** `internal/collect/github/provenance/provenance_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/releases`

**Status rubric:**

- **verified-fail:** at least one release in the lookback window has no asset matching a known checksum-file naming convention
- **not-checkable:** the repo fetch, the workflow listing, or the release listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on the first such failure, since none of them can be computed without this shared evidence; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or no releases match the configured release tag pattern within the lookback window
- **verified-pass:** every release in the lookback window ships at least one asset matching a known checksum-file naming convention (checksums.txt, SHA256SUMS, or a per-file `.sha256`/`.sha256sum` sidecar)

**Remediation:** Publish a checksum file (e.g. `checksums.txt`/`SHA256SUMS`) as a release asset — most release-automation tools (e.g. goreleaser) generate this automatically as part of the release job.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PS.2.1`:** Make software integrity verification information available to software acquirers.

---

### `C07.release.signatures`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PS.2.1` (practice `PS.2`: Provide a Mechanism for Verifying Software Release Integrity), `PS.3.2` (practice `PS.3`: Archive and Protect Each Software Release)
- **CISA form cluster(s):** 2, 3

#### azuredevops — Releases ship signature or attestation assets

- **Token permission:** none — this check makes no API call of its own; Azure DevOps has no release-asset concept to query (see its own doc comment)
- **Fixture:** `internal/collect/azuredevops/provenance/provenance_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — Azure DevOps has no release-asset concept the way GitHub Releases does; Azure Artifacts is a package registry, not a release-asset store, and is out of scope for this collector (issue #153's own C07 spec)

**Remediation:** No remediation applicable via this tool: the same platform gap as C07.release.checksums applies — Azure DevOps has no release-asset concept for this collector to inspect signature/attestation assets against. Document any real signing practice in the self-attestation questionnaire instead.

#### github — Releases ship signature or attestation assets

- **Token permission:** repo (classic) or Contents: read-only (fine-grained) — plus whatever fine-grained category gates git ref/tag reads and the attestations endpoint specifically, not independently verified against GitHub's docs (see C05's TokenScope for the same kind of hedge, and why)
- **Fixture:** `internal/collect/github/provenance/provenance_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/releases`, `GET /repos/{owner}/{repo}/attestations/{subject_digest}`

**Status rubric:**

- **verified-fail:** at least one release in the lookback window has neither a matching signature/attestation asset nor a GitHub Artifact Attestation for any of its asset digests — every attestation lookup attempted for it completed cleanly with zero results
- **partial:** every release with confirmed evidence ships a matching asset or has a GitHub Artifact Attestation, but at least one release has no matching asset and its attestation lookup itself failed before confirming an absence — unresolved, not a confirmed absence (the digest that errored might well have an attestation)
- **not-checkable:** the repo fetch, the workflow listing, or the release listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on the first such failure, since none of them can be computed without this shared evidence; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or no releases match the configured release tag pattern within the lookback window
- **verified-pass:** every release in the lookback window ships an asset matching a known signature/attestation naming convention (`.sig`, `.pem`, `.intoto.jsonl`, `.sigstore`, `.bundle`), or has at least one GitHub Artifact Attestation found for one of its asset digests

**Remediation:** Attach a signature/attestation asset to each release (e.g. a cosign `.sig`/`.pem` bundle), or generate a GitHub Artifact Attestation for the release assets during the build workflow via `actions/attest-build-provenance`.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PS.2.1`:** Make software integrity verification information available to software acquirers.
> **`PS.3.2`:** Collect, safeguard, maintain, and share provenance data for all components of each software release (e.g., in a software bill of materials [SBOM]).

---

### `C07.release.tags-signed`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PS.2.1` (practice `PS.2`: Provide a Mechanism for Verifying Software Release Integrity)
- **CISA form cluster(s):** 2

#### azuredevops — Release tags are signed and their signature is verified

- **Token permission:** none — this check makes no API call of its own; Azure DevOps has no tag-signature-verification feature to query (see its own doc comment)
- **Fixture:** `internal/collect/azuredevops/provenance/provenance_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — Azure DevOps's GitAnnotatedTag exposes message/taggedBy/taggedObject and no signature or verification field of any kind; Azure DevOps does not verify tag signatures the way GitHub does — there is nothing this tool could ever call to confirm it, verified head-on against the GitAnnotatedTag reference

**Remediation:** No remediation applicable via this tool: Azure DevOps's GitAnnotatedTag (Git Annotated Tags - Get) exposes message/taggedBy/taggedObject and no signature or verification field of any kind, and Azure DevOps does not verify tag signatures the way GitHub does — there is nothing this tool could ever confirm here, regardless of whether tags are genuinely signed with git's own mechanisms. Document any real tag-signing practice in the self-attestation questionnaire instead.

#### github — Release tags are signed and GitHub reports the signature verified

- **Token permission:** repo (classic) or Contents: read-only (fine-grained) — plus whatever fine-grained category gates git ref/tag reads and the attestations endpoint specifically, not independently verified against GitHub's docs (see C05's TokenScope for the same kind of hedge, and why)
- **Fixture:** `internal/collect/github/provenance/provenance_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/releases`, `GET /repos/{owner}/{repo}/git/ref/{ref}`, `GET /repos/{owner}/{repo}/git/tags/{tag_sha}`

**Status rubric:**

- **verified-fail:** at least one resolved release tag in the lookback window is either a lightweight tag (which can never be signed — git's own object model only lets an annotated tag carry a signature) or an annotated tag that's unsigned or whose signature GitHub doesn't report as verified
- **partial:** every resolvable release tag in the lookback window is signed and verified, but at least one tag's resolution (Git.GetRef/Git.GetTag) itself failed — unresolved, not a confirmed pass or fail
- **not-checkable:** the repo fetch, the workflow listing, or the release listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on the first such failure, since none of them can be computed without this shared evidence; or the embedded scanner-signature registry itself failed to load (a binary-level failure, independent of the scanned repo); or no releases match the configured release tag pattern within the lookback window
- **verified-pass:** every release tag in the lookback window is annotated, signed, and GitHub reports its signature verified

**Remediation:** Sign release tags with a GPG or SSH key (`git tag -s` or `git tag -u <key> vX.Y.Z`), and register the matching public key under the tagging user's own account Settings -> SSH and GPG keys — add it specifically as a "Signing Key" (a key added only for authentication won't verify signatures). Signature verification is always tied to the individual tagger's personal account; there is no equivalent org-level key registration.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PS.2.1`:** Make software integrity verification information available to software acquirers.

---

## C08.actions-security

### `C08.actions.oidc-vs-secrets`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — Cloud deployments use workload identity federation or a managed identity, not long-lived static credentials

- **Token permission:** vso.serviceendpoint (Endpoints - Get Service Endpoints)
- **Fixture:** `internal/collect/azuredevops/pipelinesecurity/pipelinesecurity_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/serviceendpoint/endpoints?type=azurerm`

**Status rubric:**

- **verified-fail:** at least one azurerm service connection's authorization.scheme (case-insensitive) is serviceprincipal — Azure DevOps's own scheme name for a classic App Registration connection (client-secret- or certificate-backed; this collector doesn't distinguish the two — see the package doc comment), never OIDC/managed-identity
- **partial:** no connection uses a confirmed long-lived-credential scheme, but at least one reports a scheme this collector doesn't recognize as either modern or a known static-secret scheme (including a missing/nil authorization) — not confirmed either way
- **not-checkable:** the project's azurerm service connections couldn't be read (403/404/other API error); or no azurerm service connections exist in this project — nothing to evaluate
- **verified-pass:** every azurerm service connection's authorization.scheme (case-insensitive) is workloadidentityfederation or managedserviceidentity

**Remediation:** Convert each ServicePrincipal-scheme azurerm service connection to workload identity federation (Project Settings -> Service connections -> [connection] -> convert to workload identity federation) or a managed identity. If a connection's scheme isn't one this collector recognizes, review that connection's configuration directly.

#### github — Cloud deployments use OIDC rather than long-lived static credentials

- **Token permission:** repo (classic) or Contents: read-only (fine-grained) for workflow file content — plus Administration: read-only (fine-grained) for the repo default-workflow-permissions context fact, which this collector tolerates failing to read rather than treating as fatal; exact fine-grained category for that one unverified, see C05's TokenScope for the same kind of hedge
- **Fixture:** `internal/collect/github/actionssecurity/actionssecurity_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/actions/workflows`, `GET /repos/{owner}/{repo}/contents/{path}`

**Status rubric:**

- **verified-fail:** at least one detected cloud-deployment login step sets a recognized long-lived static-credential parameter (a static parameter always wins over an OIDC one if both are somehow present)
- **partial:** at least one detected cloud-deployment login step sets no recognized static-credential parameter, and doesn't set a complete OIDC parameter set either (for azure/login, setting only `client-id` or only `tenant-id` — not both — still counts as ambiguous here, not OIDC) — not confirmed either way; or no violation was found among the workflows successfully read, but one or more listed/referenced workflows could not be fetched or parsed — this result may be incomplete (see skipped_workflows)
- **not-checkable:** the repo fetch or the workflow listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on either failure, since none of them can be computed without this shared evidence; or no cloud-deployment login action (aws-actions/configure-aws-credentials, azure/login, or google-github-actions/auth) was found among the workflows successfully read — either because none exists there, or because one or more listed/referenced workflows couldn't be fetched or parsed at all (see skipped_workflows for which)
- **verified-pass:** every detected cloud-deployment login step (AWS/Azure/GCP's official login action) sets a recognized OIDC parameter — for azure/login specifically, BOTH `client-id` and `tenant-id` — and no recognized static-credential parameter; and every listed or referenced workflow was successfully fetched and parsed

**Remediation:** Configure the login action's OIDC parameters — for aws-actions/configure-aws-credentials use `role-to-assume` (with `permissions: id-token: write` on the job); for azure/login use `client-id`+`tenant-id`+`subscription-id` (also needs `permissions: id-token: write`); for google-github-actions/auth use `workload_identity_provider` (also needs `permissions: id-token: write`). If this replaces an existing long-lived static credential (verified-fail), delete it afterward from repo/org Settings -> Secrets and variables; if instead neither an OIDC nor a static-credential parameter was recognized at all (the "ambiguous" partial case), there's no existing secret to remove — just add the OIDC parameters above.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

### `C08.actions.pinned`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PW.4.1` (practice `PW.4`: Reuse Existing, Well-Secured Software When Feasible Instead of Duplicating Functionality)
- **CISA form cluster(s):** 2, 3

#### azuredevops — Pipeline tasks are pinned to an immutable version, not a floating major version

- **Token permission:** none — this check makes no API call of its own; Azure Pipelines has no task-SHA-pinning feature to query (see its own doc comment)
- **Fixture:** `internal/collect/azuredevops/pipelinesecurity/pipelinesecurity_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — Azure Pipelines resolves task references as Task@MajorVersion against org-installed task versions; there is no commit-SHA-pinning mechanism this tool could ever check for

**Remediation:** No remediation applicable via this tool: Azure Pipelines resolves task references as Task@MajorVersion against org-installed task versions — there is no commit-SHA-pinning mechanism to move to. If task-version drift is a concern, pin to a specific major version explicitly (never omit the @version suffix) and review org-installed task version updates through Azure DevOps' own task management.

#### github — Third-party actions and reusable workflows are pinned to a full commit SHA

- **Token permission:** repo (classic) or Contents: read-only (fine-grained) for workflow file content — plus Administration: read-only (fine-grained) for the repo default-workflow-permissions context fact, which this collector tolerates failing to read rather than treating as fatal; exact fine-grained category for that one unverified, see C05's TokenScope for the same kind of hedge
- **Fixture:** `internal/collect/github/actionssecurity/actionssecurity_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/actions/workflows`, `GET /repos/{owner}/{repo}/contents/{path}`

**Status rubric:**

- **verified-fail:** at least one third-party action or reusable-workflow reference is not pinned to a full 40-character commit SHA
- **partial:** every third-party reference is pinned to a full commit SHA, but at least one first-party `actions/*` reference uses a mutable tag instead; or no violation was found among the workflows successfully read, but one or more listed/referenced workflows could not be fetched or parsed — this result may be incomplete (see skipped_workflows)
- **not-checkable:** the repo fetch or the workflow listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on either failure, since none of them can be computed without this shared evidence; or no GitHub Actions workflow file could be fetched and parsed from the default branch — either none exist there, or GitHub listed one or more but every one failed to fetch or parse (see skipped_workflows for which and why)
- **verified-pass:** no external action or reusable-workflow reference exists at all, or every third-party reference (and every first-party `actions/*` reference) is pinned to a full 40-character commit SHA — and every listed or referenced workflow was successfully fetched and parsed (no skipped_workflows entries)

**Remediation:** Pin every third-party action/reusable-workflow `uses:` reference to a full 40-char commit SHA, not a tag or branch (e.g. `uses: actions/checkout@<full-sha> # v5.0.0` — keep the version as a comment for readability). A tool like `pin-github-action`/`pinact`, or Renovate's digest-pinning preset, can do this initial tag-to-SHA conversion (Dependabot cannot — it only keeps an already-pinned reference's version comment up to date going forward, via that same trailing comment). First-party `actions/*` references on a mutable tag are tolerated (capped at partial) but should be pinned too for a full pass.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PW.4.1`:** Acquire and maintain well-secured software components (e.g., software libraries, modules, middleware, frameworks) from commercial, open-source, and other third-party developers for use by the organization's software.

---

### `C08.actions.pull-request-target`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — No trigger combines base-pipeline privileges with untrusted fork checkout

- **Token permission:** none — this check makes no API call of its own; Azure Pipelines has no pull_request_target-equivalent trigger to query (see its own doc comment)
- **Fixture:** `internal/collect/azuredevops/pipelinesecurity/pipelinesecurity_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — Azure Pipelines has no trigger equivalent to GitHub's pull_request_target; see C08.pipelines.fork-protection for the adjacent real ADO control

**Remediation:** No remediation applicable via this tool: Azure Pipelines has no pull_request_target-equivalent trigger to reconfigure. If fork pull requests can trigger a privileged build at all, see C08.pipelines.fork-protection instead.

#### github — pull_request_target is not combined with checking out the PR head

- **Token permission:** repo (classic) or Contents: read-only (fine-grained) for workflow file content — plus Administration: read-only (fine-grained) for the repo default-workflow-permissions context fact, which this collector tolerates failing to read rather than treating as fatal; exact fine-grained category for that one unverified, see C05's TokenScope for the same kind of hedge
- **Fixture:** `internal/collect/github/actionssecurity/actionssecurity_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/actions/workflows`, `GET /repos/{owner}/{repo}/contents/{path}`

**Status rubric:**

- **verified-fail:** at least one `pull_request_target`-triggered workflow checks out the PR head commit/branch (an `actions/checkout` step whose `with.ref` references `github.event.pull_request.head.{sha,ref}` or the `github.head_ref` alias) — the classic "pwn request" pattern
- **partial:** `pull_request_target` is used, but no checkout of the PR head commit/branch was detected in any of its jobs — still a risky trigger by design, but no confirmed exploit pattern found; or no violation was found among the workflows successfully read, but one or more listed/referenced workflows could not be fetched or parsed — this result may be incomplete (see skipped_workflows)
- **not-checkable:** the repo fetch or the workflow listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on either failure, since none of them can be computed without this shared evidence; or no GitHub Actions workflow file could be fetched and parsed from the default branch — either none exist there, or GitHub listed one or more but every one failed to fetch or parse (see skipped_workflows for which and why)
- **verified-pass:** no workflow triggers on `pull_request_target` at all — and every listed or referenced workflow was successfully fetched and parsed

**Remediation:** Switch the trigger to `pull_request` if privileged (secrets/write token) access to the base repo isn't actually needed. If it genuinely is needed against fork code, use the two-workflow pattern instead: an untrusted `pull_request`-triggered workflow that uploads an artifact, and a separate, minimally-privileged `workflow_run`-triggered workflow that consumes it — either fully eliminates the pull_request_target trigger and reaches a pass. Just removing the `actions/checkout` step's PR-head ref (`github.event.pull_request.head.*` or `github.head_ref`) while keeping the pull_request_target trigger only demotes this from a fail to partial — pull_request_target itself is still flagged as risky by design.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

### `C08.actions.self-hosted`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — Self-hosted agent pools are not exposed to public-project pull requests

- **Token permission:** vso.build (Pipelines - List, Definitions - Get), vso.project (Projects - Get)
- **Fixture:** `internal/collect/azuredevops/pipelinesecurity/pipelinesecurity_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/pipelines`, `GET dev.azure.com/{org}/{project}/_apis/build/definitions/{definitionId}`, `GET dev.azure.com/{org}/_apis/projects/{project}`

**Status rubric:**

- **partial:** the project is public, and at least one build definition targets a non-hosted pool, and/or at least one definition's pool could not be resolved (queue or queue.pool was absent from its own Definitions - Get response) — a public contributor's pull request is a potential path to a self-hosted pool, or this collector can't confirm otherwise. This check has no verified-fail outcome: self-hosted-pool exposure on a public project is only ever capped at partial, by design, mirroring the GitHub twin's own identical choice
- **not-checkable:** the project's build definitions couldn't be listed or read (403/404/other API error), or the project's own visibility couldn't be read (403/404/other API error)
- **verified-pass:** the project has zero build definitions at all (a definitive enumeration, not an evidence gap — a deliberate divergence from the GitHub twin's own zero-workflow-evidence not-checkable; see the package doc comment); or the project is private (the public-fork attack vector this check flags doesn't apply, regardless of any definition's own pool); or the project is public, but every build definition resolved to a Microsoft-hosted pool

**Remediation:** Only moving affected build definitions to a Microsoft-hosted pool actually clears this check on a public project (it looks solely at queue.pool.isHosted, not at build-validation/branch- policy approval settings). Real-world exposure can also be reduced without changing this check's result: require approval for pull requests from non-team-members, or don't let those definitions build fork pull requests at all.

#### github — Self-hosted runners are not exposed to public-repo pull requests

- **Token permission:** repo (classic) or Contents: read-only (fine-grained) for workflow file content — plus Administration: read-only (fine-grained) for the repo default-workflow-permissions context fact, which this collector tolerates failing to read rather than treating as fatal; exact fine-grained category for that one unverified, see C05's TokenScope for the same kind of hedge
- **Fixture:** `internal/collect/github/actionssecurity/actionssecurity_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/actions/workflows`, `GET /repos/{owner}/{repo}/contents/{path}`

**Status rubric:**

- **partial:** one or more jobs use `runs-on: self-hosted` and the repository is public — an external contributor's pull request is a potential path to the runner; or no self-hosted usage was found among the workflows successfully read, but one or more listed/referenced workflows could not be fetched or parsed — this result may be incomplete. This check has no verified-fail outcome: self-hosted-runner usage is only ever capped at partial, by design, never a hard fail
- **not-checkable:** the repo fetch or the workflow listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on either failure, since none of them can be computed without this shared evidence; or no GitHub Actions workflow file could be fetched and parsed from the default branch — either none exist there, or GitHub listed one or more but every one failed to fetch or parse (see skipped_workflows for which and why)
- **verified-pass:** no job uses `runs-on: self-hosted` at all, and every listed or referenced workflow was successfully fetched and parsed; or one or more self-hosted usages ARE found but the repository is private (the public-fork attack vector this check flags doesn't apply) — that specific pass sub-case is unaffected by any skipped workflow, since a confirmed finding on a private repo can't be weakened by what else might be unread

**Remediation:** Only moving the job to a GitHub-hosted runner actually clears this check (it looks solely at whether `runs-on: self-hosted` appears, not at trigger/approval settings). Real-world exposure can also be reduced without changing this check's result: require approval for first-time/outside contributors (Settings -> Actions -> General -> "Approval for running fork pull request workflows from contributors"), or don't trigger the job on pull_request/pull_request_target from forks at all.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

### `C08.actions.token-permissions`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development), `PW.6.2` (practice `PW.6`: Configure the Compilation, Interpreter, and Build Processes to Improve Executable Security)
- **CISA form cluster(s):** 1, 2, 3, 4

#### azuredevops — Pipeline job tokens are scoped to least privilege

- **Token permission:** vso.project (General Settings - Get — verified against Microsoft's own REST reference, surprisingly not vso.build)
- **Fixture:** `internal/collect/azuredevops/pipelinesecurity/pipelinesecurity_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/build/generalsettings`

**Status rubric:**

- **verified-fail:** none of enforceJobAuthScope, enforceJobAuthScopeForReleases, or enforceReferencedRepoScopedToken is enabled
- **partial:** one or two, but not all three, of enforceJobAuthScope/enforceJobAuthScopeForReleases/enforceReferencedRepoScopedToken are enabled
- **not-checkable:** the project's pipeline general settings couldn't be read (403/404/other API error)
- **verified-pass:** enforceJobAuthScope, enforceJobAuthScopeForReleases, and enforceReferencedRepoScopedToken are all enabled

**Remediation:** Project Settings -> Pipelines -> Settings: enable "Limit job authorization scope to current project" for both build and release pipelines (enforceJobAuthScope, enforceJobAuthScopeForReleases), and the setting restricting pipelines to only repositories they explicitly reference (enforceReferencedRepoScopedToken).

#### github — Workflows declare explicit, least-privilege GITHUB_TOKEN permissions

- **Token permission:** repo (classic) or Contents: read-only (fine-grained) for workflow file content — plus Administration: read-only (fine-grained) for the repo default-workflow-permissions context fact, which this collector tolerates failing to read rather than treating as fatal; exact fine-grained category for that one unverified, see C05's TokenScope for the same kind of hedge
- **Fixture:** `internal/collect/github/actionssecurity/actionssecurity_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/actions/workflows`, `GET /repos/{owner}/{repo}/contents/{path}`

**Status rubric:**

- **verified-fail:** no job or workflow declares an explicit `permissions:` block at all — every job runs with the ambient default GITHUB_TOKEN permissions
- **partial:** some but not all jobs/workflows declare an explicit `permissions:` block; or every one does, but at least one is `write-all` rather than a scoped, least-privilege set; or no violation was found among the workflows successfully read, but one or more listed/referenced workflows could not be fetched or parsed — this result may be incomplete (see skipped_workflows)
- **not-checkable:** the repo fetch or the workflow listing failed (403/plan-gated/other API error) — collectRepo returns not-checkable for every check on either failure, since none of them can be computed without this shared evidence; or no GitHub Actions workflow file could be fetched and parsed from the default branch — either none exist there, or GitHub listed one or more but every one failed to fetch or parse (see skipped_workflows for which and why)
- **verified-pass:** every job (or its workflow, inherited when the job declares none of its own) declares an explicit `permissions:` block that isn't `write-all` — and every listed or referenced workflow was successfully fetched and parsed

**Remediation:** Add an explicit `permissions:` block — at workflow level, or per job for finer scoping — set to the minimum needed (e.g. `contents: read`), not the ambient default. Replace any `permissions: write-all` with a specific, scoped list of only the permissions that job actually needs.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.
> **`PW.6.2`:** Determine which compiler, interpreter, and build tool features should be used and how each should be configured, then implement and use the approved configurations.

---

### `C08.pipelines.fork-protection` — Fork pull request builds are protected from secret access and privilege escalation

- **Token permission:** vso.project (General Settings - Get — same call as C08.actions.token-permissions)
- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3
- **Fixture:** `internal/collect/azuredevops/pipelinesecurity/pipelinesecurity_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/build/generalsettings`

**Status rubric:**

- **verified-fail:** fork builds are enabled, and neither forkProtectionEnabled nor enforceNoAccessToSecretsFromForks is on — a fork's pull request can run pipeline jobs with no fork-specific protection at all (this collector's own interpretation of the zero-of-two case, not spelled out verbatim in issue #153 — see the package doc comment)
- **partial:** fork builds are enabled, and exactly one of forkProtectionEnabled/enforceNoAccessToSecretsFromForks is on — a mixed, partially-protected configuration
- **not-checkable:** the project's pipeline general settings couldn't be read (403/404/other API error)
- **verified-pass:** fork builds are disabled entirely (buildsEnabledForForks is false, the attack vector this check flags is absent), or fork builds are enabled and both forkProtectionEnabled and enforceNoAccessToSecretsFromForks are on

**Remediation:** Project Settings -> Pipelines -> Settings: either turn off builds from forked repositories entirely (buildsEnabledForForks), or turn on both fork-protection settings (forkProtectionEnabled and enforceNoAccessToSecretsFromForks) so a fork's pull request can't access secrets or escalate privilege during its build.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

## C09.audit-logging

### `C09.audit.log-streaming`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — Audit-log streaming to an external destination is enabled

- **Token permission:** vso.auditlog
- **Fixture:** `internal/collect/azuredevops/auditlogging/auditlogging_test.go`
- **API endpoint(s):** `GET auditservice.dev.azure.com/{org}/_apis/audit/streams`

**Status rubric:**

- **verified-fail:** GET .../_apis/audit/streams returned zero streams, or every returned stream's status is something other than "enabled" (disabledByUser, disabledBySystem, deleted, backfilling, or unknown)
- **not-checkable:** the call failed with a gated response (see azuredevops.IsAuditGated) — the org isn't Entra-backed, audit logging isn't enabled for it, or the token lacks the vso.auditlog scope — or another API error
- **verified-pass:** GET .../_apis/audit/streams returned at least one stream with status=="enabled" — unlike GitHub, where this check can only ever report not-checkable (audit-log streaming lives exclusively at the Enterprise-account level, a concept this tool has no notion of), Azure DevOps exposes streaming configuration at the organization level this tool already scans, making this a real, verifiable pass/fail here

**Remediation:** Organization Settings -> Auditing -> Streams -> Add stream, configure a supported consumer (Splunk, Azure Event Grid, Azure Monitor Logs, etc.), and confirm its status shows Enabled — a stream left Disabled by the system (e.g. after repeated delivery failures) or by a user still fails this check.

#### github — Audit-log export/streaming is configured

- **Token permission:** read:audit_log (classic OAuth/PAT scope) — the authenticated user must also be an organization owner; GitHub's docs don't distinguish a missing scope from a plan that doesn't include the Enterprise Cloud audit-log API in the response this collector sees, both surface identically (see C09.audit.org-log-available's Reason wording)
- **Fixture:** `internal/collect/github/auditlogging/auditlogging_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — audit-log streaming/export configuration exists exclusively at the GitHub Enterprise account level (`/enterprises/{enterprise}/audit-log/streams`), never the organization level; no org/repo-scoped endpoint exists for this tool to query, so this check can never reach any other status

**Remediation:** Not remediable via this tool's own checks: audit-log streaming/export only exists at the GitHub Enterprise account level (Enterprise Settings -> Audit log -> Log streaming), not the organization level, so this check can never verify it directly. If streaming is configured, document it in the self-attestation questionnaire (SA.audit-log-export-fallback) instead.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

### `C09.audit.org-log-available`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — Organization audit log is reachable via the API

- **Token permission:** vso.auditlog — the Audit Log API additionally requires the org to be Azure AD (Entra ID)-backed and the caller to have View-audit-log permission; Azure DevOps returns the same gated status whether the cause is missing scope, missing permission, or org type, so none of the three can be independently confirmed from this token alone (see this check's own Reason wording)
- **Fixture:** `internal/collect/azuredevops/auditlogging/auditlogging_test.go`
- **API endpoint(s):** `GET auditservice.dev.azure.com/{org}/_apis/audit/auditlog?batchSize=1`

**Status rubric:**

- **not-checkable:** the call failed with a gated response (see azuredevops.IsAuditGated) — one of three indistinguishable causes: the org isn't Azure AD (Entra ID)-backed, the org's "Log Audit Events" policy is off (off by default; the feature is in public preview), or the token lacks the vso.auditlog scope or the caller lacks View-audit-log permission — Azure DevOps returns the same status for all three, so this can't be told apart from the response alone — or another API error
- **verified-pass:** GET .../_apis/audit/auditlog?batchSize=1 succeeded — the endpoint is reachable; this check never inspects the returned entries themselves, only whether the call succeeded

**Remediation:** This check can only ever report verified-pass or not-checkable, never a fail — if it's not-checkable: confirm the organization is backed by Azure AD (Entra ID), not a Microsoft Account; have an Organization Administrator turn on Organization Settings -> Auditing -> "Log Audit Events" (off by default; the feature is in public preview); and use a PAT with the vso.auditlog scope from a user with View-audit-log permission.

#### github — Organization audit log is reachable via the API

- **Token permission:** read:audit_log (classic OAuth/PAT scope) — the authenticated user must also be an organization owner; GitHub's docs don't distinguish a missing scope from a plan that doesn't include the Enterprise Cloud audit-log API in the response this collector sees, both surface identically (see C09.audit.org-log-available's Reason wording)
- **Fixture:** `internal/collect/github/auditlogging/auditlogging_test.go`
- **API endpoint(s):** `GET /orgs/{org}/audit-log`

**Status rubric:**

- **not-checkable:** the call failed — a plan-gated response (402/404: the org's plan doesn't include GitHub Enterprise Cloud's audit-log API, or the token lacks the `read:audit_log` scope; GitHub returns the same status for both, so this can't be told apart from the response alone), a 403 (token lacks org-owner status or the `read:audit_log` scope), or another API error
- **verified-pass:** GET /orgs/{org}/audit-log succeeded — the endpoint is reachable; this check never inspects the returned entries themselves, only whether the call succeeded

**Remediation:** This check can only ever report verified-pass or not-checkable, never a fail — if it's not-checkable, either the org's plan doesn't include GitHub Enterprise Cloud's audit-log API, or the token isn't an org owner with the read:audit_log scope. Upgrading the plan or granting that scope is what would make this check verifiable.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

### `C09.audit.retention-awareness`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — Audit-log retention window (informational)

- **Token permission:** vso.auditlog (informational only — this check makes no API call of its own, see its own doc comment)
- **Fixture:** `internal/collect/azuredevops/auditlogging/auditlogging_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — this check is purely informational; no Azure DevOps API reports an org's actually-applied audit-log retention, so there is nothing to verify. Facts carry Azure DevOps's documented 90-day retention window as context only

**Remediation:** No remediation applicable — this check is purely informational (documents Azure DevOps's 90-day audit-log retention window) and never reports a fail. If longer retention is required, configure audit-log streaming (see C09.audit.log-streaming), Azure DevOps's documented mechanism for retention beyond 90 days.

#### github — Audit-log retention window (informational)

- **Token permission:** read:audit_log (classic OAuth/PAT scope) — the authenticated user must also be an organization owner; GitHub's docs don't distinguish a missing scope from a plan that doesn't include the Enterprise Cloud audit-log API in the response this collector sees, both surface identically (see C09.audit.org-log-available's Reason wording)
- **Fixture:** `internal/collect/github/auditlogging/auditlogging_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — this check is purely informational; no GitHub API reports an org's actually-applied audit-log retention, so there is nothing to verify. Facts carry GitHub's documented 180-day retention window as context only

**Remediation:** No remediation applicable — this check is purely informational (documents GitHub's 180-day audit-log retention window) and never reports a fail. If longer retention is required, configure audit-log export/streaming (see C09.audit.log-streaming) and document the destination and retention period in the self-attestation questionnaire.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

### `C09.repo.webhooks`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

#### azuredevops — A service hook subscription exports push/build events

- **Token permission:** vso.project (Projects - Get, to resolve the scanned project to its id) plus vso.build and/or vso.code (Subscriptions - List's own documented scopes are vso.work, vso.build, and vso.code; only vso.build/vso.code appear elsewhere in this epic's scope list — issue #34 — so vso.work isn't claimed as already-held here). All three named scopes are already part of this project's epic-wide ADO token-scope set, so this check needs nothing beyond that
- **Fixture:** `internal/collect/azuredevops/auditlogging/auditlogging_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/_apis/projects/{project}`, `GET dev.azure.com/{org}/_apis/hooks/subscriptions`

**Status rubric:**

- **verified-fail:** no enabled service hook subscription with eventType git.push or build.complete is scoped to this project (or to all projects) — includes the case where the org has zero subscriptions at all
- **not-checkable:** the scanned project couldn't be resolved to a project id, or the subscriptions-listing call itself failed (403/404/other API error)
- **verified-pass:** at least one enabled (status=="enabled", or status absent — Azure DevOps's own documented sample responses show several subscriptions omitting the field entirely, which this collector treats as the enum's default/enabled state) org-level service hook subscription has eventType git.push or build.complete, and its publisherInputs.projectId either matches the scanned project or is empty/absent (an all-projects subscription counts)

**Remediation:** Organization Settings -> Service Hooks -> Create subscription -> choose the "Code pushed" (git.push) or "Build completed" (build.complete) event, and scope it to (or leave unscoped, covering every project in) the project being scanned.

#### github — A webhook exports push/release/deployment events

- **Token permission:** repo (classic) or Webhooks: read-only (fine-grained) — exact fine-grained category not independently verified against GitHub's docs, see C05's TokenScope for the same kind of hedge
- **Fixture:** `internal/collect/github/auditlogging/auditlogging_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/hooks`

**Status rubric:**

- **verified-fail:** no active webhook on this repo subscribes to any of `push`, `release`, `deployment`, or the wildcard event — includes the case where the repo has zero webhooks at all (a definitive "no", not a gap). Scoped to per-repo webhooks only: a repo covered solely by an org-level webhook (a different, unevaluated endpoint) will still show fail here even though event export genuinely happens elsewhere
- **not-checkable:** the webhook-listing call itself failed (403/404/other API error)
- **verified-pass:** at least one active webhook on this repo subscribes to `push`, `release`, `deployment`, or the `*` wildcard event

**Remediation:** Repo Settings -> Webhooks -> Add webhook -> subscribe to at least Push, Release, and Deployment events (or the wildcard "Send me everything") pointing at your log/SIEM ingestion endpoint.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`PO.5.1`:** Separate and protect each environment involved in software development.

---

## C10.vdp

### `C10.vdp.intake-channel`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `RV.1.1` (practice `RV.1`: Identify and Confirm Vulnerabilities on an Ongoing Basis), `RV.1.3` (practice `RV.1`: Identify and Confirm Vulnerabilities on an Ongoing Basis)
- **CISA form cluster(s):** 2, 3, 4

#### azuredevops — SECURITY.md advertises an actionable intake channel

- **Token permission:** vso.code
- **Fixture:** `internal/collect/azuredevops/vdp/vdp_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/items`

**Status rubric:**

- **verified-fail:** no SECURITY.md exists to advertise an intake channel at all — shares C10.vdp.security-md's own fail condition, since there's nothing to inspect for a channel
- **partial:** SECURITY.md resolved, but neither intake-channel signal was found in its content — the file exists but doesn't tell a reporter how to actually reach the producer
- **not-checkable:** resolving SECURITY.md failed with a genuine API error — permission denied, a malformed response, or another failure; a plain 404 at one candidate path is never this cause, since that just means the next path is tried
- **verified-pass:** SECURITY.md resolved (see C10.vdp.security-md) and its content matches at least one of two signals: an email address or an http(s):// URL — narrower than the GitHub twin's three signals, since Azure DevOps has no private-vulnerability-reporting feature whose mention could count as a third (see C10.vdp.private-reporting)

**Remediation:** If no SECURITY.md exists at all, add one first (see C10.vdp.security-md). If it exists but this still fails, make the intake channel concrete and actionable: an email address, or a URL (e.g. a reporting form or bug-bounty page) — not just general prose like "we take security seriously."

#### github — SECURITY.md advertises an actionable intake channel

- **Token permission:** public_repo/repo (classic) or Contents: read-only (fine-grained) for SECURITY.md content — private-reporting additionally needs whatever category gates that endpoint; exact fine-grained category unverified, see C05's TokenScope for the same kind of hedge
- **Fixture:** `internal/collect/github/vdp/vdp_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/contents/{path}`

**Status rubric:**

- **verified-fail:** no SECURITY.md exists to advertise an intake channel at all — shares C10.vdp.security-md's own fail condition, since there's nothing to inspect for a channel
- **partial:** SECURITY.md resolved, but none of the three intake-channel signals were found in its content — the file exists but doesn't tell a reporter how to actually reach the producer
- **not-checkable:** resolving SECURITY.md failed with a genuine API error — permission denied, a file GitHub found but couldn't decode (e.g. an over-1MB file with `encoding: none`), or another failure; a plain 404 at any one candidate path is never this cause, since that just means the next path is tried
- **verified-pass:** SECURITY.md resolved (see C10.vdp.security-md) and its content matches at least one of three signals: an email address, an `http(s)://` URL, or a GitHub private-vulnerability-reporting mention

**Remediation:** If no SECURITY.md exists at all, add one first (see C10.vdp.security-md). If it exists but this still fails, make the intake channel concrete and actionable: an email address, a URL (e.g. a reporting form or bug-bounty page), or an explicit mention that reporters should use GitHub's private vulnerability reporting feature — not just general prose like "we take security seriously."

**SSDF task text (verbatim from NIST SP 800-218):**

> **`RV.1.1`:** Gather information from software acquirers, users, and public sources on potential vulnerabilities in the software and third-party components that the software uses, and investigate all credible reports.
> **`RV.1.3`:** Have a policy that addresses vulnerability disclosure and remediation, and implement the roles, responsibilities, and processes needed to support that policy.

---

### `C10.vdp.private-reporting`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `RV.1.1` (practice `RV.1`: Identify and Confirm Vulnerabilities on an Ongoing Basis)
- **CISA form cluster(s):** 2, 3, 4

#### azuredevops — A private-vulnerability-reporting mechanism is enabled

- **Token permission:** none — this check makes no API call of its own; Azure DevOps has no private-vulnerability-reporting feature to query (see its own doc comment)
- **Fixture:** `internal/collect/azuredevops/vdp/vdp_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — Azure DevOps has no private-vulnerability-reporting feature or API surface at all, unlike GitHub's dedicated feature and endpoint; there is nothing this tool could ever call to verify it

**Remediation:** No remediation applicable via this tool: Azure DevOps has no private-vulnerability-reporting feature or API surface at all, unlike GitHub's dedicated feature — there is nothing to enable. If the producer has an out-of-band private reporting channel (e.g. a security@ mailbox), advertise it in SECURITY.md (see C10.vdp.intake-channel) and/or document it in the self-attestation questionnaire.

#### github — GitHub private vulnerability reporting is enabled

- **Token permission:** public_repo/repo (classic) or Contents: read-only (fine-grained) for SECURITY.md content — private-reporting additionally needs whatever category gates that endpoint; exact fine-grained category unverified, see C05's TokenScope for the same kind of hedge
- **Fixture:** `internal/collect/github/vdp/vdp_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/private-vulnerability-reporting`

**Status rubric:**

- **verified-fail:** GET /repos/{owner}/{repo}/private-vulnerability-reporting succeeded and reports the feature not enabled
- **not-checkable:** the call failed — a plan-gated response (402/404; only the 404 case has been empirically observed, on private repos without GHAS — 402 is included on the strength of this codebase's general plan-gate predicate, not a separate observation of its own — and neither is confirmed against GitHub's own docs for this specific endpoint, which document only 200/422), a 403 (token lacks permission), or another error; never asserted as a confirmed "disabled" state
- **verified-pass:** GET /repos/{owner}/{repo}/private-vulnerability-reporting succeeded and reports the feature enabled

**Remediation:** Repo Settings -> Security -> Advanced Security -> enable "Private vulnerability reporting."

**SSDF task text (verbatim from NIST SP 800-218):**

> **`RV.1.1`:** Gather information from software acquirers, users, and public sources on potential vulnerabilities in the software and third-party components that the software uses, and investigate all credible reports.

---

### `C10.vdp.security-md`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `RV.1.3` (practice `RV.1`: Identify and Confirm Vulnerabilities on an Ongoing Basis)
- **CISA form cluster(s):** 4

#### azuredevops — A SECURITY.md resolves for this repo

- **Token permission:** vso.code
- **Fixture:** `internal/collect/azuredevops/vdp/vdp_test.go`
- **API endpoint(s):** `GET dev.azure.com/{org}/{project}/_apis/git/repositories/{repositoryId}/items`

**Status rubric:**

- **verified-fail:** no SECURITY.md resolved at either candidate path (/SECURITY.md or /docs/SECURITY.md) — includes the case where the repository itself doesn't exist or isn't visible to this token, which a 404 at both paths can't distinguish from a genuinely missing file
- **not-checkable:** resolving SECURITY.md failed with a genuine API error — permission denied, a malformed response, or another failure; a plain 404 at one candidate path is never this cause, since that just means the next path is tried
- **verified-pass:** SECURITY.md resolved at one of two candidate repo-content paths — /SECURITY.md (repo root) or /docs/SECURITY.md, tried in that order — a repo-content convention this collector checks for, not a platform-enforced one: Azure DevOps documents no community-health-file search order the way GitHub does, and has no org-wide-default mechanism to fall back to (see C10.vdp.security-policy-org)

**Remediation:** Add a SECURITY.md at the repo root or under docs/ describing how to report a vulnerability. Azure DevOps has no org-wide-default mechanism to add it to instead (see C10.vdp.security-policy-org) — it must live in this repo.

#### github — A SECURITY.md resolves for this repo

- **Token permission:** public_repo/repo (classic) or Contents: read-only (fine-grained) for SECURITY.md content — private-reporting additionally needs whatever category gates that endpoint; exact fine-grained category unverified, see C05's TokenScope for the same kind of hedge
- **Fixture:** `internal/collect/github/vdp/vdp_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}/contents/{path}`

**Status rubric:**

- **verified-fail:** no SECURITY.md was found at any of the six candidate locations (three paths × [this repo, the org's `.github` repo])
- **not-checkable:** resolving SECURITY.md failed with a genuine API error — permission denied, a file GitHub found but couldn't decode (e.g. an over-1MB file with `encoding: none`), or another failure; a plain 404 at any one candidate path is never this cause, since that just means the next path is tried
- **verified-pass:** a SECURITY.md resolved somewhere in GitHub's documented fallback chain (`.github/`, repo root, or `docs/`, tried in that order) — either in this repo directly, or in the org's own `.github` repo if this repo has none of its own

**Remediation:** Add a SECURITY.md at .github/SECURITY.md (or the repo root, or docs/) describing how to report a vulnerability. If most repos in the org should share one policy, add it to the org's own `.github` repo instead (see C10.vdp.security-policy-org) so it applies as the org-wide default for repos without their own.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`RV.1.3`:** Have a policy that addresses vulnerability disclosure and remediation, and implement the roles, responsibilities, and processes needed to support that policy.

---

### `C10.vdp.security-policy-org`

This check is registered under more than one platform — details for each below.

- **SSDF task(s):** `RV.1.3` (practice `RV.1`: Identify and Confirm Vulnerabilities on an Ongoing Basis)
- **CISA form cluster(s):** 4

#### azuredevops — The org has an org-wide default security policy

- **Token permission:** none — this check makes no API call of its own; Azure DevOps has no ".github"-repo-style org-default mechanism to query (see its own doc comment)
- **Fixture:** `internal/collect/azuredevops/vdp/vdp_test.go`
- **API endpoint(s):** none — this check's result is a fixed fact, not derived from an API call (see rubric below)

**Status rubric:**

- **not-checkable:** always — Azure DevOps has no ".github"-repo-style org-wide-default convention or mechanism; there is no project/repo this tool could check as a fallback the way GitHub's own ".github" special repo works

**Remediation:** No remediation applicable via this tool: Azure DevOps has no ".github"-repo-style org-wide-default mechanism — there is no project/repo this tool could check as a fallback. Add a SECURITY.md to each repo individually (see C10.vdp.security-md), or document an org-wide policy elsewhere and reference it in the self-attestation questionnaire.

#### github — The org has an org-wide default security policy

- **Token permission:** public_repo/repo (classic) or Contents: read-only (fine-grained), against the org's own ".github" repo if one exists
- **Fixture:** `internal/collect/github/vdp/vdp_test.go`
- **API endpoint(s):** `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/contents/{path}`

**Status rubric:**

- **verified-fail:** the org's `.github` repo exists, but no SECURITY.md resolved within it at any of the three candidate paths
- **not-checkable:** the org has no `.github` repo at all (a 404 on `GET /repos/{org}/.github` — no org-wide default mechanism exists, which most orgs never create and isn't itself a gap), or the repo-existence check itself failed for another reason, or resolving SECURITY.md within `.github` failed with a genuine API error
- **verified-pass:** the org's own `.github` repo exists and a SECURITY.md resolved within it (the same three-path fallback), serving as the org-wide default

**Remediation:** Add a SECURITY.md to the org's own `.github` repo (create the repo first if it doesn't exist) so it serves as the org-wide default security policy for every repo that doesn't have its own.

**SSDF task text (verbatim from NIST SP 800-218):**

> **`RV.1.3`:** Have a policy that addresses vulnerability disclosure and remediation, and implement the roles, responsibilities, and processes needed to support that policy.

---

## Self-Attestation Questions

These questions have no registered check metadata: nothing here is independently verified or
remediated by this tool. A producer's answer is always rendered as `self-attested` in scan
output — see each question's `pairing` field (not shown here; see
`mappings/self-attestation-questions.yaml`) for the API-verified checks it complements.

### `SA.agency-notification-process`

Does the producer have a defined process to notify any agency this form was submitted to if it ceases consistent use of the attested practices? (Paraphrases the CISA form's own closing commitment; see cisa-ssda-form.yaml's notify_on_cessation_clause for the verbatim text this question is asking the producer to substantiate.)

- **SSDF task(s):** (none cited)
- **CISA form cluster(s):** (none cited)

### `SA.audit-log-export-fallback`

If GitHub's own audit-log API or streaming isn't available (e.g. a non-Enterprise plan, or streaming being an Enterprise-account-only feature this tool can't query — see C09.audit.log-streaming), does the producer export or retain audit/access logs through another mechanism, and for how long?

- **SSDF task(s):** `PO.5.1` (practice `PO.5`: Implement and Maintain Secure Environments for Software Development)
- **CISA form cluster(s):** 1, 2, 3

### `SA.dev-security-training`

Do developers with access to the software's source code or build pipeline receive periodic security training?

- **SSDF task(s):** (none cited)
- **CISA form cluster(s):** (none cited)

### `SA.threat-modeling`

Is the software's design reviewed — by a qualified person not involved in that design, and/or an automated process — to confirm it meets security requirements and addresses identified risk before implementation?

- **SSDF task(s):** `PW.2.1` (practice `PW.2`: Review the Software Design to Verify Compliance with Security Requirements and Risk Information)
- **CISA form cluster(s):** 4

### `SA.vuln-remediation-sla`

What is the producer's target time to remediate a confirmed vulnerability, by severity?

- **SSDF task(s):** `RV.2.2` (practice `RV.2`: Assess, Prioritize, and Remediate Vulnerabilities)
- **CISA form cluster(s):** 4

### `SA.vuln-triage-sla`

What is the producer's target time to triage (assess the risk of) a newly reported vulnerability?

- **SSDF task(s):** `RV.2.1` (practice `RV.2`: Assess, Prioritize, and Remediate Vulnerabilities)
- **CISA form cluster(s):** 4

