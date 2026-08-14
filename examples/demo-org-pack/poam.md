# Plan of Action & Milestones (Draft)

This is a **draft** POA&M generated from `evidence.json`. Owner, target date, and
resources-required fields are placeholders for a human to fill in — this tool has
no authority to assign ownership, timelines, or budget. Every finding here traces
to a specific `verified-fail` or `partial` check result; see report.md for full
narrative context.

## Summary

- **Org:** Qloud-ltd-com
- **Scan window:** 2026-08-14 05:59:17 UTC – 2026-08-14 05:59:21 UTC
- **Total findings:** 44 (40 fail, 4 partial)

| Cluster | Fail | Partial | Total |
|---|---|---|---|
| 1. Secure development and build environments | 11 | 3 | 14 |
| 2. Trusted source code supply chain (good-faith effort) | 25 | 1 | 26 |
| 3. Provenance for internal and third-party code | 2 | 0 | 2 |
| 4. Automated vulnerability checking, pre-release, and disclosure program | 2 | 0 | 2 |

---

## Findings

### Cluster 1: Secure development and build environments

> The software is developed and built in secure environments. Those environments are secured by the following actions, at a minimum: a) Separating and protecting each environment involved in developing and building software; b) Regularly logging, monitoring, and auditing trust relationships used for authorization and access: i) to any software development and build environments; and ii) among components within each environment; c) Enforcing multi-factor authentication and conditional access across the environments relevant to developing and building software in a manner that minimizes security risk; d) Taking consistent and reasonable steps to document, as well as minimize use or inclusion of software products that create undue risk within the environments used to develop and build software; e) Encrypting sensitive data, such as credentials, to the extent practicable and based on risk; f) Implementing defensive cybersecurity practices, including continuous monitoring of operations and alerts and, as necessary, responding to suspected and confirmed cyber incidents.

#### POAM-001: Org requires two-factor authentication (C01.org.2fa-required) — [FAIL] Verified Fail

- **Scope:** (org-level)
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** org does not require two-factor authentication for members
- **Evidence:** GET /orgs/Qloud-ltd-com (digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)
- **Suggested remediation:** Org Settings -> Authentication security -> check "Require two-factor authentication for everyone in the [org] organization". Any member without 2FA enabled will be removed from the org when this is turned on, so resolve C01.org.members-without-2fa first.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-002: Production-like environments restrict which branches/tags can deploy (C03.env.branch-policy) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** environment(s) that allow deployment from any branch: \[production\]
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad/environments (digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)
- **Suggested remediation:** Open the production-like environment -> Settings -> Deployment branches and tags -> change from "No restriction" to "Protected branches only" or a "Selected branches and tags" allowlist.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-003: Production-like environments have at least one protection rule (C03.env.protection-rules) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** environment(s) with no protection rules: \[production\]
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad/environments (digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)
- **Suggested remediation:** Open the production-like environment -> Settings -> Deployment protection rules -> add at least one rule (required reviewers or a wait timer).
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-004: Production-like environments require reviewer approval before deployment (C03.env.required-reviewers) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** environment(s) without required reviewers: \[production\]
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad/environments (digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)
- **Suggested remediation:** Open the production-like environment -> Settings -> Deployment protection rules -> add "Required reviewers" and select who must approve a deployment.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-005: Org enables secret/dependency security features by default for new repos (C04.org.security-defaults) — [FAIL] Verified Fail

- **Scope:** (org-level)
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** not every security feature is enabled by default for new repositories
- **Evidence:** GET /orgs/Qloud-ltd-com (digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)
- **Suggested remediation:** Org Settings -> Code security -> enable secret scanning, push protection, Dependabot alerts, AND Advanced Security "for new repositories" — all four must be on for this check to pass — so every repo created going forward starts with them on, instead of relying on each repo owner to enable them individually.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-006: Secret scanning push protection is active (C04.secrets.push-protection) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** secret scanning push protection is not enabled (freely available on public repos)
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- **Suggested remediation:** Repo Settings -> Code security -> under Secret scanning, enable "Push protection" so commits containing a detected secret are blocked before they land.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-007: Secret scanning is active (C04.secrets.scanning-enabled) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** secret scanning is not enabled (freely available on public repos)
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- **Suggested remediation:** Repo Settings -> Code security -> enable "Secret scanning". Free for public repos; on a private repo it needs a GitHub Advanced Security license, or (since GitHub's 2025 GHAS unbundling) a standalone GitHub Secret Protection license.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-008: Cloud deployments use OIDC rather than long-lived static credentials (C08.actions.oidc-vs-secrets) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** 1 cloud-deployment login step(s) use long-lived static credentials instead of OIDC
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/actions/workflows (digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml (digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml (digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- **Suggested remediation:** Configure the login action's OIDC parameters — for aws-actions/configure-aws-credentials use `role-to-assume` (with `permissions: id-token: write` on the job); for azure/login use `client-id`+`tenant-id`+`subscription-id` (also needs `permissions: id-token: write`); for google-github-actions/auth use `workload_identity_provider` (also needs `permissions: id-token: write`). If this replaces an existing long-lived static credential (verified-fail), delete it afterward from repo/org Settings -> Secrets and variables; if instead neither an OIDC nor a static-credential parameter was recognized at all (the "ambiguous" partial case), there's no existing secret to remove — just add the OIDC parameters above.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-009: pull\_request\_target is not combined with checking out the PR head (C08.actions.pull-request-target) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** at least one pull\_request\_target workflow checks out the PR head commit/branch — this combination runs attacker-controlled code with base-repo secrets and token access
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/actions/workflows (digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml (digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml (digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- **Suggested remediation:** Switch the trigger to `pull_request` if privileged (secrets/write token) access to the base repo isn't actually needed. If it genuinely is needed against fork code, use the two-workflow pattern instead: an untrusted `pull_request`-triggered workflow that uploads an artifact, and a separate, minimally-privileged `workflow_run`-triggered workflow that consumes it — either fully eliminates the pull_request_target trigger and reaches a pass. Just removing the `actions/checkout` step's PR-head ref (`github.event.pull_request.head.*` or `github.head_ref`) while keeping the pull_request_target trigger only demotes this from a fail to partial — pull_request_target itself is still flagged as risky by design.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-010: Self-hosted runners are not exposed to public-repo pull requests (C08.actions.self-hosted) — [PARTIAL] Partial

- **Scope:** demo-bad
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** self-hosted runner(s) are used on a public repository — an external contributor's pull request is a potential path to them
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/actions/workflows (digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml (digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml (digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- **Suggested remediation:** Only moving the job to a GitHub-hosted runner actually clears this check (it looks solely at whether `runs-on: self-hosted` appears, not at trigger/approval settings). Real-world exposure can also be reduced without changing this check's result: require approval for first-time/outside contributors (Settings -> Actions -> General -> "Approval for running fork pull request workflows from contributors"), or don't trigger the job on pull_request/pull_request_target from forks at all.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-011: Workflows declare explicit, least-privilege GITHUB\_TOKEN permissions (C08.actions.token-permissions) — [PARTIAL] Partial

- **Scope:** demo-bad
- **Affected SSDF task(s):** PO.5.1, PW.6.2
- **CISA form cluster(s):** 1, 2, 3, 4
- **Description:** 1 of 2 job(s)/workflow(s) declare explicit permissions; the rest rely on the default GITHUB\_TOKEN permissions
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/actions/workflows (digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml (digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml (digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4); GET /repos/Qloud-ltd-com/demo-bad/actions/permissions/workflow (digest f6e178fc1e56cf43900da383f85398b61de9ae61c6b8433116c1856605745924)
- **Suggested remediation:** Add an explicit `permissions:` block — at workflow level, or per job for finer scoping — set to the minimum needed (e.g. `contents: read`), not the ambient default. Replace any `permissions: write-all` with a specific, scoped list of only the permissions that job actually needs.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-012: Workflows declare explicit, least-privilege GITHUB\_TOKEN permissions (C08.actions.token-permissions) — [PARTIAL] Partial

- **Scope:** demo-good
- **Affected SSDF task(s):** PO.5.1, PW.6.2
- **CISA form cluster(s):** 1, 2, 3, 4
- **Description:** 1 of 2 job(s)/workflow(s) declare explicit permissions; the rest rely on the default GITHUB\_TOKEN permissions
- **Evidence:** GET /repos/Qloud-ltd-com/demo-good (digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d); GET /repos/Qloud-ltd-com/demo-good/actions/workflows (digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a); GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml (digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b); GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml (digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865); GET /repos/Qloud-ltd-com/demo-good/actions/permissions/workflow (digest f6e178fc1e56cf43900da383f85398b61de9ae61c6b8433116c1856605745924)
- **Suggested remediation:** Add an explicit `permissions:` block — at workflow level, or per job for finer scoping — set to the minimum needed (e.g. `contents: read`), not the ambient default. Replace any `permissions: write-all` with a specific, scoped list of only the permissions that job actually needs.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-013: A webhook exports push/release/deployment events (C09.repo.webhooks) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** no active webhook subscribes to push, release, or deployment events
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad/hooks (digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)
- **Suggested remediation:** Repo Settings -> Webhooks -> Add webhook -> subscribe to at least Push, Release, and Deployment events (or the wildcard "Send me everything") pointing at your log/SIEM ingestion endpoint.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-014: A webhook exports push/release/deployment events (C09.repo.webhooks) — [FAIL] Verified Fail

- **Scope:** demo-good
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** no active webhook subscribes to push, release, or deployment events
- **Evidence:** GET /repos/Qloud-ltd-com/demo-good/hooks (digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)
- **Suggested remediation:** Repo Settings -> Webhooks -> Add webhook -> subscribe to at least Push, Release, and Deployment events (or the wildcard "Send me everything") pointing at your log/SIEM ingestion endpoint.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

### Cluster 2: Trusted source code supply chain (good-faith effort)

> The software producer makes a good-faith effort to maintain trusted source code supply chains by employing automated tools or comparable processes to address the security of internal code and third-party components and manage related vulnerabilities.

#### POAM-015: Whether members can create public repositories (C01.org.members-can-create-public) — [FAIL] Verified Fail

- **Scope:** (org-level)
- **Affected SSDF task(s):** PS.1.1
- **CISA form cluster(s):** 2, 4
- **Description:** members can create public repositories (potential leak vector)
- **Evidence:** GET /orgs/Qloud-ltd-com (digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)
- **Suggested remediation:** Org Settings -> Member privileges -> Repository creation -> uncheck "Public" so members can't create public repositories without an explicit visibility change reviewed separately.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-016: Default branch protections apply to admins (no unconditional bypass actor) (C02.branch.admin-enforced) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PS.1.1
- **CISA form cluster(s):** 2, 4
- **Description:** default branch protections do not apply to admins
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection (digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d); GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main (digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)
- **Suggested remediation:** For a ruleset, set Enforcement status to "Active" (not "Evaluate") and remove every bypass actor entirely — even one scoped to "Pull request only" caps this check at partial, not a full pass. For legacy branch protection, check "Do not allow bypassing the above settings" (Include administrators). Where both legacy protection and a ruleset apply to the same branch, both must independently bind admins for this check to pass.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-017: Default branch blocks branch deletion (C02.branch.deletion-blocked) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PS.1.1
- **CISA form cluster(s):** 2, 4
- **Description:** default branch allows deletion
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection (digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d); GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main (digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)
- **Suggested remediation:** In a ruleset, enable "Restrict deletions"; in legacy branch protection, leave "Allow deletions" unchecked.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-018: Default branch blocks force pushes (C02.branch.force-push-blocked) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PS.1.1
- **CISA form cluster(s):** 2, 4
- **Description:** default branch allows force pushes
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection (digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d); GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main (digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)
- **Suggested remediation:** In a ruleset, enable "Block force pushes"; in legacy branch protection, leave "Allow force pushes" unchecked.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-019: Default branch has protection (legacy branch protection or a ruleset) (C02.branch.protection-exists) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PS.1.1
- **CISA form cluster(s):** 2, 4
- **Description:** default branch has no legacy branch protection and no ruleset applies to it
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection (digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d); GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main (digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)
- **Suggested remediation:** Repo Settings -> Rules -> Rulesets (or the legacy Settings -> Branches -> Branch protection rules) -> add a rule targeting the default branch.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-020: Default branch requires at least one approving review before merge (C02.branch.required-reviews) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PS.1.1
- **CISA form cluster(s):** 2, 4
- **Description:** default branch does not require an approving review before merge
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection (digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d); GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main (digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)
- **Suggested remediation:** In that ruleset/protection rule, enable "Require a pull request before merging" with at least 1 required approving review, and leave legacy branch protection's "Allow specified actors to bypass required pull requests" empty — or remove any users/teams/apps already listed there.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-021: Default branch requires status checks before merge (C02.branch.required-status-checks) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PS.1.1
- **CISA form cluster(s):** 2, 4
- **Description:** default branch does not require any status checks before merge
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection (digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d); GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main (digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)
- **Suggested remediation:** In that ruleset/protection rule, enable "Require status checks to pass before merging" and select the CI checks that must pass.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-022: Dependabot vulnerability alerts are enabled (C04.deps.dependabot-alerts) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PW.4.4
- **CISA form cluster(s):** 2, 3, 4
- **Description:** Dependabot vulnerability alerts are not enabled
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad/vulnerability-alerts (digest 9823ff5229a049b085025a16d246d1aef8fe4df5f4e335238a1d33b2b0874967)
- **Suggested remediation:** Repo Settings -> Code security -> enable "Dependabot alerts".
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-023: CodeQL default setup is configured (C05.sast.default-setup) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PW.7.1, RV.1.2
- **CISA form cluster(s):** 2, 3, 4
- **Description:** CodeQL default setup is "not-configured"
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad/code-scanning/default-setup (digest 42357385cf151d57ee6a21d7399ad340616105dc9c88108071663c7657ae66ad)
- **Suggested remediation:** Repo Settings -> Security -> Advanced Security -> under Code Security, "CodeQL analysis" -> Set up -> Default (choose "Default", not "Advanced", unless a custom workflow is specifically needed).
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-024: CodeQL default setup is configured (C05.sast.default-setup) — [FAIL] Verified Fail

- **Scope:** demo-good
- **Affected SSDF task(s):** PW.7.1, RV.1.2
- **CISA form cluster(s):** 2, 3, 4
- **Description:** CodeQL default setup is "not-configured"
- **Evidence:** GET /repos/Qloud-ltd-com/demo-good/code-scanning/default-setup (digest 42357385cf151d57ee6a21d7399ad340616105dc9c88108071663c7657ae66ad)
- **Suggested remediation:** Repo Settings -> Security -> Advanced Security -> under Code Security, "CodeQL analysis" -> Set up -> Default (choose "Default", not "Advanced", unless a custom workflow is specifically needed).
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-025: A SAST tool is configured (C05.sast.tool-configured) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PW.7.1, RV.1.2
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no SAST tool detected in any workflow, and CodeQL default setup is not configured
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/actions/workflows (digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml (digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml (digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4); GET /repos/Qloud-ltd-com/demo-bad/releases (digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)
- **Suggested remediation:** Enable CodeQL default setup (repo Settings -> Security -> Advanced Security -> under Code Security, "CodeQL analysis" -> Set up -> Default), or add a workflow using a recognized SAST action/CLI (see mappings/scanner-signatures.yaml for what this tool recognizes) — a workflow whose name merely suggests SAST isn't enough on its own; it needs a matched action/CLI invocation to count as more than a low-confidence signal.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-026: A SAST tool is configured (C05.sast.tool-configured) — [FAIL] Verified Fail

- **Scope:** demo-good
- **Affected SSDF task(s):** PW.7.1, RV.1.2
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no SAST tool detected in any workflow, and CodeQL default setup is not configured
- **Evidence:** GET /repos/Qloud-ltd-com/demo-good (digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d); GET /repos/Qloud-ltd-com/demo-good/actions/workflows (digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a); GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml (digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b); GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml (digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865); GET /repos/Qloud-ltd-com/demo-good/releases (digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161); GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 (digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a); GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 (digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)
- **Suggested remediation:** Enable CodeQL default setup (repo Settings -> Security -> Advanced Security -> under Code Security, "CodeQL analysis" -> Set up -> Default), or add a workflow using a recognized SAST action/CLI (see mappings/scanner-signatures.yaml for what this tool recognizes) — a workflow whose name merely suggests SAST isn't enough on its own; it needs a matched action/CLI invocation to count as more than a low-confidence signal.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-027: Open Dependabot alerts are triaged within the default window (C06.sca.alerts-triaged) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PW.4.4, RV.2.1
- **CISA form cluster(s):** 2, 3, 4
- **Description:** Dependabot alerts are not enabled for this repository
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad/dependabot/alerts (digest c1beac3c35f574fcd0f58fc959d11e4a464a9974a02f0c4c0c0afb16b45dda5a)
- **Suggested remediation:** If Dependabot alerts are disabled entirely, enable them first: repo Settings -> Code security -> enable "Dependabot alerts" (see C04.deps.dependabot-alerts). Once enabled, triage: Security -> Dependabot alerts -> filter by Critical severity -> fix or dismiss (with a documented reason) any critical alert open longer than 30 days.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-028: Dependabot config covers the repo's detected dependency ecosystems (C06.sca.dependabot-config) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PW.4.4
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no Dependabot config found; 1 detected ecosystem(s) are uncovered
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad/contents/ (digest d89bb027c06e65a8d878a29d4ff725c7a25da56aead63c3fefef6ad5cb9ad313); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yml (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yaml (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- **Suggested remediation:** Extend `.github/dependabot.yml` with an `updates:` entry for each detected-but-uncovered ecosystem (see this finding's `uncovered_ecosystems` fact for exactly which ones).
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-029: Dependabot config covers the repo's detected dependency ecosystems (C06.sca.dependabot-config) — [FAIL] Verified Fail

- **Scope:** demo-good
- **Affected SSDF task(s):** PW.4.4
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no Dependabot config found; 1 detected ecosystem(s) are uncovered
- **Evidence:** GET /repos/Qloud-ltd-com/demo-good/contents/ (digest 6d37f7c4f592d43db39aa75eb69666c1c376dee2ed272a5c3a3ea8505eac1ab5); GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yml (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yaml (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- **Suggested remediation:** Extend `.github/dependabot.yml` with an `updates:` entry for each detected-but-uncovered ecosystem (see this finding's `uncovered_ecosystems` fact for exactly which ones).
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-030: Dependency review is enforced as a required check on pull requests (C06.sca.dependency-review) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PW.4.4
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no dependency-review-action (or equivalent) workflow detected
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/actions/workflows (digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml (digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml (digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4); GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection (digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d); GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main (digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)
- **Suggested remediation:** Add a workflow using `actions/dependency-review-action` (or equivalent), make sure it triggers on `pull_request` (not just push), and add it as a required status check: repo Settings -> Rules -> Rulesets -> the branch's rule -> Require status checks to pass -> select the dependency-review workflow's check.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-031: Dependency review is enforced as a required check on pull requests (C06.sca.dependency-review) — [FAIL] Verified Fail

- **Scope:** demo-good
- **Affected SSDF task(s):** PW.4.4
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no dependency-review-action (or equivalent) workflow detected
- **Evidence:** GET /repos/Qloud-ltd-com/demo-good (digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d); GET /repos/Qloud-ltd-com/demo-good/actions/workflows (digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a); GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml (digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b); GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml (digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865); GET /repos/Qloud-ltd-com/demo-good/branches/main/protection (digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3); GET /repos/Qloud-ltd-com/demo-good/rules/branches/main (digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)
- **Suggested remediation:** Add a workflow using `actions/dependency-review-action` (or equivalent), make sure it triggers on `pull_request` (not just push), and add it as a required status check: repo Settings -> Rules -> Rulesets -> the branch's rule -> Require status checks to pass -> select the dependency-review workflow's check.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-032: An SCA tool ran for each release in the lookback window (C06.sca.ran-per-release) — [FAIL] Verified Fail

- **Scope:** demo-good
- **Affected SSDF task(s):** PW.4.4, RV.1.2
- **CISA form cluster(s):** 2, 3, 4
- **Description:** at least one release in the lookback window has no matched SCA run at all
- **Evidence:** GET /repos/Qloud-ltd-com/demo-good (digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d); GET /repos/Qloud-ltd-com/demo-good/actions/workflows (digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a); GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml (digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b); GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml (digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865); GET /repos/Qloud-ltd-com/demo-good/releases (digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161); GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 (digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a); GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 (digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)
- **Suggested remediation:** Applies to a workflow-based SCA tool specifically (Dependabot has no per-release run history to check). Make sure the SCA workflow's trigger fires on the commit each release is cut from, and that any run that fired completed successfully.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-033: An SCA tool is configured (C06.sca.tool-configured) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PW.4.4, RV.1.2
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no SCA tool detected in any workflow, and no Dependabot config found
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/actions/workflows (digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml (digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml (digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yml (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yaml (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- **Suggested remediation:** Add a `.github/dependabot.yml` with at least one `updates:` entry, or add a workflow using a recognized SCA action/CLI (see mappings/scanner-signatures.yaml) — a workflow whose name merely suggests SCA isn't enough on its own; it needs a matched action/CLI invocation.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-034: An SCA tool is configured (C06.sca.tool-configured) — [FAIL] Verified Fail

- **Scope:** demo-good
- **Affected SSDF task(s):** PW.4.4, RV.1.2
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no SCA tool detected in any workflow, and no Dependabot config found
- **Evidence:** GET /repos/Qloud-ltd-com/demo-good (digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d); GET /repos/Qloud-ltd-com/demo-good/actions/workflows (digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a); GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml (digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b); GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml (digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865); GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yml (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yaml (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- **Suggested remediation:** Add a `.github/dependabot.yml` with at least one `updates:` entry, or add a workflow using a recognized SCA action/CLI (see mappings/scanner-signatures.yaml) — a workflow whose name merely suggests SCA isn't enough on its own; it needs a matched action/CLI invocation.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-035: Third-party actions and reusable workflows are pinned to a full commit SHA (C08.actions.pinned) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PW.4.1
- **CISA form cluster(s):** 2, 3
- **Description:** 2 third-party action/reusable-workflow reference(s) are not pinned to a full-length commit SHA
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/actions/workflows (digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml (digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml (digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- **Suggested remediation:** Pin every third-party action/reusable-workflow `uses:` reference to a full 40-char commit SHA, not a tag or branch (e.g. `uses: actions/checkout@<full-sha> # v5.0.0` — keep the version as a comment for readability). A tool like `pin-github-action`/`pinact`, or Renovate's digest-pinning preset, can do this initial tag-to-SHA conversion (Dependabot cannot — it only keeps an already-pinned reference's version comment up to date going forward, via that same trailing comment). First-party `actions/*` references on a mutable tag are tolerated (capped at partial) but should be pinned too for a full pass.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-036: Third-party actions and reusable workflows are pinned to a full commit SHA (C08.actions.pinned) — [PARTIAL] Partial

- **Scope:** demo-good
- **Affected SSDF task(s):** PW.4.1
- **CISA form cluster(s):** 2, 3
- **Description:** every third-party reference is SHA-pinned, but 1 first-party actions/\* reference(s) use a mutable tag instead of a SHA
- **Evidence:** GET /repos/Qloud-ltd-com/demo-good (digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d); GET /repos/Qloud-ltd-com/demo-good/actions/workflows (digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a); GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml (digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b); GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml (digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- **Suggested remediation:** Pin every third-party action/reusable-workflow `uses:` reference to a full 40-char commit SHA, not a tag or branch (e.g. `uses: actions/checkout@<full-sha> # v5.0.0` — keep the version as a comment for readability). A tool like `pin-github-action`/`pinact`, or Renovate's digest-pinning preset, can do this initial tag-to-SHA conversion (Dependabot cannot — it only keeps an already-pinned reference's version comment up to date going forward, via that same trailing comment). First-party `actions/*` references on a mutable tag are tolerated (capped at partial) but should be pinned too for a full pass.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-037: SECURITY.md advertises an actionable intake channel (C10.vdp.intake-channel) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** RV.1.1, RV.1.3
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no SECURITY.md exists to advertise an intake channel
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad/contents/.github/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/demo-bad/contents/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/demo-bad/contents/docs/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/.github/contents/.github/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/.github/contents/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/.github/contents/docs/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- **Suggested remediation:** If no SECURITY.md exists at all, add one first (see C10.vdp.security-md). If it exists but this still fails, make the intake channel concrete and actionable: an email address, a URL (e.g. a reporting form or bug-bounty page), or an explicit mention that reporters should use GitHub's private vulnerability reporting feature — not just general prose like "we take security seriously."
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-038: SECURITY.md advertises an actionable intake channel (C10.vdp.intake-channel) — [FAIL] Verified Fail

- **Scope:** demo-good
- **Affected SSDF task(s):** RV.1.1, RV.1.3
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no SECURITY.md exists to advertise an intake channel
- **Evidence:** GET /repos/Qloud-ltd-com/demo-good/contents/.github/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/demo-good/contents/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/demo-good/contents/docs/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/.github/contents/.github/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/.github/contents/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/.github/contents/docs/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- **Suggested remediation:** If no SECURITY.md exists at all, add one first (see C10.vdp.security-md). If it exists but this still fails, make the intake channel concrete and actionable: an email address, a URL (e.g. a reporting form or bug-bounty page), or an explicit mention that reporters should use GitHub's private vulnerability reporting feature — not just general prose like "we take security seriously."
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-039: GitHub private vulnerability reporting is enabled (C10.vdp.private-reporting) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** RV.1.1
- **CISA form cluster(s):** 2, 3, 4
- **Description:** private vulnerability reporting is not enabled
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad/private-vulnerability-reporting (digest 5acf3ff77b4420677b5923071f303facaba7a9273a346284a667a275df325146)
- **Suggested remediation:** Repo Settings -> Security -> Advanced Security -> enable "Private vulnerability reporting."
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-040: GitHub private vulnerability reporting is enabled (C10.vdp.private-reporting) — [FAIL] Verified Fail

- **Scope:** demo-good
- **Affected SSDF task(s):** RV.1.1
- **CISA form cluster(s):** 2, 3, 4
- **Description:** private vulnerability reporting is not enabled
- **Evidence:** GET /repos/Qloud-ltd-com/demo-good/private-vulnerability-reporting (digest 5acf3ff77b4420677b5923071f303facaba7a9273a346284a667a275df325146)
- **Suggested remediation:** Repo Settings -> Security -> Advanced Security -> enable "Private vulnerability reporting."
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

### Cluster 3: Provenance for internal and third-party code

> The software producer maintains provenance for internal code and third-party components incorporated into the software to the greatest extent feasible.

#### POAM-041: A SAST tool ran for each release in the lookback window (C05.sast.ran-per-release) — [FAIL] Verified Fail

- **Scope:** demo-good
- **Affected SSDF task(s):** PW.7.2, RV.1.2
- **CISA form cluster(s):** 3, 4
- **Description:** at least one release in the lookback window has no matched SAST run at all
- **Evidence:** GET /repos/Qloud-ltd-com/demo-good (digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d); GET /repos/Qloud-ltd-com/demo-good/actions/workflows (digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a); GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml (digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b); GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml (digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865); GET /repos/Qloud-ltd-com/demo-good/releases (digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161); GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 (digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a); GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 (digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)
- **Suggested remediation:** Make sure the SAST workflow's trigger actually fires on (or before) the commit each release is cut from — e.g. trigger on push to the release branch, or on the release event itself — and that any run that did fire completed successfully rather than erroring out.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-042: A provenance-generating tool is configured (C07.provenance.workflow) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** PS.3.2
- **CISA form cluster(s):** 3
- **Description:** no provenance-generating tool (Sigstore/cosign, SLSA generator, or GitHub Attestations) detected in any workflow
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad (digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0); GET /repos/Qloud-ltd-com/demo-bad/actions/workflows (digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml (digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b); GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml (digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- **Suggested remediation:** Add a provenance-generating step to the release workflow: Sigstore/cosign, a SLSA provenance generator (slsa-framework/slsa-github-generator), or GitHub's native `actions/attest-build-provenance` action.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

### Cluster 4: Automated vulnerability checking, pre-release, and disclosure program

> The software producer employs automated tools or comparable processes that check for security vulnerabilities. In addition: a) The software producer operates these processes on an ongoing basis and prior to product, version, or update releases; b) The software producer has a policy or process to address discovered security vulnerabilities prior to product release; and c) The software producer operates a vulnerability disclosure program and accepts, reviews, and addresses disclosed software vulnerabilities in a timely fashion and according to any timelines specified in the vulnerability disclosure program or applicable policies.

#### POAM-043: A SECURITY.md resolves for this repo (C10.vdp.security-md) — [FAIL] Verified Fail

- **Scope:** demo-bad
- **Affected SSDF task(s):** RV.1.3
- **CISA form cluster(s):** 4
- **Description:** no SECURITY.md found at any of the standard locations (.github/, repo root, docs/) in this repo or the org's .github repo
- **Evidence:** GET /repos/Qloud-ltd-com/demo-bad/contents/.github/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/demo-bad/contents/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/demo-bad/contents/docs/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/.github/contents/.github/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/.github/contents/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/.github/contents/docs/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- **Suggested remediation:** Add a SECURITY.md at .github/SECURITY.md (or the repo root, or docs/) describing how to report a vulnerability. If most repos in the org should share one policy, add it to the org's own `.github` repo instead (see C10.vdp.security-policy-org) so it applies as the org-wide default for repos without their own.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-044: A SECURITY.md resolves for this repo (C10.vdp.security-md) — [FAIL] Verified Fail

- **Scope:** demo-good
- **Affected SSDF task(s):** RV.1.3
- **CISA form cluster(s):** 4
- **Description:** no SECURITY.md found at any of the standard locations (.github/, repo root, docs/) in this repo or the org's .github repo
- **Evidence:** GET /repos/Qloud-ltd-com/demo-good/contents/.github/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/demo-good/contents/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/demo-good/contents/docs/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/.github/contents/.github/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/.github/contents/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-ltd-com/.github/contents/docs/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- **Suggested remediation:** Add a SECURITY.md at .github/SECURITY.md (or the repo root, or docs/) describing how to report a vulnerability. If most repos in the org should share one policy, add it to the org's own `.github` repo instead (see C10.vdp.security-policy-org) so it applies as the org-wide default for repos without their own.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

---

## Requires Attention Outside This Tool

Self-attested and not-checkable items are **not** POA&M findings — a self-attested
answer is the producer's own claim, not independently verified, and a not-checkable
result means this tool structurally could not determine an answer (plan-gated,
insufficient token permission, or an unanswered self-attestation question). Neither
is a confirmed gap, but both may need a human's attention outside this document.

- C04.secrets.advanced-security (Not Checkable) on demo-bad: not applicable to public repositories (GHAS licensing only gates private-repo features)
- C04.secrets.advanced-security (Not Checkable) on demo-good: not applicable to public repositories (GHAS licensing only gates private-repo features)
- C05.sast.cadence (Not Checkable) on demo-bad: no SAST tool is configured; cadence cannot be computed
- C05.sast.cadence (Not Checkable) on demo-good: no SAST tool is configured; cadence cannot be computed
- C05.sast.ran-per-release (Not Checkable) on demo-bad: no releases match the configured release tag pattern within the lookback window
- C06.sca.ran-per-release (Not Checkable) on demo-bad: no releases match the configured release tag pattern within the lookback window
- C07.provenance.commit-linkage (Not Checkable) on demo-bad: no releases match the configured release tag pattern within the lookback window
- C07.release.checksums (Not Checkable) on demo-bad: no releases match the configured release tag pattern within the lookback window
- C07.release.signatures (Not Checkable) on demo-bad: no releases match the configured release tag pattern within the lookback window
- C07.release.tags-signed (Not Checkable) on demo-bad: no releases match the configured release tag pattern within the lookback window
- C08.actions.oidc-vs-secrets (Not Checkable) on demo-good: no cloud-deployment login action (AWS/Azure/GCP) detected among the workflow files that could be fetched and parsed on the default branch
- C09.audit.log-streaming (Not Checkable): audit-log streaming/export is configured exclusively at the GitHub Enterprise account level (/enterprises/{enterprise}/audit-log/streams), not the organization level — there is no API this org/repo-scoped tool can query to determine whether it's configured
- C09.audit.org-log-available (Not Checkable): GET /orgs/{org}/audit-log returned 404 — either the org's plan doesn't include GitHub Enterprise Cloud's audit-log API, or the token lacks the read:audit\_log scope (GitHub returns the same status for both, so this can't be told apart from the response alone)
- C09.audit.retention-awareness (Not Checkable): informational only — GitHub's documented audit-log retention window is provided as context; no API exposes what retention actually applies to this specific org
- C10.vdp.security-policy-org (Not Checkable): Qloud-ltd-com has no .github repo — no org-wide default community-health-file mechanism exists
- SA.agency-notification-process (Not Checkable): no self-attestation provided for this question
- SA.audit-log-export-fallback (Not Checkable): no self-attestation provided for this question
- SA.dev-security-training (Not Checkable): no self-attestation provided for this question
- SA.threat-modeling (Not Checkable): no self-attestation provided for this question
- SA.vuln-remediation-sla (Not Checkable): no self-attestation provided for this question
- SA.vuln-triage-sla (Not Checkable): no self-attestation provided for this question

