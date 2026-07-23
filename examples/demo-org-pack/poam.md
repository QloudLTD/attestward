# Plan of Action & Milestones (Draft)

This is a **draft** POA&M generated from `evidence.json`. Owner, target date, and
resources-required fields are placeholders for a human to fill in — this tool has
no authority to assign ownership, timelines, or budget. Every finding here traces
to a specific `verified-fail` or `partial` check result; see report.md for full
narrative context.

## Summary

- **Org:** Qloud-LTD
- **Scan window:** 2026-07-23 10:27:23 UTC – 2026-07-23 10:27:28 UTC
- **Total findings:** 16 (14 fail, 2 partial)

| Cluster | Fail | Partial | Total |
|---|---|---|---|
| 1. Secure development and build environments | 3 | 1 | 4 |
| 2. Trusted source code supply chain (good-faith effort) | 9 | 1 | 10 |
| 3. Provenance for internal and third-party code | 1 | 0 | 1 |
| 4. Automated vulnerability checking, pre-release, and disclosure program | 1 | 0 | 1 |

---

## Findings

### Cluster 1: Secure development and build environments

> The software is developed and built in secure environments. Those environments are secured by the following actions, at a minimum: a) Separating and protecting each environment involved in developing and building software; b) Regularly logging, monitoring, and auditing trust relationships used for authorization and access: i) to any software development and build environments; and ii) among components within each environment; c) Enforcing multi-factor authentication and conditional access across the environments relevant to developing and building software in a manner that minimizes security risk; d) Taking consistent and reasonable steps to document, as well as minimize use or inclusion of software products that create undue risk within the environments used to develop and build software; e) Encrypting sensitive data, such as credentials, to the extent practicable and based on risk; f) Implementing defensive cybersecurity practices, including continuous monitoring of operations and alerts and, as necessary, responding to suspected and confirmed cyber incidents.

#### POAM-001: Org requires two-factor authentication (`C01.org.2fa-required`) — [FAIL] Verified Fail

- **Repo:** (org-level)
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** org does not require two-factor authentication for members
- **Evidence:** GET /orgs/Qloud-LTD (digest d8417038f16eb3660ebca827deaac94dcf0b3ccea3de3b3238acf749d88775f1)
- **Suggested remediation:** Org Settings -> Authentication security -> check "Require two-factor authentication for everyone in the [org] organization". Any member without 2FA enabled will be removed from the org when this is turned on, so resolve C01.org.members-without-2fa first.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-002: Org enables secret/dependency security features by default for new repos (`C04.org.security-defaults`) — [FAIL] Verified Fail

- **Repo:** (org-level)
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** not every security feature is enabled by default for new repositories
- **Evidence:** GET /orgs/Qloud-LTD (digest d8417038f16eb3660ebca827deaac94dcf0b3ccea3de3b3238acf749d88775f1)
- **Suggested remediation:** Org Settings -> Code security -> enable secret scanning, push protection, Dependabot alerts, AND Advanced Security "for new repositories" — all four must be on for this check to pass — so every repo created going forward starts with them on, instead of relying on each repo owner to enable them individually.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-003: Workflows declare explicit, least-privilege GITHUB\_TOKEN permissions (`C08.actions.token-permissions`) — [PARTIAL] Partial

- **Repo:** demo-good
- **Affected SSDF task(s):** PO.5.1, PW.6.2
- **CISA form cluster(s):** 1, 2, 3, 4
- **Description:** 1 of 2 job(s)/workflow(s) declare explicit permissions; the rest rely on the default GITHUB\_TOKEN permissions
- **Evidence:** GET /repos/Qloud-LTD/demo-good (digest f9e6e5942a1cf1417c9718fb56d6fd5d3ca0039c8e5c4e645c33d412ace6010c); GET /repos/Qloud-LTD/demo-good/actions/workflows (digest d73bbf7ce5d27a560581df9eb4c2a1591baff2b6a5cf9884c9b28c5fbab628fa); GET /repos/Qloud-LTD/demo-good/contents/.github/workflows/ci.yaml (digest 746a66ccb957a4071de87d9d6a24ddfd4defceece0b07d921a3fa9f5e1c7a70a); GET /repos/Qloud-LTD/demo-good/contents/.github/workflows/release.yaml (digest a8529d841b78c4ed6ae6e0092401f32b0908597e441a06068fa47d6a55cb9b2e); GET /repos/Qloud-LTD/demo-good/actions/permissions/workflow (digest f6e178fc1e56cf43900da383f85398b61de9ae61c6b8433116c1856605745924)
- **Suggested remediation:** Add an explicit `permissions:` block — at workflow level, or per job for finer scoping — set to the minimum needed (e.g. `contents: read`), not the ambient default. Replace any `permissions: write-all` with a specific, scoped list of only the permissions that job actually needs.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-004: A webhook exports push/release/deployment events (`C09.repo.webhooks`) — [FAIL] Verified Fail

- **Repo:** demo-good
- **Affected SSDF task(s):** PO.5.1
- **CISA form cluster(s):** 1, 2, 3
- **Description:** no active webhook subscribes to push, release, or deployment events
- **Evidence:** GET /repos/Qloud-LTD/demo-good/hooks (digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)
- **Suggested remediation:** Repo Settings -> Webhooks -> Add webhook -> subscribe to at least Push, Release, and Deployment events (or the wildcard "Send me everything") pointing at your log/SIEM ingestion endpoint.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

### Cluster 2: Trusted source code supply chain (good-faith effort)

> The software producer makes a good-faith effort to maintain trusted source code supply chains by employing automated tools or comparable processes to address the security of internal code and third-party components and manage related vulnerabilities.

#### POAM-005: Whether members can create public repositories (`C01.org.members-can-create-public`) — [FAIL] Verified Fail

- **Repo:** (org-level)
- **Affected SSDF task(s):** PS.1.1
- **CISA form cluster(s):** 2, 4
- **Description:** members can create public repositories (potential leak vector)
- **Evidence:** GET /orgs/Qloud-LTD (digest d8417038f16eb3660ebca827deaac94dcf0b3ccea3de3b3238acf749d88775f1)
- **Suggested remediation:** Org Settings -> Member privileges -> Repository creation -> uncheck "Public" so members can't create public repositories without an explicit visibility change reviewed separately.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-006: CodeQL default setup is configured (`C05.sast.default-setup`) — [FAIL] Verified Fail

- **Repo:** demo-good
- **Affected SSDF task(s):** PW.7.1, RV.1.2
- **CISA form cluster(s):** 2, 3, 4
- **Description:** CodeQL default setup is "not-configured"
- **Evidence:** GET /repos/Qloud-LTD/demo-good/code-scanning/default-setup (digest 42357385cf151d57ee6a21d7399ad340616105dc9c88108071663c7657ae66ad)
- **Suggested remediation:** Repo Settings -> Security -> Advanced Security -> under Code Security, "CodeQL analysis" -> Set up -> Default (choose "Default", not "Advanced", unless a custom workflow is specifically needed).
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-007: A SAST tool is configured (`C05.sast.tool-configured`) — [FAIL] Verified Fail

- **Repo:** demo-good
- **Affected SSDF task(s):** PW.7.1, RV.1.2
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no SAST tool detected in any workflow, and CodeQL default setup is not configured
- **Evidence:** GET /repos/Qloud-LTD/demo-good (digest f9e6e5942a1cf1417c9718fb56d6fd5d3ca0039c8e5c4e645c33d412ace6010c); GET /repos/Qloud-LTD/demo-good/actions/workflows (digest d73bbf7ce5d27a560581df9eb4c2a1591baff2b6a5cf9884c9b28c5fbab628fa); GET /repos/Qloud-LTD/demo-good/contents/.github/workflows/ci.yaml (digest 746a66ccb957a4071de87d9d6a24ddfd4defceece0b07d921a3fa9f5e1c7a70a); GET /repos/Qloud-LTD/demo-good/contents/.github/workflows/release.yaml (digest a8529d841b78c4ed6ae6e0092401f32b0908597e441a06068fa47d6a55cb9b2e); GET /repos/Qloud-LTD/demo-good/releases (digest c60286ab460e65c072e0b7d75d20c7ad396ebd1d622a67ceb567ae4d0f8a9a2a); GET /repos/Qloud-LTD/demo-good/git/ref/tags/v1.0.0 (digest 98f7aba3b28cd0f19bff125e3af3e63c7dae27667431f951d064f04fe3ea2db1); GET /repos/Qloud-LTD/demo-good/git/tags/c9f04e6ab5082a7cc428cf60d80582444d9cb2e7 (digest ddd253807b827ddd0c7d5db95c35fd9ab773a72f0973408477415186e1acb68c)
- **Suggested remediation:** Enable CodeQL default setup (repo Settings -> Security -> Advanced Security -> under Code Security, "CodeQL analysis" -> Set up -> Default), or add a workflow using a recognized SAST action/CLI (see mappings/scanner-signatures.yaml for what this tool recognizes) — a workflow whose name merely suggests SAST isn't enough on its own; it needs a matched action/CLI invocation to count as more than a low-confidence signal.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-008: Dependabot config covers the repo's detected dependency ecosystems (`C06.sca.dependabot-config`) — [FAIL] Verified Fail

- **Repo:** demo-good
- **Affected SSDF task(s):** PW.4.4
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no Dependabot config found; 1 detected ecosystem(s) are uncovered
- **Evidence:** GET /repos/Qloud-LTD/demo-good/contents/ (digest 32fbcbbce3cbd4b00f89f56285636192c4eb0cefbd784799cba46415258ac932); GET /repos/Qloud-LTD/demo-good/contents/.github/dependabot.yml (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-LTD/demo-good/contents/.github/dependabot.yaml (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- **Suggested remediation:** Extend `.github/dependabot.yml` with an `updates:` entry for each detected-but-uncovered ecosystem (see this finding's `uncovered_ecosystems` fact for exactly which ones).
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-009: Dependency review is enforced as a required check on pull requests (`C06.sca.dependency-review`) — [FAIL] Verified Fail

- **Repo:** demo-good
- **Affected SSDF task(s):** PW.4.4
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no dependency-review-action (or equivalent) workflow detected
- **Evidence:** GET /repos/Qloud-LTD/demo-good (digest f9e6e5942a1cf1417c9718fb56d6fd5d3ca0039c8e5c4e645c33d412ace6010c); GET /repos/Qloud-LTD/demo-good/actions/workflows (digest d73bbf7ce5d27a560581df9eb4c2a1591baff2b6a5cf9884c9b28c5fbab628fa); GET /repos/Qloud-LTD/demo-good/contents/.github/workflows/ci.yaml (digest 746a66ccb957a4071de87d9d6a24ddfd4defceece0b07d921a3fa9f5e1c7a70a); GET /repos/Qloud-LTD/demo-good/contents/.github/workflows/release.yaml (digest a8529d841b78c4ed6ae6e0092401f32b0908597e441a06068fa47d6a55cb9b2e); GET /repos/Qloud-LTD/demo-good/branches/main/protection (digest c3603c76c73c25d8a422d5635bfc1ab626f361074537273d9001a4f1d5876e39); GET /repos/Qloud-LTD/demo-good/rules/branches/main (digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)
- **Suggested remediation:** Add a workflow using `actions/dependency-review-action` (or equivalent), make sure it triggers on `pull_request` (not just push), and add it as a required status check: repo Settings -> Rules -> Rulesets -> the branch's rule -> Require status checks to pass -> select the dependency-review workflow's check.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-010: An SCA tool ran for each release in the lookback window (`C06.sca.ran-per-release`) — [FAIL] Verified Fail

- **Repo:** demo-good
- **Affected SSDF task(s):** PW.4.4, RV.1.2
- **CISA form cluster(s):** 2, 3, 4
- **Description:** at least one release in the lookback window has no matched SCA run at all
- **Evidence:** GET /repos/Qloud-LTD/demo-good (digest f9e6e5942a1cf1417c9718fb56d6fd5d3ca0039c8e5c4e645c33d412ace6010c); GET /repos/Qloud-LTD/demo-good/actions/workflows (digest d73bbf7ce5d27a560581df9eb4c2a1591baff2b6a5cf9884c9b28c5fbab628fa); GET /repos/Qloud-LTD/demo-good/contents/.github/workflows/ci.yaml (digest 746a66ccb957a4071de87d9d6a24ddfd4defceece0b07d921a3fa9f5e1c7a70a); GET /repos/Qloud-LTD/demo-good/contents/.github/workflows/release.yaml (digest a8529d841b78c4ed6ae6e0092401f32b0908597e441a06068fa47d6a55cb9b2e); GET /repos/Qloud-LTD/demo-good/releases (digest c60286ab460e65c072e0b7d75d20c7ad396ebd1d622a67ceb567ae4d0f8a9a2a); GET /repos/Qloud-LTD/demo-good/git/ref/tags/v1.0.0 (digest 98f7aba3b28cd0f19bff125e3af3e63c7dae27667431f951d064f04fe3ea2db1); GET /repos/Qloud-LTD/demo-good/git/tags/c9f04e6ab5082a7cc428cf60d80582444d9cb2e7 (digest ddd253807b827ddd0c7d5db95c35fd9ab773a72f0973408477415186e1acb68c)
- **Suggested remediation:** Applies to a workflow-based SCA tool specifically (Dependabot has no per-release run history to check). Make sure the SCA workflow's trigger fires on the commit each release is cut from, and that any run that fired completed successfully.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-011: An SCA tool is configured (`C06.sca.tool-configured`) — [FAIL] Verified Fail

- **Repo:** demo-good
- **Affected SSDF task(s):** PW.4.4, RV.1.2
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no SCA tool detected in any workflow, and no Dependabot config found
- **Evidence:** GET /repos/Qloud-LTD/demo-good (digest f9e6e5942a1cf1417c9718fb56d6fd5d3ca0039c8e5c4e645c33d412ace6010c); GET /repos/Qloud-LTD/demo-good/actions/workflows (digest d73bbf7ce5d27a560581df9eb4c2a1591baff2b6a5cf9884c9b28c5fbab628fa); GET /repos/Qloud-LTD/demo-good/contents/.github/workflows/ci.yaml (digest 746a66ccb957a4071de87d9d6a24ddfd4defceece0b07d921a3fa9f5e1c7a70a); GET /repos/Qloud-LTD/demo-good/contents/.github/workflows/release.yaml (digest a8529d841b78c4ed6ae6e0092401f32b0908597e441a06068fa47d6a55cb9b2e); GET /repos/Qloud-LTD/demo-good/contents/.github/dependabot.yml (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-LTD/demo-good/contents/.github/dependabot.yaml (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- **Suggested remediation:** Add a `.github/dependabot.yml` with at least one `updates:` entry, or add a workflow using a recognized SCA action/CLI (see mappings/scanner-signatures.yaml) — a workflow whose name merely suggests SCA isn't enough on its own; it needs a matched action/CLI invocation.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-012: Third-party actions and reusable workflows are pinned to a full commit SHA (`C08.actions.pinned`) — [PARTIAL] Partial

- **Repo:** demo-good
- **Affected SSDF task(s):** PW.4.1
- **CISA form cluster(s):** 2, 3
- **Description:** every third-party reference is SHA-pinned, but 1 first-party actions/\* reference(s) use a mutable tag instead of a SHA
- **Evidence:** GET /repos/Qloud-LTD/demo-good (digest f9e6e5942a1cf1417c9718fb56d6fd5d3ca0039c8e5c4e645c33d412ace6010c); GET /repos/Qloud-LTD/demo-good/actions/workflows (digest d73bbf7ce5d27a560581df9eb4c2a1591baff2b6a5cf9884c9b28c5fbab628fa); GET /repos/Qloud-LTD/demo-good/contents/.github/workflows/ci.yaml (digest 746a66ccb957a4071de87d9d6a24ddfd4defceece0b07d921a3fa9f5e1c7a70a); GET /repos/Qloud-LTD/demo-good/contents/.github/workflows/release.yaml (digest a8529d841b78c4ed6ae6e0092401f32b0908597e441a06068fa47d6a55cb9b2e)
- **Suggested remediation:** Pin every third-party action/reusable-workflow `uses:` reference to a full 40-char commit SHA, not a tag or branch (e.g. `uses: actions/checkout@<full-sha> # v5.0.0` — keep the version as a comment for readability). A tool like `pin-github-action`/`pinact`, or Renovate's digest-pinning preset, can do this initial tag-to-SHA conversion (Dependabot cannot — it only keeps an already-pinned reference's version comment up to date going forward, via that same trailing comment). First-party `actions/*` references on a mutable tag are tolerated (capped at partial) but should be pinned too for a full pass.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-013: SECURITY.md advertises an actionable intake channel (`C10.vdp.intake-channel`) — [FAIL] Verified Fail

- **Repo:** demo-good
- **Affected SSDF task(s):** RV.1.1, RV.1.3
- **CISA form cluster(s):** 2, 3, 4
- **Description:** no SECURITY.md exists to advertise an intake channel
- **Evidence:** GET /repos/Qloud-LTD/demo-good/contents/.github/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-LTD/demo-good/contents/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-LTD/demo-good/contents/docs/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-LTD/.github/contents/.github/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-LTD/.github/contents/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-LTD/.github/contents/docs/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- **Suggested remediation:** If no SECURITY.md exists at all, add one first (see C10.vdp.security-md). If it exists but this still fails, make the intake channel concrete and actionable: an email address, a URL (e.g. a reporting form or bug-bounty page), or an explicit mention that reporters should use GitHub's private vulnerability reporting feature — not just general prose like "we take security seriously."
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

#### POAM-014: GitHub private vulnerability reporting is enabled (`C10.vdp.private-reporting`) — [FAIL] Verified Fail

- **Repo:** demo-good
- **Affected SSDF task(s):** RV.1.1
- **CISA form cluster(s):** 2, 3, 4
- **Description:** private vulnerability reporting is not enabled
- **Evidence:** GET /repos/Qloud-LTD/demo-good/private-vulnerability-reporting (digest 5acf3ff77b4420677b5923071f303facaba7a9273a346284a667a275df325146)
- **Suggested remediation:** Repo Settings -> Security -> Advanced Security -> enable "Private vulnerability reporting."
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

### Cluster 3: Provenance for internal and third-party code

> The software producer maintains provenance for internal code and third-party components incorporated into the software to the greatest extent feasible.

#### POAM-015: A SAST tool ran for each release in the lookback window (`C05.sast.ran-per-release`) — [FAIL] Verified Fail

- **Repo:** demo-good
- **Affected SSDF task(s):** PW.7.2, RV.1.2
- **CISA form cluster(s):** 3, 4
- **Description:** at least one release in the lookback window has no matched SAST run at all
- **Evidence:** GET /repos/Qloud-LTD/demo-good (digest f9e6e5942a1cf1417c9718fb56d6fd5d3ca0039c8e5c4e645c33d412ace6010c); GET /repos/Qloud-LTD/demo-good/actions/workflows (digest d73bbf7ce5d27a560581df9eb4c2a1591baff2b6a5cf9884c9b28c5fbab628fa); GET /repos/Qloud-LTD/demo-good/contents/.github/workflows/ci.yaml (digest 746a66ccb957a4071de87d9d6a24ddfd4defceece0b07d921a3fa9f5e1c7a70a); GET /repos/Qloud-LTD/demo-good/contents/.github/workflows/release.yaml (digest a8529d841b78c4ed6ae6e0092401f32b0908597e441a06068fa47d6a55cb9b2e); GET /repos/Qloud-LTD/demo-good/releases (digest c60286ab460e65c072e0b7d75d20c7ad396ebd1d622a67ceb567ae4d0f8a9a2a); GET /repos/Qloud-LTD/demo-good/git/ref/tags/v1.0.0 (digest 98f7aba3b28cd0f19bff125e3af3e63c7dae27667431f951d064f04fe3ea2db1); GET /repos/Qloud-LTD/demo-good/git/tags/c9f04e6ab5082a7cc428cf60d80582444d9cb2e7 (digest ddd253807b827ddd0c7d5db95c35fd9ab773a72f0973408477415186e1acb68c)
- **Suggested remediation:** Make sure the SAST workflow's trigger actually fires on (or before) the commit each release is cut from — e.g. trigger on push to the release branch, or on the release event itself — and that any run that did fire completed successfully rather than erroring out.
- **Owner:** ____
- **Target date:** ____
- **Resources required:** ____
- **Milestones:** ____
- **Status:** Open

### Cluster 4: Automated vulnerability checking, pre-release, and disclosure program

> The software producer employs automated tools or comparable processes that check for security vulnerabilities. In addition: a) The software producer operates these processes on an ongoing basis and prior to product, version, or update releases; b) The software producer has a policy or process to address discovered security vulnerabilities prior to product release; and c) The software producer operates a vulnerability disclosure program and accepts, reviews, and addresses disclosed software vulnerabilities in a timely fashion and according to any timelines specified in the vulnerability disclosure program or applicable policies.

#### POAM-016: A SECURITY.md resolves for this repo (`C10.vdp.security-md`) — [FAIL] Verified Fail

- **Repo:** demo-good
- **Affected SSDF task(s):** RV.1.3
- **CISA form cluster(s):** 4
- **Description:** no SECURITY.md found at any of the standard locations (.github/, repo root, docs/) in this repo or the org's .github repo
- **Evidence:** GET /repos/Qloud-LTD/demo-good/contents/.github/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-LTD/demo-good/contents/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-LTD/demo-good/contents/docs/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-LTD/.github/contents/.github/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-LTD/.github/contents/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2); GET /repos/Qloud-LTD/.github/contents/docs/SECURITY.md (digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
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

- `C04.secrets.advanced-security` (Not Checkable) on demo-good: not applicable to public repositories (GHAS licensing only gates private-repo features)
- `C05.sast.cadence` (Not Checkable) on demo-good: no SAST tool is configured; cadence cannot be computed
- `C08.actions.oidc-vs-secrets` (Not Checkable) on demo-good: no cloud-deployment login action (AWS/Azure/GCP) detected among the workflow files that could be fetched and parsed on the default branch
- `C09.audit.log-streaming` (Not Checkable): audit-log streaming/export is configured exclusively at the GitHub Enterprise account level (/enterprises/{enterprise}/audit-log/streams), not the organization level — there is no API this org/repo-scoped tool can query to determine whether it's configured
- `C09.audit.org-log-available` (Not Checkable): GET /orgs/{org}/audit-log returned 404 — either the org's plan doesn't include GitHub Enterprise Cloud's audit-log API, or the token lacks the read:audit\_log scope (GitHub returns the same status for both, so this can't be told apart from the response alone)
- `C09.audit.retention-awareness` (Not Checkable): informational only — GitHub's documented audit-log retention window is provided as context; no API exposes what retention actually applies to this specific org
- `C10.vdp.security-policy-org` (Not Checkable): Qloud-LTD has no .github repo — no org-wide default community-health-file mechanism exists
- `SA.agency-notification-process` (Not Checkable): no self-attestation provided for this question
- `SA.audit-log-export-fallback` (Not Checkable): no self-attestation provided for this question
- `SA.dev-security-training` (Not Checkable): no self-attestation provided for this question
- `SA.threat-modeling` (Not Checkable): no self-attestation provided for this question
- `SA.vuln-remediation-sla` (Not Checkable): no self-attestation provided for this question
- `SA.vuln-triage-sla` (Not Checkable): no self-attestation provided for this question

