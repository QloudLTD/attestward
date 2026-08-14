# Software Development Security Report

## Executive Summary

- **Org:** Qloud-ltd-com
- **Repos in scope:** demo-good, demo-bad
- **Scan window:** 2026-08-14 05:59:17 UTC – 2026-08-14 05:59:21 UTC
- **Tool version:** d0f4117
- **Mapping versions:** SSDF 1.13.0 · CISA form 1.0.0 · scanner signatures 1.5.0 · self-attestation 1.0.0
- **Pack SHA-256:** `0d73629646bf2f7601922f67b8507b342a414033bcb553c0bd336b22d7a597f4`

### Cluster status

| Cluster | Status |
|---|---|
| 1. Secure development and build environments | [FAIL] Verified Fail |
| 2. Trusted source code supply chain (good-faith effort) | [FAIL] Verified Fail |
| 3. Provenance for internal and third-party code | [FAIL] Verified Fail |
| 4. Automated vulnerability checking, pre-release, and disclosure program | [FAIL] Verified Fail |

### Result counts

| Status | Count |
|---|---|
| [FAIL] Verified Fail | 40 |
| [PARTIAL] Partial | 4 |
| [NOT CHECKABLE] Not Checkable | 21 |
| [SELF-ATTESTED] Self-Attested | 0 |
| [PASS] Verified Pass | 24 |

---

## Cluster Detail

### Cluster 1: Secure development and build environments — [FAIL] Verified Fail

> The software is developed and built in secure environments. Those environments are secured by the following actions, at a minimum: a) Separating and protecting each environment involved in developing and building software; b) Regularly logging, monitoring, and auditing trust relationships used for authorization and access: i) to any software development and build environments; and ii) among components within each environment; c) Enforcing multi-factor authentication and conditional access across the environments relevant to developing and building software in a manner that minimizes security risk; d) Taking consistent and reasonable steps to document, as well as minimize use or inclusion of software products that create undue risk within the environments used to develop and build software; e) Encrypting sensitive data, such as credentials, to the extent practicable and based on risk; f) Implementing defensive cybersecurity practices, including continuous monitoring of operations and alerts and, as necessary, responding to suspected and confirmed cyber incidents.

#### PO.3.2 — _no data_

Follow recommended security practices to deploy, operate, and maintain tools and toolchains.

#### PO.3.3 — _no data_

Configure tools to generate artifacts of their support of secure software development practices as defined by the organization.

#### PO.5.1 — [FAIL] Verified Fail

Separate and protect each environment involved in software development.

##### Org requires two-factor authentication (`C01.org.2fa-required`) — [FAIL] Verified Fail

org does not require two-factor authentication for members

Evidence:
- GET /orgs/Qloud-ltd-com at 2026-08-14 05:59:17 UTC (HTTP 200, digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)

- two\_factor\_requirement\_enabled: false


##### Count of members without two-factor authentication (`C01.org.members-without-2fa`) — [PASS] Verified Pass

all org members have two-factor authentication enabled

Evidence:
- GET /orgs/Qloud-ltd-com/members at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- members\_without\_2fa\_count: 0


##### Production-like environments restrict which branches/tags can deploy (`C03.env.branch-policy`) — [FAIL] Verified Fail

Repo: demo-bad. environment(s) that allow deployment from any branch: \[production\]

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)

- environments\_allowing\_any\_branch: production

- production\_like\_environments: production


##### Production-like environments restrict which branches/tags can deploy (`C03.env.branch-policy`) — [PASS] Verified Pass

Repo: demo-good. every production-like environment restricts which branches/tags can deploy

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest ffcebe166089955525006cf81320099a8c985b500225d3c3084c29f38efbfb0d)

- environments\_allowing\_any\_branch: 

- production\_like\_environments: production


##### A production-like environment exists (`C03.env.exists`) — [PASS] Verified Pass

Repo: demo-bad. 1 production-like environment(s) found among 1 total

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)

- production\_like\_heuristic: name matches prod\*/production, case-insensitive

- all\_environment\_names: production

- production\_like\_environments: production


##### A production-like environment exists (`C03.env.exists`) — [PASS] Verified Pass

Repo: demo-good. 1 production-like environment(s) found among 1 total

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest ffcebe166089955525006cf81320099a8c985b500225d3c3084c29f38efbfb0d)

- production\_like\_heuristic: name matches prod\*/production, case-insensitive

- all\_environment\_names: production

- production\_like\_environments: production


##### Production-like environments have at least one protection rule (`C03.env.protection-rules`) — [FAIL] Verified Fail

Repo: demo-bad. environment(s) with no protection rules: \[production\]

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)

- environments\_without\_protection: production

- production\_like\_environments: production


##### Production-like environments have at least one protection rule (`C03.env.protection-rules`) — [PASS] Verified Pass

Repo: demo-good. every production-like environment has at least one protection rule

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest ffcebe166089955525006cf81320099a8c985b500225d3c3084c29f38efbfb0d)

- environments\_without\_protection: 

- production\_like\_environments: production


##### Production-like environments require reviewer approval before deployment (`C03.env.required-reviewers`) — [FAIL] Verified Fail

Repo: demo-bad. environment(s) without required reviewers: \[production\]

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)

- environments\_without\_required\_reviewers: production

- production\_like\_environments: production


##### Production-like environments require reviewer approval before deployment (`C03.env.required-reviewers`) — [PASS] Verified Pass

Repo: demo-good. every production-like environment requires reviewer approval

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest ffcebe166089955525006cf81320099a8c985b500225d3c3084c29f38efbfb0d)

- environments\_without\_required\_reviewers: 

- production\_like\_environments: production


##### Org enables secret/dependency security features by default for new repos (`C04.org.security-defaults`) — [FAIL] Verified Fail

not every security feature is enabled by default for new repositories

Evidence:
- GET /orgs/Qloud-ltd-com at 2026-08-14 05:59:17 UTC (HTTP 200, digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)

- advanced\_security\_enabled\_for\_new\_repositories: false

- dependabot\_alerts\_enabled\_for\_new\_repositories: true

- secret\_scanning\_enabled\_for\_new\_repositories: true

- secret\_scanning\_push\_protection\_enabled\_for\_new\_repositories: true


##### GitHub Advanced Security is enabled where applicable (`C04.secrets.advanced-security`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. not applicable to public repositories (GHAS licensing only gates private-repo features)

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)


##### GitHub Advanced Security is enabled where applicable (`C04.secrets.advanced-security`) — [NOT CHECKABLE] Not Checkable

Repo: demo-good. not applicable to public repositories (GHAS licensing only gates private-repo features)

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)


##### Secret scanning push protection is active (`C04.secrets.push-protection`) — [FAIL] Verified Fail

Repo: demo-bad. secret scanning push protection is not enabled (freely available on public repos)

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)

- private: false

- push\_protection\_status: disabled


##### Secret scanning push protection is active (`C04.secrets.push-protection`) — [PASS] Verified Pass

Repo: demo-good. secret scanning push protection is enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)

- private: false

- push\_protection\_status: enabled


##### Secret scanning is active (`C04.secrets.scanning-enabled`) — [FAIL] Verified Fail

Repo: demo-bad. secret scanning is not enabled (freely available on public repos)

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)

- private: false

- secret\_scanning\_status: disabled


##### Secret scanning is active (`C04.secrets.scanning-enabled`) — [PASS] Verified Pass

Repo: demo-good. secret scanning is enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)

- private: false

- secret\_scanning\_status: enabled


##### Cloud deployments use OIDC rather than long-lived static credentials (`C08.actions.oidc-vs-secrets`) — [FAIL] Verified Fail

Repo: demo-bad. 1 cloud-deployment login step(s) use long-lived static credentials instead of OIDC

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)

- skipped\_workflows: (none)

**logins**

| cloud | file | line | uses | verdict | 
|---|---|---|---|---|
| aws | .github/workflows/deploy-fixture.yaml | 9 | aws-actions/configure-aws-credentials@v4 | static | 


##### Cloud deployments use OIDC rather than long-lived static credentials (`C08.actions.oidc-vs-secrets`) — [NOT CHECKABLE] Not Checkable

Repo: demo-good. no cloud-deployment login action (AWS/Azure/GCP) detected among the workflow files that could be fetched and parsed on the default branch

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)

- skipped\_workflows: (none)


##### pull\_request\_target is not combined with checking out the PR head (`C08.actions.pull-request-target`) — [FAIL] Verified Fail

Repo: demo-bad. at least one pull\_request\_target workflow checks out the PR head commit/branch — this combination runs attacker-controlled code with base-repo secrets and token access

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)

- bare\_usage: 

- skipped\_workflows: (none)

**dangerous**

| file | line | uses | 
|---|---|---|
| .github/workflows/pr-target-fixture.yaml | 10 | actions/checkout@v5 | 


##### pull\_request\_target is not combined with checking out the PR head (`C08.actions.pull-request-target`) — [PASS] Verified Pass

Repo: demo-good. no workflow triggers on pull\_request\_target

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)

- bare\_usage: 

- dangerous: 

- skipped\_workflows: (none)


##### Self-hosted runners are not exposed to public-repo pull requests (`C08.actions.self-hosted`) — [PARTIAL] Partial

Repo: demo-bad. self-hosted runner(s) are used on a public repository — an external contributor's pull request is a potential path to them

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)

- repo\_private: false

- skipped\_workflows: (none)

**self\_hosted\_jobs**

| file | job | line | 
|---|---|---|
| .github/workflows/deploy-fixture.yaml | deploy | 5 | 


##### Self-hosted runners are not exposed to public-repo pull requests (`C08.actions.self-hosted`) — [PASS] Verified Pass

Repo: demo-good. no self-hosted runner usage detected

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)

- repo\_private: false

- self\_hosted\_jobs: 

- skipped\_workflows: (none)


##### Workflows declare explicit, least-privilege GITHUB\_TOKEN permissions (`C08.actions.token-permissions`) — [PARTIAL] Partial

Repo: demo-bad. 1 of 2 job(s)/workflow(s) declare explicit permissions; the rest rely on the default GITHUB\_TOKEN permissions

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/actions/permissions/workflow at 2026-08-14 05:59:19 UTC (HTTP 200, digest f6e178fc1e56cf43900da383f85398b61de9ae61c6b8433116c1856605745924)

- repo\_default\_workflow\_permissions: read

- skipped\_workflows: (none)

**findings**

| file | job | line | verdict | 
|---|---|---|---|
| .github/workflows/deploy-fixture.yaml | deploy | 5 | missing | 
| .github/workflows/pr-target-fixture.yaml | label | 7 | explicit | 


##### Workflows declare explicit, least-privilege GITHUB\_TOKEN permissions (`C08.actions.token-permissions`) — [PARTIAL] Partial

Repo: demo-good. 1 of 2 job(s)/workflow(s) declare explicit permissions; the rest rely on the default GITHUB\_TOKEN permissions

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/actions/permissions/workflow at 2026-08-14 05:59:19 UTC (HTTP 200, digest f6e178fc1e56cf43900da383f85398b61de9ae61c6b8433116c1856605745924)

- repo\_default\_workflow\_permissions: read

- skipped\_workflows: (none)

**findings**

| file | job | line | verdict | 
|---|---|---|---|
| .github/workflows/ci.yaml | build | 4 | missing | 
| .github/workflows/release.yaml | release | 9 | explicit | 


##### Audit-log export/streaming is configured (`C09.audit.log-streaming`) — [NOT CHECKABLE] Not Checkable

audit-log streaming/export is configured exclusively at the GitHub Enterprise account level (/enterprises/{enterprise}/audit-log/streams), not the organization level — there is no API this org/repo-scoped tool can query to determine whether it's configured


##### Organization audit log is reachable via the API (`C09.audit.org-log-available`) — [NOT CHECKABLE] Not Checkable

GET /orgs/{org}/audit-log returned 404 — either the org's plan doesn't include GitHub Enterprise Cloud's audit-log API, or the token lacks the read:audit\_log scope (GitHub returns the same status for both, so this can't be told apart from the response alone)

Evidence:
- GET /orgs/Qloud-ltd-com/audit-log at 2026-08-14 05:59:19 UTC (HTTP 404, digest 875304a522b4c5c07101c03cd5eab96b2818c9fa2be10733c0cd426613baa6d8)
- GET /orgs/Qloud-ltd-com at 2026-08-14 05:59:20 UTC (HTTP 200, digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)

- org\_plan: free


##### Audit-log retention window (informational) (`C09.audit.retention-awareness`) — [NOT CHECKABLE] Not Checkable

informational only — GitHub's documented audit-log retention window is provided as context; no API exposes what retention actually applies to this specific org

- documented\_retention\_days: 180

- note: GitHub's docs state the audit log lists events from the last 180 days. Exporting/streaming (Enterprise-only, see C09.audit.log-streaming) is GitHub's documented mechanism for retention beyond that window.

- source\_url: https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization


##### A webhook exports push/release/deployment events (`C09.repo.webhooks`) — [FAIL] Verified Fail

Repo: demo-bad. no active webhook subscribes to push, release, or deployment events

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/hooks at 2026-08-14 05:59:20 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- webhooks: (none)


##### A webhook exports push/release/deployment events (`C09.repo.webhooks`) — [FAIL] Verified Fail

Repo: demo-good. no active webhook subscribes to push, release, or deployment events

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/hooks at 2026-08-14 05:59:20 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- webhooks: (none)


##### If GitHub's own audit-log API or streaming isn't available (e.g. a non-Enterprise plan, or streaming being an Enterprise-account-only feature this tool can't query — see C09.audit.log-streaming), does the producer export or retain audit/access logs through another mechanism, and for how long? (`SA.audit-log-export-fallback`) — [NOT CHECKABLE] Not Checkable

no self-attestation provided for this question


#### PO.5.2 — _no data_

Secure and harden development endpoints (i.e., endpoints for software designers, developers, testers, builders, etc.) to perform development-related tasks using a risk-based approach.


### Cluster 2: Trusted source code supply chain (good-faith effort) — [FAIL] Verified Fail

> The software producer makes a good-faith effort to maintain trusted source code supply chains by employing automated tools or comparable processes to address the security of internal code and third-party components and manage related vulnerabilities.

#### PO.1.1 — _no data_

Identify and document all security requirements for the organization's software development infrastructures and processes, and maintain the requirements over time.

#### PO.3.1 — _no data_

Specify which tools or tool types must or should be included in each toolchain to mitigate identified risks, as well as how the toolchain components are to be integrated with each other.

#### PO.3.2 — _no data_

Follow recommended security practices to deploy, operate, and maintain tools and toolchains.

#### PO.5.1 — [FAIL] Verified Fail

Separate and protect each environment involved in software development.

##### Org requires two-factor authentication (`C01.org.2fa-required`) — [FAIL] Verified Fail

org does not require two-factor authentication for members

Evidence:
- GET /orgs/Qloud-ltd-com at 2026-08-14 05:59:17 UTC (HTTP 200, digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)

- two\_factor\_requirement\_enabled: false


##### Count of members without two-factor authentication (`C01.org.members-without-2fa`) — [PASS] Verified Pass

all org members have two-factor authentication enabled

Evidence:
- GET /orgs/Qloud-ltd-com/members at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- members\_without\_2fa\_count: 0


##### Production-like environments restrict which branches/tags can deploy (`C03.env.branch-policy`) — [FAIL] Verified Fail

Repo: demo-bad. environment(s) that allow deployment from any branch: \[production\]

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)

- environments\_allowing\_any\_branch: production

- production\_like\_environments: production


##### Production-like environments restrict which branches/tags can deploy (`C03.env.branch-policy`) — [PASS] Verified Pass

Repo: demo-good. every production-like environment restricts which branches/tags can deploy

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest ffcebe166089955525006cf81320099a8c985b500225d3c3084c29f38efbfb0d)

- environments\_allowing\_any\_branch: 

- production\_like\_environments: production


##### A production-like environment exists (`C03.env.exists`) — [PASS] Verified Pass

Repo: demo-bad. 1 production-like environment(s) found among 1 total

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)

- production\_like\_heuristic: name matches prod\*/production, case-insensitive

- all\_environment\_names: production

- production\_like\_environments: production


##### A production-like environment exists (`C03.env.exists`) — [PASS] Verified Pass

Repo: demo-good. 1 production-like environment(s) found among 1 total

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest ffcebe166089955525006cf81320099a8c985b500225d3c3084c29f38efbfb0d)

- production\_like\_heuristic: name matches prod\*/production, case-insensitive

- all\_environment\_names: production

- production\_like\_environments: production


##### Production-like environments have at least one protection rule (`C03.env.protection-rules`) — [FAIL] Verified Fail

Repo: demo-bad. environment(s) with no protection rules: \[production\]

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)

- environments\_without\_protection: production

- production\_like\_environments: production


##### Production-like environments have at least one protection rule (`C03.env.protection-rules`) — [PASS] Verified Pass

Repo: demo-good. every production-like environment has at least one protection rule

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest ffcebe166089955525006cf81320099a8c985b500225d3c3084c29f38efbfb0d)

- environments\_without\_protection: 

- production\_like\_environments: production


##### Production-like environments require reviewer approval before deployment (`C03.env.required-reviewers`) — [FAIL] Verified Fail

Repo: demo-bad. environment(s) without required reviewers: \[production\]

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)

- environments\_without\_required\_reviewers: production

- production\_like\_environments: production


##### Production-like environments require reviewer approval before deployment (`C03.env.required-reviewers`) — [PASS] Verified Pass

Repo: demo-good. every production-like environment requires reviewer approval

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest ffcebe166089955525006cf81320099a8c985b500225d3c3084c29f38efbfb0d)

- environments\_without\_required\_reviewers: 

- production\_like\_environments: production


##### Org enables secret/dependency security features by default for new repos (`C04.org.security-defaults`) — [FAIL] Verified Fail

not every security feature is enabled by default for new repositories

Evidence:
- GET /orgs/Qloud-ltd-com at 2026-08-14 05:59:17 UTC (HTTP 200, digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)

- advanced\_security\_enabled\_for\_new\_repositories: false

- dependabot\_alerts\_enabled\_for\_new\_repositories: true

- secret\_scanning\_enabled\_for\_new\_repositories: true

- secret\_scanning\_push\_protection\_enabled\_for\_new\_repositories: true


##### GitHub Advanced Security is enabled where applicable (`C04.secrets.advanced-security`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. not applicable to public repositories (GHAS licensing only gates private-repo features)

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)


##### GitHub Advanced Security is enabled where applicable (`C04.secrets.advanced-security`) — [NOT CHECKABLE] Not Checkable

Repo: demo-good. not applicable to public repositories (GHAS licensing only gates private-repo features)

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)


##### Secret scanning push protection is active (`C04.secrets.push-protection`) — [FAIL] Verified Fail

Repo: demo-bad. secret scanning push protection is not enabled (freely available on public repos)

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)

- private: false

- push\_protection\_status: disabled


##### Secret scanning push protection is active (`C04.secrets.push-protection`) — [PASS] Verified Pass

Repo: demo-good. secret scanning push protection is enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)

- private: false

- push\_protection\_status: enabled


##### Secret scanning is active (`C04.secrets.scanning-enabled`) — [FAIL] Verified Fail

Repo: demo-bad. secret scanning is not enabled (freely available on public repos)

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)

- private: false

- secret\_scanning\_status: disabled


##### Secret scanning is active (`C04.secrets.scanning-enabled`) — [PASS] Verified Pass

Repo: demo-good. secret scanning is enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)

- private: false

- secret\_scanning\_status: enabled


##### Cloud deployments use OIDC rather than long-lived static credentials (`C08.actions.oidc-vs-secrets`) — [FAIL] Verified Fail

Repo: demo-bad. 1 cloud-deployment login step(s) use long-lived static credentials instead of OIDC

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)

- skipped\_workflows: (none)

**logins**

| cloud | file | line | uses | verdict | 
|---|---|---|---|---|
| aws | .github/workflows/deploy-fixture.yaml | 9 | aws-actions/configure-aws-credentials@v4 | static | 


##### Cloud deployments use OIDC rather than long-lived static credentials (`C08.actions.oidc-vs-secrets`) — [NOT CHECKABLE] Not Checkable

Repo: demo-good. no cloud-deployment login action (AWS/Azure/GCP) detected among the workflow files that could be fetched and parsed on the default branch

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)

- skipped\_workflows: (none)


##### pull\_request\_target is not combined with checking out the PR head (`C08.actions.pull-request-target`) — [FAIL] Verified Fail

Repo: demo-bad. at least one pull\_request\_target workflow checks out the PR head commit/branch — this combination runs attacker-controlled code with base-repo secrets and token access

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)

- bare\_usage: 

- skipped\_workflows: (none)

**dangerous**

| file | line | uses | 
|---|---|---|
| .github/workflows/pr-target-fixture.yaml | 10 | actions/checkout@v5 | 


##### pull\_request\_target is not combined with checking out the PR head (`C08.actions.pull-request-target`) — [PASS] Verified Pass

Repo: demo-good. no workflow triggers on pull\_request\_target

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)

- bare\_usage: 

- dangerous: 

- skipped\_workflows: (none)


##### Self-hosted runners are not exposed to public-repo pull requests (`C08.actions.self-hosted`) — [PARTIAL] Partial

Repo: demo-bad. self-hosted runner(s) are used on a public repository — an external contributor's pull request is a potential path to them

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)

- repo\_private: false

- skipped\_workflows: (none)

**self\_hosted\_jobs**

| file | job | line | 
|---|---|---|
| .github/workflows/deploy-fixture.yaml | deploy | 5 | 


##### Self-hosted runners are not exposed to public-repo pull requests (`C08.actions.self-hosted`) — [PASS] Verified Pass

Repo: demo-good. no self-hosted runner usage detected

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)

- repo\_private: false

- self\_hosted\_jobs: 

- skipped\_workflows: (none)


##### Workflows declare explicit, least-privilege GITHUB\_TOKEN permissions (`C08.actions.token-permissions`) — [PARTIAL] Partial

Repo: demo-bad. 1 of 2 job(s)/workflow(s) declare explicit permissions; the rest rely on the default GITHUB\_TOKEN permissions

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/actions/permissions/workflow at 2026-08-14 05:59:19 UTC (HTTP 200, digest f6e178fc1e56cf43900da383f85398b61de9ae61c6b8433116c1856605745924)

- repo\_default\_workflow\_permissions: read

- skipped\_workflows: (none)

**findings**

| file | job | line | verdict | 
|---|---|---|---|
| .github/workflows/deploy-fixture.yaml | deploy | 5 | missing | 
| .github/workflows/pr-target-fixture.yaml | label | 7 | explicit | 


##### Workflows declare explicit, least-privilege GITHUB\_TOKEN permissions (`C08.actions.token-permissions`) — [PARTIAL] Partial

Repo: demo-good. 1 of 2 job(s)/workflow(s) declare explicit permissions; the rest rely on the default GITHUB\_TOKEN permissions

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/actions/permissions/workflow at 2026-08-14 05:59:19 UTC (HTTP 200, digest f6e178fc1e56cf43900da383f85398b61de9ae61c6b8433116c1856605745924)

- repo\_default\_workflow\_permissions: read

- skipped\_workflows: (none)

**findings**

| file | job | line | verdict | 
|---|---|---|---|
| .github/workflows/ci.yaml | build | 4 | missing | 
| .github/workflows/release.yaml | release | 9 | explicit | 


##### Audit-log export/streaming is configured (`C09.audit.log-streaming`) — [NOT CHECKABLE] Not Checkable

audit-log streaming/export is configured exclusively at the GitHub Enterprise account level (/enterprises/{enterprise}/audit-log/streams), not the organization level — there is no API this org/repo-scoped tool can query to determine whether it's configured


##### Organization audit log is reachable via the API (`C09.audit.org-log-available`) — [NOT CHECKABLE] Not Checkable

GET /orgs/{org}/audit-log returned 404 — either the org's plan doesn't include GitHub Enterprise Cloud's audit-log API, or the token lacks the read:audit\_log scope (GitHub returns the same status for both, so this can't be told apart from the response alone)

Evidence:
- GET /orgs/Qloud-ltd-com/audit-log at 2026-08-14 05:59:19 UTC (HTTP 404, digest 875304a522b4c5c07101c03cd5eab96b2818c9fa2be10733c0cd426613baa6d8)
- GET /orgs/Qloud-ltd-com at 2026-08-14 05:59:20 UTC (HTTP 200, digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)

- org\_plan: free


##### Audit-log retention window (informational) (`C09.audit.retention-awareness`) — [NOT CHECKABLE] Not Checkable

informational only — GitHub's documented audit-log retention window is provided as context; no API exposes what retention actually applies to this specific org

- documented\_retention\_days: 180

- note: GitHub's docs state the audit log lists events from the last 180 days. Exporting/streaming (Enterprise-only, see C09.audit.log-streaming) is GitHub's documented mechanism for retention beyond that window.

- source\_url: https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization


##### A webhook exports push/release/deployment events (`C09.repo.webhooks`) — [FAIL] Verified Fail

Repo: demo-bad. no active webhook subscribes to push, release, or deployment events

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/hooks at 2026-08-14 05:59:20 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- webhooks: (none)


##### A webhook exports push/release/deployment events (`C09.repo.webhooks`) — [FAIL] Verified Fail

Repo: demo-good. no active webhook subscribes to push, release, or deployment events

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/hooks at 2026-08-14 05:59:20 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- webhooks: (none)


##### If GitHub's own audit-log API or streaming isn't available (e.g. a non-Enterprise plan, or streaming being an Enterprise-account-only feature this tool can't query — see C09.audit.log-streaming), does the producer export or retain audit/access logs through another mechanism, and for how long? (`SA.audit-log-export-fallback`) — [NOT CHECKABLE] Not Checkable

no self-attestation provided for this question


#### PO.5.2 — _no data_

Secure and harden development endpoints (i.e., endpoints for software designers, developers, testers, builders, etc.) to perform development-related tasks using a risk-based approach.

#### PS.1.1 — [FAIL] Verified Fail

Store all forms of code – including source code, executable code, and configuration-as-code – based on the principle of least privilege so that only authorized personnel, tools, services, etc. have access.

##### Default repository permission for members (`C01.org.default-repo-permission`) — [PASS] Verified Pass

default repository permission is "read"

Evidence:
- GET /orgs/Qloud-ltd-com at 2026-08-14 05:59:17 UTC (HTTP 200, digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)

- default\_repository\_permission: read


##### Whether members can create public repositories (`C01.org.members-can-create-public`) — [FAIL] Verified Fail

members can create public repositories (potential leak vector)

Evidence:
- GET /orgs/Qloud-ltd-com at 2026-08-14 05:59:17 UTC (HTTP 200, digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)

- members\_can\_create\_public\_repositories: true


##### Default branch protections apply to admins (no unconditional bypass actor) (`C02.branch.admin-enforced`) — [FAIL] Verified Fail

Repo: demo-bad. default branch protections do not apply to admins

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- bypass\_actors: 

- via: 


##### Default branch protections apply to admins (no unconditional bypass actor) (`C02.branch.admin-enforced`) — [PASS] Verified Pass

Repo: demo-good. default branch protections apply to admins with no bypass actors

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- bypass\_actors: 

- via: legacy


##### Default branch blocks branch deletion (`C02.branch.deletion-blocked`) — [FAIL] Verified Fail

Repo: demo-bad. default branch allows deletion

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- via: 


##### Default branch blocks branch deletion (`C02.branch.deletion-blocked`) — [PASS] Verified Pass

Repo: demo-good. default branch blocks deletion

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- via: legacy


##### Default branch blocks force pushes (`C02.branch.force-push-blocked`) — [FAIL] Verified Fail

Repo: demo-bad. default branch allows force pushes

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- via: 


##### Default branch blocks force pushes (`C02.branch.force-push-blocked`) — [PASS] Verified Pass

Repo: demo-good. default branch blocks force pushes

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- via: legacy


##### Default branch has protection (legacy branch protection or a ruleset) (`C02.branch.protection-exists`) — [FAIL] Verified Fail

Repo: demo-bad. default branch has no legacy branch protection and no ruleset applies to it

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- protected\_via: 


##### Default branch has protection (legacy branch protection or a ruleset) (`C02.branch.protection-exists`) — [PASS] Verified Pass

Repo: demo-good. default branch is protected via: \[legacy\]

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- protected\_via: legacy


##### Default branch requires at least one approving review before merge (`C02.branch.required-reviews`) — [FAIL] Verified Fail

Repo: demo-bad. default branch does not require an approving review before merge

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- dismiss\_stale\_reviews: false

- required\_approving\_review\_count: 0

- review\_bypass\_actors: 

- via: 


##### Default branch requires at least one approving review before merge (`C02.branch.required-reviews`) — [PASS] Verified Pass

Repo: demo-good. default branch requires 1 approving review(s)

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- dismiss\_stale\_reviews: false

- required\_approving\_review\_count: 1

- review\_bypass\_actors: 

- via: legacy


##### Default branch requires status checks before merge (`C02.branch.required-status-checks`) — [FAIL] Verified Fail

Repo: demo-bad. default branch does not require any status checks before merge

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- required\_status\_check\_names: 

- via: 


##### Default branch requires status checks before merge (`C02.branch.required-status-checks`) — [PASS] Verified Pass

Repo: demo-good. default branch requires 1 status check(s)

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- required\_status\_check\_names: build

- via: legacy


#### PS.2.1 — [NOT CHECKABLE] Not Checkable

Make software integrity verification information available to software acquirers.

##### Releases ship checksum assets (`C07.release.checksums`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no releases match the configured release tag pattern within the lookback window

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)


##### Releases ship checksum assets (`C07.release.checksums`) — [PASS] Verified Pass

Repo: demo-good. every release in the lookback window ships a checksum asset

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)

**per\_release**

| matched\_assets | passed | reason | tag | 
|---|---|---|---|
| \["checksums.txt"\] | true | checksum asset(s) found: \[checksums.txt\] | v1.0.0 | 


##### Releases ship signature or attestation assets (`C07.release.signatures`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no releases match the configured release tag pattern within the lookback window

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)


##### Releases ship signature or attestation assets (`C07.release.signatures`) — [PASS] Verified Pass

Repo: demo-good. every release in the lookback window ships a signature/attestation asset or has a GitHub Artifact Attestation

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)

**per\_release**

| attestation\_lookup\_capped | attested\_digest | matched\_assets | passed | reason | tag | 
|---|---|---|---|---|---|
| false |  | \["checksums.txt.bundle"\] | true | signature asset(s) found: \[checksums.txt.bundle\] | v1.0.0 | 


##### Release tags are signed and GitHub reports the signature verified (`C07.release.tags-signed`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no releases match the configured release tag pattern within the lookback window

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)


##### Release tags are signed and GitHub reports the signature verified (`C07.release.tags-signed`) — [PASS] Verified Pass

Repo: demo-good. every release tag in the lookback window is signed and its signature is verified

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:20 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)

**per\_release**

| annotated | passed | reason | signed | tag | verified | 
|---|---|---|---|---|---|
| true | true | valid | true | v1.0.0 | true | 


#### PS.3.1 — _no data_

Securely archive the necessary files and supporting data (e.g., integrity verification information, provenance data) to be retained for each software release.

#### PW.4.1 — [FAIL] Verified Fail

Acquire and maintain well-secured software components (e.g., software libraries, modules, middleware, frameworks) from commercial, open-source, and other third-party developers for use by the organization's software.

##### Third-party actions and reusable workflows are pinned to a full commit SHA (`C08.actions.pinned`) — [FAIL] Verified Fail

Repo: demo-bad. 2 third-party action/reusable-workflow reference(s) are not pinned to a full-length commit SHA

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)

- skipped\_workflows: (none)

- unresolved\_external\_workflows: (none)

**first\_party\_unpinned**

| class | file | line | ref | slug | uses | 
|---|---|---|---|---|---|
| first-party | .github/workflows/pr-target-fixture.yaml | 10 | v5 | actions/checkout | actions/checkout@v5 | 

**third\_party\_unpinned**

| class | file | line | ref | slug | uses | 
|---|---|---|---|---|---|
| third-party | .github/workflows/deploy-fixture.yaml | 8 | v6 | docker/build-push-action | docker/build-push-action@v6 | 
| third-party | .github/workflows/deploy-fixture.yaml | 9 | v4 | aws-actions/configure-aws-credentials | aws-actions/configure-aws-credentials@v4 | 


##### Third-party actions and reusable workflows are pinned to a full commit SHA (`C08.actions.pinned`) — [PARTIAL] Partial

Repo: demo-good. every third-party reference is SHA-pinned, but 1 first-party actions/\* reference(s) use a mutable tag instead of a SHA

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)

- skipped\_workflows: (none)

- third\_party\_unpinned: (none)

- unresolved\_external\_workflows: (none)

**first\_party\_unpinned**

| class | file | line | ref | slug | uses | 
|---|---|---|---|---|---|
| first-party | .github/workflows/release.yaml | 12 | v5 | actions/checkout | actions/checkout@v5 | 


#### PW.4.4 — [FAIL] Verified Fail

Verify that acquired commercial, open-source, and all other third-party software components comply with the requirements, as defined by the organization, throughout their life cycles.

##### Dependabot vulnerability alerts are enabled (`C04.deps.dependabot-alerts`) — [FAIL] Verified Fail

Repo: demo-bad. Dependabot vulnerability alerts are not enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/vulnerability-alerts at 2026-08-14 05:59:18 UTC (HTTP 404, digest 9823ff5229a049b085025a16d246d1aef8fe4df5f4e335238a1d33b2b0874967)

- dependabot\_alerts\_enabled: false


##### Dependabot vulnerability alerts are enabled (`C04.deps.dependabot-alerts`) — [PASS] Verified Pass

Repo: demo-good. Dependabot vulnerability alerts are enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/vulnerability-alerts at 2026-08-14 05:59:18 UTC (HTTP 204, digest e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)

- dependabot\_alerts\_enabled: true


##### Open Dependabot alerts are triaged within the default window (`C06.sca.alerts-triaged`) — [FAIL] Verified Fail

Repo: demo-bad. Dependabot alerts are not enabled for this repository

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/dependabot/alerts at 2026-08-14 05:59:20 UTC (HTTP 403, digest c1beac3c35f574fcd0f58fc959d11e4a464a9974a02f0c4c0c0afb16b45dda5a)


##### Open Dependabot alerts are triaged within the default window (`C06.sca.alerts-triaged`) — [PASS] Verified Pass

Repo: demo-good. 0 open alert(s), no critical alert open beyond the 30-day triage window

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/dependabot/alerts at 2026-08-14 05:59:20 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- oldest\_open\_age\_days: 0

- oldest\_unclassified\_age\_days: 0

- open\_critical\_count: 0

- open\_high\_count: 0

- open\_low\_count: 0

- open\_medium\_count: 0

- open\_total\_count: 0

- open\_unclassified\_count: 0

- triage\_threshold\_days: 30


##### Dependabot config covers the repo's detected dependency ecosystems (`C06.sca.dependabot-config`) — [FAIL] Verified Fail

Repo: demo-bad. no Dependabot config found; 1 detected ecosystem(s) are uncovered

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/contents/ at 2026-08-14 05:59:19 UTC (HTTP 200, digest d89bb027c06e65a8d878a29d4ff725c7a25da56aead63c3fefef6ad5cb9ad313)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yml at 2026-08-14 05:59:19 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- detected\_ecosystems: github-actions

- uncovered\_ecosystems: github-actions


##### Dependabot config covers the repo's detected dependency ecosystems (`C06.sca.dependabot-config`) — [FAIL] Verified Fail

Repo: demo-good. no Dependabot config found; 1 detected ecosystem(s) are uncovered

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/contents/ at 2026-08-14 05:59:20 UTC (HTTP 200, digest 6d37f7c4f592d43db39aa75eb69666c1c376dee2ed272a5c3a3ea8505eac1ab5)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- detected\_ecosystems: github-actions

- uncovered\_ecosystems: github-actions


##### Dependency review is enforced as a required check on pull requests (`C06.sca.dependency-review`) — [FAIL] Verified Fail

Repo: demo-bad. no dependency-review-action (or equivalent) workflow detected

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:20 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:20 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)


##### Dependency review is enforced as a required check on pull requests (`C06.sca.dependency-review`) — [FAIL] Verified Fail

Repo: demo-good. no dependency-review-action (or equivalent) workflow detected

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:21 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:21 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)


##### An SCA tool ran for each release in the lookback window (`C06.sca.ran-per-release`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no releases match the configured release tag pattern within the lookback window

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- dropped\_tags: 0


##### An SCA tool ran for each release in the lookback window (`C06.sca.ran-per-release`) — [FAIL] Verified Fail

Repo: demo-good. at least one release in the lookback window has no matched SCA run at all

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)

- dropped\_tags: 0

**per\_release**

| status | tag | 
|---|---|
| missing | v1.0.0 | 


##### An SCA tool is configured (`C06.sca.tool-configured`) — [FAIL] Verified Fail

Repo: demo-bad. no SCA tool detected in any workflow, and no Dependabot config found

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yml at 2026-08-14 05:59:19 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- dependabot\_configured: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


##### An SCA tool is configured (`C06.sca.tool-configured`) — [FAIL] Verified Fail

Repo: demo-good. no SCA tool detected in any workflow, and no Dependabot config found

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- dependabot\_configured: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


#### PW.7.1 — [FAIL] Verified Fail

Determine whether code review (a person looks directly at the code to find issues) and/or code analysis (tools are used to find issues in code, either in a fully automated way or in conjunction with a person) should be used, as defined by the organization.

##### CodeQL default setup is configured (`C05.sast.default-setup`) — [FAIL] Verified Fail

Repo: demo-bad. CodeQL default setup is "not-configured"

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/code-scanning/default-setup at 2026-08-14 05:59:19 UTC (HTTP 200, digest 42357385cf151d57ee6a21d7399ad340616105dc9c88108071663c7657ae66ad)

- state: not-configured

- languages: actions


##### CodeQL default setup is configured (`C05.sast.default-setup`) — [FAIL] Verified Fail

Repo: demo-good. CodeQL default setup is "not-configured"

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/code-scanning/default-setup at 2026-08-14 05:59:19 UTC (HTTP 200, digest 42357385cf151d57ee6a21d7399ad340616105dc9c88108071663c7657ae66ad)

- state: not-configured

- languages: actions


##### A SAST tool is configured (`C05.sast.tool-configured`) — [FAIL] Verified Fail

Repo: demo-bad. no SAST tool detected in any workflow, and CodeQL default setup is not configured

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- codeql\_default\_setup: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


##### A SAST tool is configured (`C05.sast.tool-configured`) — [FAIL] Verified Fail

Repo: demo-good. no SAST tool detected in any workflow, and CodeQL default setup is not configured

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)

- codeql\_default\_setup: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


#### PW.8.1 — _no data_

Determine whether executable code testing should be performed to find vulnerabilities not identified by previous reviews, analysis, or testing and, if so, which types of testing should be used.

#### RV.1.1 — [FAIL] Verified Fail

Gather information from software acquirers, users, and public sources on potential vulnerabilities in the software and third-party components that the software uses, and investigate all credible reports.

##### SECURITY.md advertises an actionable intake channel (`C10.vdp.intake-channel`) — [FAIL] Verified Fail

Repo: demo-bad. no SECURITY.md exists to advertise an intake channel

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/docs/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/.github/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/docs/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)


##### SECURITY.md advertises an actionable intake channel (`C10.vdp.intake-channel`) — [FAIL] Verified Fail

Repo: demo-good. no SECURITY.md exists to advertise an intake channel

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/docs/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/docs/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)


##### GitHub private vulnerability reporting is enabled (`C10.vdp.private-reporting`) — [FAIL] Verified Fail

Repo: demo-bad. private vulnerability reporting is not enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/private-vulnerability-reporting at 2026-08-14 05:59:21 UTC (HTTP 200, digest 5acf3ff77b4420677b5923071f303facaba7a9273a346284a667a275df325146)


##### GitHub private vulnerability reporting is enabled (`C10.vdp.private-reporting`) — [FAIL] Verified Fail

Repo: demo-good. private vulnerability reporting is not enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/private-vulnerability-reporting at 2026-08-14 05:59:21 UTC (HTTP 200, digest 5acf3ff77b4420677b5923071f303facaba7a9273a346284a667a275df325146)



### Cluster 3: Provenance for internal and third-party code — [FAIL] Verified Fail

> The software producer maintains provenance for internal code and third-party components incorporated into the software to the greatest extent feasible.

#### PO.1.3 — _no data_

Communicate requirements to all third parties who will provide commercial software components to the organization for reuse by the organization's own software.

#### PO.3.2 — _no data_

Follow recommended security practices to deploy, operate, and maintain tools and toolchains.

#### PO.5.1 — [FAIL] Verified Fail

Separate and protect each environment involved in software development.

##### Org requires two-factor authentication (`C01.org.2fa-required`) — [FAIL] Verified Fail

org does not require two-factor authentication for members

Evidence:
- GET /orgs/Qloud-ltd-com at 2026-08-14 05:59:17 UTC (HTTP 200, digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)

- two\_factor\_requirement\_enabled: false


##### Count of members without two-factor authentication (`C01.org.members-without-2fa`) — [PASS] Verified Pass

all org members have two-factor authentication enabled

Evidence:
- GET /orgs/Qloud-ltd-com/members at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- members\_without\_2fa\_count: 0


##### Production-like environments restrict which branches/tags can deploy (`C03.env.branch-policy`) — [FAIL] Verified Fail

Repo: demo-bad. environment(s) that allow deployment from any branch: \[production\]

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)

- environments\_allowing\_any\_branch: production

- production\_like\_environments: production


##### Production-like environments restrict which branches/tags can deploy (`C03.env.branch-policy`) — [PASS] Verified Pass

Repo: demo-good. every production-like environment restricts which branches/tags can deploy

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest ffcebe166089955525006cf81320099a8c985b500225d3c3084c29f38efbfb0d)

- environments\_allowing\_any\_branch: 

- production\_like\_environments: production


##### A production-like environment exists (`C03.env.exists`) — [PASS] Verified Pass

Repo: demo-bad. 1 production-like environment(s) found among 1 total

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)

- production\_like\_heuristic: name matches prod\*/production, case-insensitive

- all\_environment\_names: production

- production\_like\_environments: production


##### A production-like environment exists (`C03.env.exists`) — [PASS] Verified Pass

Repo: demo-good. 1 production-like environment(s) found among 1 total

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest ffcebe166089955525006cf81320099a8c985b500225d3c3084c29f38efbfb0d)

- production\_like\_heuristic: name matches prod\*/production, case-insensitive

- all\_environment\_names: production

- production\_like\_environments: production


##### Production-like environments have at least one protection rule (`C03.env.protection-rules`) — [FAIL] Verified Fail

Repo: demo-bad. environment(s) with no protection rules: \[production\]

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)

- environments\_without\_protection: production

- production\_like\_environments: production


##### Production-like environments have at least one protection rule (`C03.env.protection-rules`) — [PASS] Verified Pass

Repo: demo-good. every production-like environment has at least one protection rule

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest ffcebe166089955525006cf81320099a8c985b500225d3c3084c29f38efbfb0d)

- environments\_without\_protection: 

- production\_like\_environments: production


##### Production-like environments require reviewer approval before deployment (`C03.env.required-reviewers`) — [FAIL] Verified Fail

Repo: demo-bad. environment(s) without required reviewers: \[production\]

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest 5041b582b876bdfbcafaa4540bc6403119adb2aeea336f161ffe85a68345268d)

- environments\_without\_required\_reviewers: production

- production\_like\_environments: production


##### Production-like environments require reviewer approval before deployment (`C03.env.required-reviewers`) — [PASS] Verified Pass

Repo: demo-good. every production-like environment requires reviewer approval

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/environments at 2026-08-14 05:59:17 UTC (HTTP 200, digest ffcebe166089955525006cf81320099a8c985b500225d3c3084c29f38efbfb0d)

- environments\_without\_required\_reviewers: 

- production\_like\_environments: production


##### Org enables secret/dependency security features by default for new repos (`C04.org.security-defaults`) — [FAIL] Verified Fail

not every security feature is enabled by default for new repositories

Evidence:
- GET /orgs/Qloud-ltd-com at 2026-08-14 05:59:17 UTC (HTTP 200, digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)

- advanced\_security\_enabled\_for\_new\_repositories: false

- dependabot\_alerts\_enabled\_for\_new\_repositories: true

- secret\_scanning\_enabled\_for\_new\_repositories: true

- secret\_scanning\_push\_protection\_enabled\_for\_new\_repositories: true


##### GitHub Advanced Security is enabled where applicable (`C04.secrets.advanced-security`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. not applicable to public repositories (GHAS licensing only gates private-repo features)

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)


##### GitHub Advanced Security is enabled where applicable (`C04.secrets.advanced-security`) — [NOT CHECKABLE] Not Checkable

Repo: demo-good. not applicable to public repositories (GHAS licensing only gates private-repo features)

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)


##### Secret scanning push protection is active (`C04.secrets.push-protection`) — [FAIL] Verified Fail

Repo: demo-bad. secret scanning push protection is not enabled (freely available on public repos)

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)

- private: false

- push\_protection\_status: disabled


##### Secret scanning push protection is active (`C04.secrets.push-protection`) — [PASS] Verified Pass

Repo: demo-good. secret scanning push protection is enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)

- private: false

- push\_protection\_status: enabled


##### Secret scanning is active (`C04.secrets.scanning-enabled`) — [FAIL] Verified Fail

Repo: demo-bad. secret scanning is not enabled (freely available on public repos)

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)

- private: false

- secret\_scanning\_status: disabled


##### Secret scanning is active (`C04.secrets.scanning-enabled`) — [PASS] Verified Pass

Repo: demo-good. secret scanning is enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)

- private: false

- secret\_scanning\_status: enabled


##### Cloud deployments use OIDC rather than long-lived static credentials (`C08.actions.oidc-vs-secrets`) — [FAIL] Verified Fail

Repo: demo-bad. 1 cloud-deployment login step(s) use long-lived static credentials instead of OIDC

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)

- skipped\_workflows: (none)

**logins**

| cloud | file | line | uses | verdict | 
|---|---|---|---|---|
| aws | .github/workflows/deploy-fixture.yaml | 9 | aws-actions/configure-aws-credentials@v4 | static | 


##### Cloud deployments use OIDC rather than long-lived static credentials (`C08.actions.oidc-vs-secrets`) — [NOT CHECKABLE] Not Checkable

Repo: demo-good. no cloud-deployment login action (AWS/Azure/GCP) detected among the workflow files that could be fetched and parsed on the default branch

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)

- skipped\_workflows: (none)


##### pull\_request\_target is not combined with checking out the PR head (`C08.actions.pull-request-target`) — [FAIL] Verified Fail

Repo: demo-bad. at least one pull\_request\_target workflow checks out the PR head commit/branch — this combination runs attacker-controlled code with base-repo secrets and token access

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)

- bare\_usage: 

- skipped\_workflows: (none)

**dangerous**

| file | line | uses | 
|---|---|---|
| .github/workflows/pr-target-fixture.yaml | 10 | actions/checkout@v5 | 


##### pull\_request\_target is not combined with checking out the PR head (`C08.actions.pull-request-target`) — [PASS] Verified Pass

Repo: demo-good. no workflow triggers on pull\_request\_target

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)

- bare\_usage: 

- dangerous: 

- skipped\_workflows: (none)


##### Self-hosted runners are not exposed to public-repo pull requests (`C08.actions.self-hosted`) — [PARTIAL] Partial

Repo: demo-bad. self-hosted runner(s) are used on a public repository — an external contributor's pull request is a potential path to them

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)

- repo\_private: false

- skipped\_workflows: (none)

**self\_hosted\_jobs**

| file | job | line | 
|---|---|---|
| .github/workflows/deploy-fixture.yaml | deploy | 5 | 


##### Self-hosted runners are not exposed to public-repo pull requests (`C08.actions.self-hosted`) — [PASS] Verified Pass

Repo: demo-good. no self-hosted runner usage detected

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)

- repo\_private: false

- self\_hosted\_jobs: 

- skipped\_workflows: (none)


##### Workflows declare explicit, least-privilege GITHUB\_TOKEN permissions (`C08.actions.token-permissions`) — [PARTIAL] Partial

Repo: demo-bad. 1 of 2 job(s)/workflow(s) declare explicit permissions; the rest rely on the default GITHUB\_TOKEN permissions

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/actions/permissions/workflow at 2026-08-14 05:59:19 UTC (HTTP 200, digest f6e178fc1e56cf43900da383f85398b61de9ae61c6b8433116c1856605745924)

- repo\_default\_workflow\_permissions: read

- skipped\_workflows: (none)

**findings**

| file | job | line | verdict | 
|---|---|---|---|
| .github/workflows/deploy-fixture.yaml | deploy | 5 | missing | 
| .github/workflows/pr-target-fixture.yaml | label | 7 | explicit | 


##### Workflows declare explicit, least-privilege GITHUB\_TOKEN permissions (`C08.actions.token-permissions`) — [PARTIAL] Partial

Repo: demo-good. 1 of 2 job(s)/workflow(s) declare explicit permissions; the rest rely on the default GITHUB\_TOKEN permissions

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/actions/permissions/workflow at 2026-08-14 05:59:19 UTC (HTTP 200, digest f6e178fc1e56cf43900da383f85398b61de9ae61c6b8433116c1856605745924)

- repo\_default\_workflow\_permissions: read

- skipped\_workflows: (none)

**findings**

| file | job | line | verdict | 
|---|---|---|---|
| .github/workflows/ci.yaml | build | 4 | missing | 
| .github/workflows/release.yaml | release | 9 | explicit | 


##### Audit-log export/streaming is configured (`C09.audit.log-streaming`) — [NOT CHECKABLE] Not Checkable

audit-log streaming/export is configured exclusively at the GitHub Enterprise account level (/enterprises/{enterprise}/audit-log/streams), not the organization level — there is no API this org/repo-scoped tool can query to determine whether it's configured


##### Organization audit log is reachable via the API (`C09.audit.org-log-available`) — [NOT CHECKABLE] Not Checkable

GET /orgs/{org}/audit-log returned 404 — either the org's plan doesn't include GitHub Enterprise Cloud's audit-log API, or the token lacks the read:audit\_log scope (GitHub returns the same status for both, so this can't be told apart from the response alone)

Evidence:
- GET /orgs/Qloud-ltd-com/audit-log at 2026-08-14 05:59:19 UTC (HTTP 404, digest 875304a522b4c5c07101c03cd5eab96b2818c9fa2be10733c0cd426613baa6d8)
- GET /orgs/Qloud-ltd-com at 2026-08-14 05:59:20 UTC (HTTP 200, digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)

- org\_plan: free


##### Audit-log retention window (informational) (`C09.audit.retention-awareness`) — [NOT CHECKABLE] Not Checkable

informational only — GitHub's documented audit-log retention window is provided as context; no API exposes what retention actually applies to this specific org

- documented\_retention\_days: 180

- note: GitHub's docs state the audit log lists events from the last 180 days. Exporting/streaming (Enterprise-only, see C09.audit.log-streaming) is GitHub's documented mechanism for retention beyond that window.

- source\_url: https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization


##### A webhook exports push/release/deployment events (`C09.repo.webhooks`) — [FAIL] Verified Fail

Repo: demo-bad. no active webhook subscribes to push, release, or deployment events

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/hooks at 2026-08-14 05:59:20 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- webhooks: (none)


##### A webhook exports push/release/deployment events (`C09.repo.webhooks`) — [FAIL] Verified Fail

Repo: demo-good. no active webhook subscribes to push, release, or deployment events

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/hooks at 2026-08-14 05:59:20 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- webhooks: (none)


##### If GitHub's own audit-log API or streaming isn't available (e.g. a non-Enterprise plan, or streaming being an Enterprise-account-only feature this tool can't query — see C09.audit.log-streaming), does the producer export or retain audit/access logs through another mechanism, and for how long? (`SA.audit-log-export-fallback`) — [NOT CHECKABLE] Not Checkable

no self-attestation provided for this question


#### PO.5.2 — _no data_

Secure and harden development endpoints (i.e., endpoints for software designers, developers, testers, builders, etc.) to perform development-related tasks using a risk-based approach.

#### PS.3.1 — _no data_

Securely archive the necessary files and supporting data (e.g., integrity verification information, provenance data) to be retained for each software release.

#### PS.3.2 — [FAIL] Verified Fail

Collect, safeguard, maintain, and share provenance data for all components of each software release (e.g., in a software bill of materials [SBOM]).

##### Release artifacts are traceable to a workflow run on the release commit (`C07.provenance.commit-linkage`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no releases match the configured release tag pattern within the lookback window

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)


##### Release artifacts are traceable to a workflow run on the release commit (`C07.provenance.commit-linkage`) — [PASS] Verified Pass

Repo: demo-good. every release in the lookback window is traceable to a workflow run on its commit

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:20 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)
- GET /repos/Qloud-ltd-com/demo-good/actions/runs at 2026-08-14 05:59:20 UTC (HTTP 200, digest 9c7d255cb4e1b8df2f362e8b3804763a23ec490ed8f9087288978e039321d4dc)

**per\_release**

| passed | reason | run\_count | tag | 
|---|---|---|---|
| true | 3 workflow run(s) found on this release's commit | 3 | v1.0.0 | 


##### A provenance-generating tool is configured (`C07.provenance.workflow`) — [FAIL] Verified Fail

Repo: demo-bad. no provenance-generating tool (Sigstore/cosign, SLSA generator, or GitHub Attestations) detected in any workflow

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


##### A provenance-generating tool is configured (`C07.provenance.workflow`) — [PASS] Verified Pass

Repo: demo-good. a provenance-generating tool is configured

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: Sigstore cosign


##### Releases ship signature or attestation assets (`C07.release.signatures`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no releases match the configured release tag pattern within the lookback window

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)


##### Releases ship signature or attestation assets (`C07.release.signatures`) — [PASS] Verified Pass

Repo: demo-good. every release in the lookback window ships a signature/attestation asset or has a GitHub Artifact Attestation

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)

**per\_release**

| attestation\_lookup\_capped | attested\_digest | matched\_assets | passed | reason | tag | 
|---|---|---|---|---|---|
| false |  | \["checksums.txt.bundle"\] | true | signature asset(s) found: \[checksums.txt.bundle\] | v1.0.0 | 


#### PW.4.1 — [FAIL] Verified Fail

Acquire and maintain well-secured software components (e.g., software libraries, modules, middleware, frameworks) from commercial, open-source, and other third-party developers for use by the organization's software.

##### Third-party actions and reusable workflows are pinned to a full commit SHA (`C08.actions.pinned`) — [FAIL] Verified Fail

Repo: demo-bad. 2 third-party action/reusable-workflow reference(s) are not pinned to a full-length commit SHA

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)

- skipped\_workflows: (none)

- unresolved\_external\_workflows: (none)

**first\_party\_unpinned**

| class | file | line | ref | slug | uses | 
|---|---|---|---|---|---|
| first-party | .github/workflows/pr-target-fixture.yaml | 10 | v5 | actions/checkout | actions/checkout@v5 | 

**third\_party\_unpinned**

| class | file | line | ref | slug | uses | 
|---|---|---|---|---|---|
| third-party | .github/workflows/deploy-fixture.yaml | 8 | v6 | docker/build-push-action | docker/build-push-action@v6 | 
| third-party | .github/workflows/deploy-fixture.yaml | 9 | v4 | aws-actions/configure-aws-credentials | aws-actions/configure-aws-credentials@v4 | 


##### Third-party actions and reusable workflows are pinned to a full commit SHA (`C08.actions.pinned`) — [PARTIAL] Partial

Repo: demo-good. every third-party reference is SHA-pinned, but 1 first-party actions/\* reference(s) use a mutable tag instead of a SHA

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)

- skipped\_workflows: (none)

- third\_party\_unpinned: (none)

- unresolved\_external\_workflows: (none)

**first\_party\_unpinned**

| class | file | line | ref | slug | uses | 
|---|---|---|---|---|---|
| first-party | .github/workflows/release.yaml | 12 | v5 | actions/checkout | actions/checkout@v5 | 


#### PW.4.4 — [FAIL] Verified Fail

Verify that acquired commercial, open-source, and all other third-party software components comply with the requirements, as defined by the organization, throughout their life cycles.

##### Dependabot vulnerability alerts are enabled (`C04.deps.dependabot-alerts`) — [FAIL] Verified Fail

Repo: demo-bad. Dependabot vulnerability alerts are not enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/vulnerability-alerts at 2026-08-14 05:59:18 UTC (HTTP 404, digest 9823ff5229a049b085025a16d246d1aef8fe4df5f4e335238a1d33b2b0874967)

- dependabot\_alerts\_enabled: false


##### Dependabot vulnerability alerts are enabled (`C04.deps.dependabot-alerts`) — [PASS] Verified Pass

Repo: demo-good. Dependabot vulnerability alerts are enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/vulnerability-alerts at 2026-08-14 05:59:18 UTC (HTTP 204, digest e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)

- dependabot\_alerts\_enabled: true


##### Open Dependabot alerts are triaged within the default window (`C06.sca.alerts-triaged`) — [FAIL] Verified Fail

Repo: demo-bad. Dependabot alerts are not enabled for this repository

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/dependabot/alerts at 2026-08-14 05:59:20 UTC (HTTP 403, digest c1beac3c35f574fcd0f58fc959d11e4a464a9974a02f0c4c0c0afb16b45dda5a)


##### Open Dependabot alerts are triaged within the default window (`C06.sca.alerts-triaged`) — [PASS] Verified Pass

Repo: demo-good. 0 open alert(s), no critical alert open beyond the 30-day triage window

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/dependabot/alerts at 2026-08-14 05:59:20 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- oldest\_open\_age\_days: 0

- oldest\_unclassified\_age\_days: 0

- open\_critical\_count: 0

- open\_high\_count: 0

- open\_low\_count: 0

- open\_medium\_count: 0

- open\_total\_count: 0

- open\_unclassified\_count: 0

- triage\_threshold\_days: 30


##### Dependabot config covers the repo's detected dependency ecosystems (`C06.sca.dependabot-config`) — [FAIL] Verified Fail

Repo: demo-bad. no Dependabot config found; 1 detected ecosystem(s) are uncovered

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/contents/ at 2026-08-14 05:59:19 UTC (HTTP 200, digest d89bb027c06e65a8d878a29d4ff725c7a25da56aead63c3fefef6ad5cb9ad313)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yml at 2026-08-14 05:59:19 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- detected\_ecosystems: github-actions

- uncovered\_ecosystems: github-actions


##### Dependabot config covers the repo's detected dependency ecosystems (`C06.sca.dependabot-config`) — [FAIL] Verified Fail

Repo: demo-good. no Dependabot config found; 1 detected ecosystem(s) are uncovered

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/contents/ at 2026-08-14 05:59:20 UTC (HTTP 200, digest 6d37f7c4f592d43db39aa75eb69666c1c376dee2ed272a5c3a3ea8505eac1ab5)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- detected\_ecosystems: github-actions

- uncovered\_ecosystems: github-actions


##### Dependency review is enforced as a required check on pull requests (`C06.sca.dependency-review`) — [FAIL] Verified Fail

Repo: demo-bad. no dependency-review-action (or equivalent) workflow detected

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:20 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:20 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)


##### Dependency review is enforced as a required check on pull requests (`C06.sca.dependency-review`) — [FAIL] Verified Fail

Repo: demo-good. no dependency-review-action (or equivalent) workflow detected

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:21 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:21 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)


##### An SCA tool ran for each release in the lookback window (`C06.sca.ran-per-release`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no releases match the configured release tag pattern within the lookback window

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- dropped\_tags: 0


##### An SCA tool ran for each release in the lookback window (`C06.sca.ran-per-release`) — [FAIL] Verified Fail

Repo: demo-good. at least one release in the lookback window has no matched SCA run at all

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)

- dropped\_tags: 0

**per\_release**

| status | tag | 
|---|---|
| missing | v1.0.0 | 


##### An SCA tool is configured (`C06.sca.tool-configured`) — [FAIL] Verified Fail

Repo: demo-bad. no SCA tool detected in any workflow, and no Dependabot config found

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yml at 2026-08-14 05:59:19 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- dependabot\_configured: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


##### An SCA tool is configured (`C06.sca.tool-configured`) — [FAIL] Verified Fail

Repo: demo-good. no SCA tool detected in any workflow, and no Dependabot config found

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- dependabot\_configured: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


#### RV.1.1 — [FAIL] Verified Fail

Gather information from software acquirers, users, and public sources on potential vulnerabilities in the software and third-party components that the software uses, and investigate all credible reports.

##### SECURITY.md advertises an actionable intake channel (`C10.vdp.intake-channel`) — [FAIL] Verified Fail

Repo: demo-bad. no SECURITY.md exists to advertise an intake channel

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/docs/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/.github/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/docs/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)


##### SECURITY.md advertises an actionable intake channel (`C10.vdp.intake-channel`) — [FAIL] Verified Fail

Repo: demo-good. no SECURITY.md exists to advertise an intake channel

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/docs/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/docs/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)


##### GitHub private vulnerability reporting is enabled (`C10.vdp.private-reporting`) — [FAIL] Verified Fail

Repo: demo-bad. private vulnerability reporting is not enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/private-vulnerability-reporting at 2026-08-14 05:59:21 UTC (HTTP 200, digest 5acf3ff77b4420677b5923071f303facaba7a9273a346284a667a275df325146)


##### GitHub private vulnerability reporting is enabled (`C10.vdp.private-reporting`) — [FAIL] Verified Fail

Repo: demo-good. private vulnerability reporting is not enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/private-vulnerability-reporting at 2026-08-14 05:59:21 UTC (HTTP 200, digest 5acf3ff77b4420677b5923071f303facaba7a9273a346284a667a275df325146)


#### RV.1.2 — [FAIL] Verified Fail

Review, analyze, and/or test the software's code to identify or confirm the presence of previously undetected vulnerabilities.

##### SAST run cadence over the lookback window (`C05.sast.cadence`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no SAST tool is configured; cadence cannot be computed

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)


##### SAST run cadence over the lookback window (`C05.sast.cadence`) — [NOT CHECKABLE] Not Checkable

Repo: demo-good. no SAST tool is configured; cadence cannot be computed

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)


##### CodeQL default setup is configured (`C05.sast.default-setup`) — [FAIL] Verified Fail

Repo: demo-bad. CodeQL default setup is "not-configured"

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/code-scanning/default-setup at 2026-08-14 05:59:19 UTC (HTTP 200, digest 42357385cf151d57ee6a21d7399ad340616105dc9c88108071663c7657ae66ad)

- state: not-configured

- languages: actions


##### CodeQL default setup is configured (`C05.sast.default-setup`) — [FAIL] Verified Fail

Repo: demo-good. CodeQL default setup is "not-configured"

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/code-scanning/default-setup at 2026-08-14 05:59:19 UTC (HTTP 200, digest 42357385cf151d57ee6a21d7399ad340616105dc9c88108071663c7657ae66ad)

- state: not-configured

- languages: actions


##### A SAST tool ran for each release in the lookback window (`C05.sast.ran-per-release`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no releases match the configured release tag pattern within the lookback window

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- dropped\_tags: 0


##### A SAST tool ran for each release in the lookback window (`C05.sast.ran-per-release`) — [FAIL] Verified Fail

Repo: demo-good. at least one release in the lookback window has no matched SAST run at all

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)

- dropped\_tags: 0

**per\_release**

| status | tag | 
|---|---|
| missing | v1.0.0 | 


##### A SAST tool is configured (`C05.sast.tool-configured`) — [FAIL] Verified Fail

Repo: demo-bad. no SAST tool detected in any workflow, and CodeQL default setup is not configured

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- codeql\_default\_setup: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


##### A SAST tool is configured (`C05.sast.tool-configured`) — [FAIL] Verified Fail

Repo: demo-good. no SAST tool detected in any workflow, and CodeQL default setup is not configured

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)

- codeql\_default\_setup: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


##### An SCA tool ran for each release in the lookback window (`C06.sca.ran-per-release`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no releases match the configured release tag pattern within the lookback window

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- dropped\_tags: 0


##### An SCA tool ran for each release in the lookback window (`C06.sca.ran-per-release`) — [FAIL] Verified Fail

Repo: demo-good. at least one release in the lookback window has no matched SCA run at all

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)

- dropped\_tags: 0

**per\_release**

| status | tag | 
|---|---|
| missing | v1.0.0 | 


##### An SCA tool is configured (`C06.sca.tool-configured`) — [FAIL] Verified Fail

Repo: demo-bad. no SCA tool detected in any workflow, and no Dependabot config found

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yml at 2026-08-14 05:59:19 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- dependabot\_configured: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


##### An SCA tool is configured (`C06.sca.tool-configured`) — [FAIL] Verified Fail

Repo: demo-good. no SCA tool detected in any workflow, and no Dependabot config found

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- dependabot\_configured: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)



### Cluster 4: Automated vulnerability checking, pre-release, and disclosure program — [FAIL] Verified Fail

> The software producer employs automated tools or comparable processes that check for security vulnerabilities. In addition: a) The software producer operates these processes on an ongoing basis and prior to product, version, or update releases; b) The software producer has a policy or process to address discovered security vulnerabilities prior to product release; and c) The software producer operates a vulnerability disclosure program and accepts, reviews, and addresses disclosed software vulnerabilities in a timely fashion and according to any timelines specified in the vulnerability disclosure program or applicable policies.

#### PO.4.1 — _no data_

Define criteria for software security checks and track throughout the SDLC.

#### PO.4.2 — _no data_

Implement processes, mechanisms, etc. to gather and safeguard the necessary information in support of the criteria.

#### PS.1.1 — [FAIL] Verified Fail

Store all forms of code – including source code, executable code, and configuration-as-code – based on the principle of least privilege so that only authorized personnel, tools, services, etc. have access.

##### Default repository permission for members (`C01.org.default-repo-permission`) — [PASS] Verified Pass

default repository permission is "read"

Evidence:
- GET /orgs/Qloud-ltd-com at 2026-08-14 05:59:17 UTC (HTTP 200, digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)

- default\_repository\_permission: read


##### Whether members can create public repositories (`C01.org.members-can-create-public`) — [FAIL] Verified Fail

members can create public repositories (potential leak vector)

Evidence:
- GET /orgs/Qloud-ltd-com at 2026-08-14 05:59:17 UTC (HTTP 200, digest 69fe0d620674904fea5840159ad707cd3d194a2c8d7d162629c4dc5848efce7a)

- members\_can\_create\_public\_repositories: true


##### Default branch protections apply to admins (no unconditional bypass actor) (`C02.branch.admin-enforced`) — [FAIL] Verified Fail

Repo: demo-bad. default branch protections do not apply to admins

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- bypass\_actors: 

- via: 


##### Default branch protections apply to admins (no unconditional bypass actor) (`C02.branch.admin-enforced`) — [PASS] Verified Pass

Repo: demo-good. default branch protections apply to admins with no bypass actors

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- bypass\_actors: 

- via: legacy


##### Default branch blocks branch deletion (`C02.branch.deletion-blocked`) — [FAIL] Verified Fail

Repo: demo-bad. default branch allows deletion

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- via: 


##### Default branch blocks branch deletion (`C02.branch.deletion-blocked`) — [PASS] Verified Pass

Repo: demo-good. default branch blocks deletion

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- via: legacy


##### Default branch blocks force pushes (`C02.branch.force-push-blocked`) — [FAIL] Verified Fail

Repo: demo-bad. default branch allows force pushes

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- via: 


##### Default branch blocks force pushes (`C02.branch.force-push-blocked`) — [PASS] Verified Pass

Repo: demo-good. default branch blocks force pushes

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- via: legacy


##### Default branch has protection (legacy branch protection or a ruleset) (`C02.branch.protection-exists`) — [FAIL] Verified Fail

Repo: demo-bad. default branch has no legacy branch protection and no ruleset applies to it

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- protected\_via: 


##### Default branch has protection (legacy branch protection or a ruleset) (`C02.branch.protection-exists`) — [PASS] Verified Pass

Repo: demo-good. default branch is protected via: \[legacy\]

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- protected\_via: legacy


##### Default branch requires at least one approving review before merge (`C02.branch.required-reviews`) — [FAIL] Verified Fail

Repo: demo-bad. default branch does not require an approving review before merge

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- dismiss\_stale\_reviews: false

- required\_approving\_review\_count: 0

- review\_bypass\_actors: 

- via: 


##### Default branch requires at least one approving review before merge (`C02.branch.required-reviews`) — [PASS] Verified Pass

Repo: demo-good. default branch requires 1 approving review(s)

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- dismiss\_stale\_reviews: false

- required\_approving\_review\_count: 1

- review\_bypass\_actors: 

- via: legacy


##### Default branch requires status checks before merge (`C02.branch.required-status-checks`) — [FAIL] Verified Fail

Repo: demo-bad. default branch does not require any status checks before merge

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- required\_status\_check\_names: 

- via: 


##### Default branch requires status checks before merge (`C02.branch.required-status-checks`) — [PASS] Verified Pass

Repo: demo-good. default branch requires 1 status check(s)

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- required\_status\_check\_names: build

- via: legacy


#### PW.2.1 — [NOT CHECKABLE] Not Checkable

Have 1) a qualified person (or people) who were not involved with the design and/or 2) automated processes instantiated in the toolchain review the software design to confirm and enforce that it meets all of the security requirements and satisfactorily addresses the identified risk information.

##### Is the software's design reviewed — by a qualified person not involved in that design, and/or an automated process — to confirm it meets security requirements and addresses identified risk before implementation? (`SA.threat-modeling`) — [NOT CHECKABLE] Not Checkable

no self-attestation provided for this question


#### PW.4.4 — [FAIL] Verified Fail

Verify that acquired commercial, open-source, and all other third-party software components comply with the requirements, as defined by the organization, throughout their life cycles.

##### Dependabot vulnerability alerts are enabled (`C04.deps.dependabot-alerts`) — [FAIL] Verified Fail

Repo: demo-bad. Dependabot vulnerability alerts are not enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/vulnerability-alerts at 2026-08-14 05:59:18 UTC (HTTP 404, digest 9823ff5229a049b085025a16d246d1aef8fe4df5f4e335238a1d33b2b0874967)

- dependabot\_alerts\_enabled: false


##### Dependabot vulnerability alerts are enabled (`C04.deps.dependabot-alerts`) — [PASS] Verified Pass

Repo: demo-good. Dependabot vulnerability alerts are enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/vulnerability-alerts at 2026-08-14 05:59:18 UTC (HTTP 204, digest e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)

- dependabot\_alerts\_enabled: true


##### Open Dependabot alerts are triaged within the default window (`C06.sca.alerts-triaged`) — [FAIL] Verified Fail

Repo: demo-bad. Dependabot alerts are not enabled for this repository

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/dependabot/alerts at 2026-08-14 05:59:20 UTC (HTTP 403, digest c1beac3c35f574fcd0f58fc959d11e4a464a9974a02f0c4c0c0afb16b45dda5a)


##### Open Dependabot alerts are triaged within the default window (`C06.sca.alerts-triaged`) — [PASS] Verified Pass

Repo: demo-good. 0 open alert(s), no critical alert open beyond the 30-day triage window

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/dependabot/alerts at 2026-08-14 05:59:20 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- oldest\_open\_age\_days: 0

- oldest\_unclassified\_age\_days: 0

- open\_critical\_count: 0

- open\_high\_count: 0

- open\_low\_count: 0

- open\_medium\_count: 0

- open\_total\_count: 0

- open\_unclassified\_count: 0

- triage\_threshold\_days: 30


##### Dependabot config covers the repo's detected dependency ecosystems (`C06.sca.dependabot-config`) — [FAIL] Verified Fail

Repo: demo-bad. no Dependabot config found; 1 detected ecosystem(s) are uncovered

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/contents/ at 2026-08-14 05:59:19 UTC (HTTP 200, digest d89bb027c06e65a8d878a29d4ff725c7a25da56aead63c3fefef6ad5cb9ad313)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yml at 2026-08-14 05:59:19 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- detected\_ecosystems: github-actions

- uncovered\_ecosystems: github-actions


##### Dependabot config covers the repo's detected dependency ecosystems (`C06.sca.dependabot-config`) — [FAIL] Verified Fail

Repo: demo-good. no Dependabot config found; 1 detected ecosystem(s) are uncovered

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/contents/ at 2026-08-14 05:59:20 UTC (HTTP 200, digest 6d37f7c4f592d43db39aa75eb69666c1c376dee2ed272a5c3a3ea8505eac1ab5)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- detected\_ecosystems: github-actions

- uncovered\_ecosystems: github-actions


##### Dependency review is enforced as a required check on pull requests (`C06.sca.dependency-review`) — [FAIL] Verified Fail

Repo: demo-bad. no dependency-review-action (or equivalent) workflow detected

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/branches/main/protection at 2026-08-14 05:59:20 UTC (HTTP 404, digest d6020ee3b0852c3deb66c66d159cc80caabeaa66ee301778307a2a18d486450d)
- GET /repos/Qloud-ltd-com/demo-bad/rules/branches/main at 2026-08-14 05:59:20 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)


##### Dependency review is enforced as a required check on pull requests (`C06.sca.dependency-review`) — [FAIL] Verified Fail

Repo: demo-good. no dependency-review-action (or equivalent) workflow detected

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/branches/main/protection at 2026-08-14 05:59:21 UTC (HTTP 200, digest 1bc4f7c44a4c57343b30118e9289a01f1cd39bd2ae3b39d516dccc5e2e0570b3)
- GET /repos/Qloud-ltd-com/demo-good/rules/branches/main at 2026-08-14 05:59:21 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)


##### An SCA tool ran for each release in the lookback window (`C06.sca.ran-per-release`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no releases match the configured release tag pattern within the lookback window

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- dropped\_tags: 0


##### An SCA tool ran for each release in the lookback window (`C06.sca.ran-per-release`) — [FAIL] Verified Fail

Repo: demo-good. at least one release in the lookback window has no matched SCA run at all

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)

- dropped\_tags: 0

**per\_release**

| status | tag | 
|---|---|
| missing | v1.0.0 | 


##### An SCA tool is configured (`C06.sca.tool-configured`) — [FAIL] Verified Fail

Repo: demo-bad. no SCA tool detected in any workflow, and no Dependabot config found

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yml at 2026-08-14 05:59:19 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- dependabot\_configured: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


##### An SCA tool is configured (`C06.sca.tool-configured`) — [FAIL] Verified Fail

Repo: demo-good. no SCA tool detected in any workflow, and no Dependabot config found

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- dependabot\_configured: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


#### PW.5.1 — _no data_

Follow all secure coding practices that are appropriate to the development languages and environment to meet the organization's requirements.

#### PW.6.1 — _no data_

Use compiler, interpreter, and build tools that offer features to improve executable security.

#### PW.6.2 — [PARTIAL] Partial

Determine which compiler, interpreter, and build tool features should be used and how each should be configured, then implement and use the approved configurations.

##### Workflows declare explicit, least-privilege GITHUB\_TOKEN permissions (`C08.actions.token-permissions`) — [PARTIAL] Partial

Repo: demo-bad. 1 of 2 job(s)/workflow(s) declare explicit permissions; the rest rely on the default GITHUB\_TOKEN permissions

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/actions/permissions/workflow at 2026-08-14 05:59:19 UTC (HTTP 200, digest f6e178fc1e56cf43900da383f85398b61de9ae61c6b8433116c1856605745924)

- repo\_default\_workflow\_permissions: read

- skipped\_workflows: (none)

**findings**

| file | job | line | verdict | 
|---|---|---|---|
| .github/workflows/deploy-fixture.yaml | deploy | 5 | missing | 
| .github/workflows/pr-target-fixture.yaml | label | 7 | explicit | 


##### Workflows declare explicit, least-privilege GITHUB\_TOKEN permissions (`C08.actions.token-permissions`) — [PARTIAL] Partial

Repo: demo-good. 1 of 2 job(s)/workflow(s) declare explicit permissions; the rest rely on the default GITHUB\_TOKEN permissions

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/actions/permissions/workflow at 2026-08-14 05:59:19 UTC (HTTP 200, digest f6e178fc1e56cf43900da383f85398b61de9ae61c6b8433116c1856605745924)

- repo\_default\_workflow\_permissions: read

- skipped\_workflows: (none)

**findings**

| file | job | line | verdict | 
|---|---|---|---|
| .github/workflows/ci.yaml | build | 4 | missing | 
| .github/workflows/release.yaml | release | 9 | explicit | 


#### PW.7.1 — [FAIL] Verified Fail

Determine whether code review (a person looks directly at the code to find issues) and/or code analysis (tools are used to find issues in code, either in a fully automated way or in conjunction with a person) should be used, as defined by the organization.

##### CodeQL default setup is configured (`C05.sast.default-setup`) — [FAIL] Verified Fail

Repo: demo-bad. CodeQL default setup is "not-configured"

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/code-scanning/default-setup at 2026-08-14 05:59:19 UTC (HTTP 200, digest 42357385cf151d57ee6a21d7399ad340616105dc9c88108071663c7657ae66ad)

- state: not-configured

- languages: actions


##### CodeQL default setup is configured (`C05.sast.default-setup`) — [FAIL] Verified Fail

Repo: demo-good. CodeQL default setup is "not-configured"

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/code-scanning/default-setup at 2026-08-14 05:59:19 UTC (HTTP 200, digest 42357385cf151d57ee6a21d7399ad340616105dc9c88108071663c7657ae66ad)

- state: not-configured

- languages: actions


##### A SAST tool is configured (`C05.sast.tool-configured`) — [FAIL] Verified Fail

Repo: demo-bad. no SAST tool detected in any workflow, and CodeQL default setup is not configured

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- codeql\_default\_setup: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


##### A SAST tool is configured (`C05.sast.tool-configured`) — [FAIL] Verified Fail

Repo: demo-good. no SAST tool detected in any workflow, and CodeQL default setup is not configured

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)

- codeql\_default\_setup: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


#### PW.7.2 — [FAIL] Verified Fail

Perform the code review and/or code analysis based on the organization's secure coding standards, and record and triage all discovered issues and recommended remediations in the development team's workflow or issue tracking system.

##### SAST run cadence over the lookback window (`C05.sast.cadence`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no SAST tool is configured; cadence cannot be computed

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)


##### SAST run cadence over the lookback window (`C05.sast.cadence`) — [NOT CHECKABLE] Not Checkable

Repo: demo-good. no SAST tool is configured; cadence cannot be computed

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)


##### A SAST tool ran for each release in the lookback window (`C05.sast.ran-per-release`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no releases match the configured release tag pattern within the lookback window

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- dropped\_tags: 0


##### A SAST tool ran for each release in the lookback window (`C05.sast.ran-per-release`) — [FAIL] Verified Fail

Repo: demo-good. at least one release in the lookback window has no matched SAST run at all

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)

- dropped\_tags: 0

**per\_release**

| status | tag | 
|---|---|
| missing | v1.0.0 | 


#### PW.8.2 — _no data_

Scope the testing, design the tests, perform the testing, and document the results, including recording and triaging all discovered issues and recommended remediations in the development team's workflow or issue tracking system.

#### PW.9.1 — _no data_

Define a secure baseline by determining how to configure each setting that has an effect on security or a security-related setting so that the default settings are secure and do not weaken the security functions provided by the platform, network infrastructure, or services.

#### PW.9.2 — _no data_

Implement the default settings (or groups of default settings, if applicable), and document each setting for software administrators.

#### RV.1.1 — [FAIL] Verified Fail

Gather information from software acquirers, users, and public sources on potential vulnerabilities in the software and third-party components that the software uses, and investigate all credible reports.

##### SECURITY.md advertises an actionable intake channel (`C10.vdp.intake-channel`) — [FAIL] Verified Fail

Repo: demo-bad. no SECURITY.md exists to advertise an intake channel

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/docs/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/.github/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/docs/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)


##### SECURITY.md advertises an actionable intake channel (`C10.vdp.intake-channel`) — [FAIL] Verified Fail

Repo: demo-good. no SECURITY.md exists to advertise an intake channel

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/docs/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/docs/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)


##### GitHub private vulnerability reporting is enabled (`C10.vdp.private-reporting`) — [FAIL] Verified Fail

Repo: demo-bad. private vulnerability reporting is not enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/private-vulnerability-reporting at 2026-08-14 05:59:21 UTC (HTTP 200, digest 5acf3ff77b4420677b5923071f303facaba7a9273a346284a667a275df325146)


##### GitHub private vulnerability reporting is enabled (`C10.vdp.private-reporting`) — [FAIL] Verified Fail

Repo: demo-good. private vulnerability reporting is not enabled

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/private-vulnerability-reporting at 2026-08-14 05:59:21 UTC (HTTP 200, digest 5acf3ff77b4420677b5923071f303facaba7a9273a346284a667a275df325146)


#### RV.1.2 — [FAIL] Verified Fail

Review, analyze, and/or test the software's code to identify or confirm the presence of previously undetected vulnerabilities.

##### SAST run cadence over the lookback window (`C05.sast.cadence`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no SAST tool is configured; cadence cannot be computed

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)


##### SAST run cadence over the lookback window (`C05.sast.cadence`) — [NOT CHECKABLE] Not Checkable

Repo: demo-good. no SAST tool is configured; cadence cannot be computed

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)


##### CodeQL default setup is configured (`C05.sast.default-setup`) — [FAIL] Verified Fail

Repo: demo-bad. CodeQL default setup is "not-configured"

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/code-scanning/default-setup at 2026-08-14 05:59:19 UTC (HTTP 200, digest 42357385cf151d57ee6a21d7399ad340616105dc9c88108071663c7657ae66ad)

- state: not-configured

- languages: actions


##### CodeQL default setup is configured (`C05.sast.default-setup`) — [FAIL] Verified Fail

Repo: demo-good. CodeQL default setup is "not-configured"

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/code-scanning/default-setup at 2026-08-14 05:59:19 UTC (HTTP 200, digest 42357385cf151d57ee6a21d7399ad340616105dc9c88108071663c7657ae66ad)

- state: not-configured

- languages: actions


##### A SAST tool ran for each release in the lookback window (`C05.sast.ran-per-release`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no releases match the configured release tag pattern within the lookback window

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- dropped\_tags: 0


##### A SAST tool ran for each release in the lookback window (`C05.sast.ran-per-release`) — [FAIL] Verified Fail

Repo: demo-good. at least one release in the lookback window has no matched SAST run at all

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)

- dropped\_tags: 0

**per\_release**

| status | tag | 
|---|---|
| missing | v1.0.0 | 


##### A SAST tool is configured (`C05.sast.tool-configured`) — [FAIL] Verified Fail

Repo: demo-bad. no SAST tool detected in any workflow, and CodeQL default setup is not configured

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:17 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- codeql\_default\_setup: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


##### A SAST tool is configured (`C05.sast.tool-configured`) — [FAIL] Verified Fail

Repo: demo-good. no SAST tool detected in any workflow, and CodeQL default setup is not configured

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:17 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)

- codeql\_default\_setup: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


##### An SCA tool ran for each release in the lookback window (`C06.sca.ran-per-release`) — [NOT CHECKABLE] Not Checkable

Repo: demo-bad. no releases match the configured release tag pattern within the lookback window

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- dropped\_tags: 0


##### An SCA tool ran for each release in the lookback window (`C06.sca.ran-per-release`) — [FAIL] Verified Fail

Repo: demo-good. at least one release in the lookback window has no matched SCA run at all

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/releases at 2026-08-14 05:59:19 UTC (HTTP 200, digest 8c212ae52974dfb9bd274a46d3c95db6c6694a3865baac1c06bb54890fa7a161)
- GET /repos/Qloud-ltd-com/demo-good/git/ref/tags/v1.0.0 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 4291ed3ccaf050aa379b00000bb2089e1c6d2780255cfbebf193cafbfe11c76a)
- GET /repos/Qloud-ltd-com/demo-good/git/tags/76a674e6b5def778389fcad5f9b62b6d056db6f1 at 2026-08-14 05:59:19 UTC (HTTP 200, digest 2d6ebef9aa879dd2539ee0c89a0690f0536b16e03cecbbb94ad8f0b840aab812)

- dropped\_tags: 0

**per\_release**

| status | tag | 
|---|---|
| missing | v1.0.0 | 


##### An SCA tool is configured (`C06.sca.tool-configured`) — [FAIL] Verified Fail

Repo: demo-bad. no SCA tool detected in any workflow, and no Dependabot config found

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad at 2026-08-14 05:59:18 UTC (HTTP 200, digest 546af54a471accc2b0955746cdb2057b5e0b3d0a64b2e5a8850cae6e4adccbd0)
- GET /repos/Qloud-ltd-com/demo-bad/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 134a8d2225358b9f793fc866fbf0b8df32fde480ec5c478cf45f2bfe5de10923)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/deploy-fixture.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest fd77baaf6ad46c399a4743e491cdbce43befb10c89e38356893f11ac496a097b)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/workflows/pr-target-fixture.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest fe017d181dd8081f2bfcdfd800909379d3e28f25d64c83012d2c50939788a8d4)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yml at 2026-08-14 05:59:19 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- dependabot\_configured: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


##### An SCA tool is configured (`C06.sca.tool-configured`) — [FAIL] Verified Fail

Repo: demo-good. no SCA tool detected in any workflow, and no Dependabot config found

Evidence:
- GET /repos/Qloud-ltd-com/demo-good at 2026-08-14 05:59:18 UTC (HTTP 200, digest 9e8641b6e7289e65efbe279a3b8ccdfe529aefaa8eac7b211a6ec40cf07af24d)
- GET /repos/Qloud-ltd-com/demo-good/actions/workflows at 2026-08-14 05:59:18 UTC (HTTP 200, digest 8054e4084a9f24276e809315134b6f99eac5f344d82a9e1f16e921eefa47a81a)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/ci.yaml at 2026-08-14 05:59:18 UTC (HTTP 200, digest 1e883fa1b7efb1e8a8dfc558c41695d370d7e5a1f1b92a64f6f41960911c305b)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/workflows/release.yaml at 2026-08-14 05:59:19 UTC (HTTP 200, digest 0e04075e598265fb688b3724a0c1aa54868a3d7d53c3a1b46fbf21225acdc865)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/dependabot.yaml at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)

- dependabot\_configured: false

- low\_confidence\_match\_only: false

- skipped\_workflows: (none)

- tool\_names: (none)


#### RV.1.3 — [FAIL] Verified Fail

Have a policy that addresses vulnerability disclosure and remediation, and implement the roles, responsibilities, and processes needed to support that policy.

##### SECURITY.md advertises an actionable intake channel (`C10.vdp.intake-channel`) — [FAIL] Verified Fail

Repo: demo-bad. no SECURITY.md exists to advertise an intake channel

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/docs/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/.github/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/docs/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)


##### SECURITY.md advertises an actionable intake channel (`C10.vdp.intake-channel`) — [FAIL] Verified Fail

Repo: demo-good. no SECURITY.md exists to advertise an intake channel

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/docs/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/docs/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)


##### A SECURITY.md resolves for this repo (`C10.vdp.security-md`) — [FAIL] Verified Fail

Repo: demo-bad. no SECURITY.md found at any of the standard locations (.github/, repo root, docs/) in this repo or the org's .github repo

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-bad/contents/docs/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/.github/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/docs/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)


##### A SECURITY.md resolves for this repo (`C10.vdp.security-md`) — [FAIL] Verified Fail

Repo: demo-good. no SECURITY.md found at any of the standard locations (.github/, repo root, docs/) in this repo or the org's .github repo

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/demo-good/contents/docs/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/.github/SECURITY.md at 2026-08-14 05:59:20 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)
- GET /repos/Qloud-ltd-com/.github/contents/docs/SECURITY.md at 2026-08-14 05:59:21 UTC (HTTP 404, digest e45906ce02e79f16fb87a838d86bb4e497e37a9591f97608fa013bbcd8b9cbc2)


##### The org has an org-wide default security policy (`C10.vdp.security-policy-org`) — [NOT CHECKABLE] Not Checkable

Qloud-ltd-com has no .github repo — no org-wide default community-health-file mechanism exists

Evidence:
- GET /repos/Qloud-ltd-com/.github at 2026-08-14 05:59:20 UTC (HTTP 404, digest 4f50e254a719a6b1b06b529bdaa08980e4acf0878aad0090cba7771f6ebdf0b9)


#### RV.2.1 — [FAIL] Verified Fail

Analyze each vulnerability to gather sufficient information about risk to plan its remediation or other risk response.

##### Open Dependabot alerts are triaged within the default window (`C06.sca.alerts-triaged`) — [FAIL] Verified Fail

Repo: demo-bad. Dependabot alerts are not enabled for this repository

Evidence:
- GET /repos/Qloud-ltd-com/demo-bad/dependabot/alerts at 2026-08-14 05:59:20 UTC (HTTP 403, digest c1beac3c35f574fcd0f58fc959d11e4a464a9974a02f0c4c0c0afb16b45dda5a)


##### Open Dependabot alerts are triaged within the default window (`C06.sca.alerts-triaged`) — [PASS] Verified Pass

Repo: demo-good. 0 open alert(s), no critical alert open beyond the 30-day triage window

Evidence:
- GET /repos/Qloud-ltd-com/demo-good/dependabot/alerts at 2026-08-14 05:59:20 UTC (HTTP 200, digest 4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945)

- oldest\_open\_age\_days: 0

- oldest\_unclassified\_age\_days: 0

- open\_critical\_count: 0

- open\_high\_count: 0

- open\_low\_count: 0

- open\_medium\_count: 0

- open\_total\_count: 0

- open\_unclassified\_count: 0

- triage\_threshold\_days: 30


##### What is the producer's target time to triage (assess the risk of) a newly reported vulnerability? (`SA.vuln-triage-sla`) — [NOT CHECKABLE] Not Checkable

no self-attestation provided for this question


#### RV.2.2 — [NOT CHECKABLE] Not Checkable

Plan and implement risk responses for vulnerabilities.

##### What is the producer's target time to remediate a confirmed vulnerability, by severity? (`SA.vuln-remediation-sla`) — [NOT CHECKABLE] Not Checkable

no self-attestation provided for this question


#### RV.3.3 — _no data_

Review the software for similar vulnerabilities to eradicate a class of vulnerabilities, and proactively fix them rather than waiting for external reports.


---

## Gaps

Every `verified-fail` or `partial` result, in one place. See poam.md for remediation tracking.

| POA&M ID | Check | Scope | Status | Reason |
|---|---|---|---|---|
| POAM-001 | C01.org.2fa-required | (org) | [FAIL] Verified Fail | org does not require two-factor authentication for members |
| POAM-015 | C01.org.members-can-create-public | (org) | [FAIL] Verified Fail | members can create public repositories (potential leak vector) |
| POAM-016 | C02.branch.admin-enforced | demo-bad | [FAIL] Verified Fail | default branch protections do not apply to admins |
| POAM-017 | C02.branch.deletion-blocked | demo-bad | [FAIL] Verified Fail | default branch allows deletion |
| POAM-018 | C02.branch.force-push-blocked | demo-bad | [FAIL] Verified Fail | default branch allows force pushes |
| POAM-019 | C02.branch.protection-exists | demo-bad | [FAIL] Verified Fail | default branch has no legacy branch protection and no ruleset applies to it |
| POAM-020 | C02.branch.required-reviews | demo-bad | [FAIL] Verified Fail | default branch does not require an approving review before merge |
| POAM-021 | C02.branch.required-status-checks | demo-bad | [FAIL] Verified Fail | default branch does not require any status checks before merge |
| POAM-002 | C03.env.branch-policy | demo-bad | [FAIL] Verified Fail | environment(s) that allow deployment from any branch: \[production\] |
| POAM-003 | C03.env.protection-rules | demo-bad | [FAIL] Verified Fail | environment(s) with no protection rules: \[production\] |
| POAM-004 | C03.env.required-reviewers | demo-bad | [FAIL] Verified Fail | environment(s) without required reviewers: \[production\] |
| POAM-022 | C04.deps.dependabot-alerts | demo-bad | [FAIL] Verified Fail | Dependabot vulnerability alerts are not enabled |
| POAM-005 | C04.org.security-defaults | (org) | [FAIL] Verified Fail | not every security feature is enabled by default for new repositories |
| POAM-006 | C04.secrets.push-protection | demo-bad | [FAIL] Verified Fail | secret scanning push protection is not enabled (freely available on public repos) |
| POAM-007 | C04.secrets.scanning-enabled | demo-bad | [FAIL] Verified Fail | secret scanning is not enabled (freely available on public repos) |
| POAM-023 | C05.sast.default-setup | demo-bad | [FAIL] Verified Fail | CodeQL default setup is "not-configured" |
| POAM-024 | C05.sast.default-setup | demo-good | [FAIL] Verified Fail | CodeQL default setup is "not-configured" |
| POAM-041 | C05.sast.ran-per-release | demo-good | [FAIL] Verified Fail | at least one release in the lookback window has no matched SAST run at all |
| POAM-025 | C05.sast.tool-configured | demo-bad | [FAIL] Verified Fail | no SAST tool detected in any workflow, and CodeQL default setup is not configured |
| POAM-026 | C05.sast.tool-configured | demo-good | [FAIL] Verified Fail | no SAST tool detected in any workflow, and CodeQL default setup is not configured |
| POAM-027 | C06.sca.alerts-triaged | demo-bad | [FAIL] Verified Fail | Dependabot alerts are not enabled for this repository |
| POAM-028 | C06.sca.dependabot-config | demo-bad | [FAIL] Verified Fail | no Dependabot config found; 1 detected ecosystem(s) are uncovered |
| POAM-029 | C06.sca.dependabot-config | demo-good | [FAIL] Verified Fail | no Dependabot config found; 1 detected ecosystem(s) are uncovered |
| POAM-030 | C06.sca.dependency-review | demo-bad | [FAIL] Verified Fail | no dependency-review-action (or equivalent) workflow detected |
| POAM-031 | C06.sca.dependency-review | demo-good | [FAIL] Verified Fail | no dependency-review-action (or equivalent) workflow detected |
| POAM-032 | C06.sca.ran-per-release | demo-good | [FAIL] Verified Fail | at least one release in the lookback window has no matched SCA run at all |
| POAM-033 | C06.sca.tool-configured | demo-bad | [FAIL] Verified Fail | no SCA tool detected in any workflow, and no Dependabot config found |
| POAM-034 | C06.sca.tool-configured | demo-good | [FAIL] Verified Fail | no SCA tool detected in any workflow, and no Dependabot config found |
| POAM-042 | C07.provenance.workflow | demo-bad | [FAIL] Verified Fail | no provenance-generating tool (Sigstore/cosign, SLSA generator, or GitHub Attestations) detected in any workflow |
| POAM-008 | C08.actions.oidc-vs-secrets | demo-bad | [FAIL] Verified Fail | 1 cloud-deployment login step(s) use long-lived static credentials instead of OIDC |
| POAM-035 | C08.actions.pinned | demo-bad | [FAIL] Verified Fail | 2 third-party action/reusable-workflow reference(s) are not pinned to a full-length commit SHA |
| POAM-036 | C08.actions.pinned | demo-good | [PARTIAL] Partial | every third-party reference is SHA-pinned, but 1 first-party actions/\* reference(s) use a mutable tag instead of a SHA |
| POAM-009 | C08.actions.pull-request-target | demo-bad | [FAIL] Verified Fail | at least one pull\_request\_target workflow checks out the PR head commit/branch — this combination runs attacker-controlled code with base-repo secrets and token access |
| POAM-010 | C08.actions.self-hosted | demo-bad | [PARTIAL] Partial | self-hosted runner(s) are used on a public repository — an external contributor's pull request is a potential path to them |
| POAM-011 | C08.actions.token-permissions | demo-bad | [PARTIAL] Partial | 1 of 2 job(s)/workflow(s) declare explicit permissions; the rest rely on the default GITHUB\_TOKEN permissions |
| POAM-012 | C08.actions.token-permissions | demo-good | [PARTIAL] Partial | 1 of 2 job(s)/workflow(s) declare explicit permissions; the rest rely on the default GITHUB\_TOKEN permissions |
| POAM-013 | C09.repo.webhooks | demo-bad | [FAIL] Verified Fail | no active webhook subscribes to push, release, or deployment events |
| POAM-014 | C09.repo.webhooks | demo-good | [FAIL] Verified Fail | no active webhook subscribes to push, release, or deployment events |
| POAM-037 | C10.vdp.intake-channel | demo-bad | [FAIL] Verified Fail | no SECURITY.md exists to advertise an intake channel |
| POAM-038 | C10.vdp.intake-channel | demo-good | [FAIL] Verified Fail | no SECURITY.md exists to advertise an intake channel |
| POAM-039 | C10.vdp.private-reporting | demo-bad | [FAIL] Verified Fail | private vulnerability reporting is not enabled |
| POAM-040 | C10.vdp.private-reporting | demo-good | [FAIL] Verified Fail | private vulnerability reporting is not enabled |
| POAM-043 | C10.vdp.security-md | demo-bad | [FAIL] Verified Fail | no SECURITY.md found at any of the standard locations (.github/, repo root, docs/) in this repo or the org's .github repo |
| POAM-044 | C10.vdp.security-md | demo-good | [FAIL] Verified Fail | no SECURITY.md found at any of the standard locations (.github/, repo root, docs/) in this repo or the org's .github repo |

---

## Self-Attested & Not-Checkable Appendix

Controls in this section were **not independently verified** by this tool — either the
producer's own claim (self-attested) or a control this tool structurally cannot verify
via API (not-checkable, e.g. plan-gated or no answer on file). Neither status ever
upgrades a CISA form cluster to fully verified.

### Self-Attested

None.

### Not Checkable

| Check | Scope | Reason |
|---|---|---|
| C04.secrets.advanced-security | demo-bad | not applicable to public repositories (GHAS licensing only gates private-repo features) |
| C04.secrets.advanced-security | demo-good | not applicable to public repositories (GHAS licensing only gates private-repo features) |
| C05.sast.cadence | demo-bad | no SAST tool is configured; cadence cannot be computed |
| C05.sast.cadence | demo-good | no SAST tool is configured; cadence cannot be computed |
| C05.sast.ran-per-release | demo-bad | no releases match the configured release tag pattern within the lookback window |
| C06.sca.ran-per-release | demo-bad | no releases match the configured release tag pattern within the lookback window |
| C07.provenance.commit-linkage | demo-bad | no releases match the configured release tag pattern within the lookback window |
| C07.release.checksums | demo-bad | no releases match the configured release tag pattern within the lookback window |
| C07.release.signatures | demo-bad | no releases match the configured release tag pattern within the lookback window |
| C07.release.tags-signed | demo-bad | no releases match the configured release tag pattern within the lookback window |
| C08.actions.oidc-vs-secrets | demo-good | no cloud-deployment login action (AWS/Azure/GCP) detected among the workflow files that could be fetched and parsed on the default branch |
| C09.audit.log-streaming | (org) | audit-log streaming/export is configured exclusively at the GitHub Enterprise account level (/enterprises/{enterprise}/audit-log/streams), not the organization level — there is no API this org/repo-scoped tool can query to determine whether it's configured |
| C09.audit.org-log-available | (org) | GET /orgs/{org}/audit-log returned 404 — either the org's plan doesn't include GitHub Enterprise Cloud's audit-log API, or the token lacks the read:audit\_log scope (GitHub returns the same status for both, so this can't be told apart from the response alone) |
| C09.audit.retention-awareness | (org) | informational only — GitHub's documented audit-log retention window is provided as context; no API exposes what retention actually applies to this specific org |
| C10.vdp.security-policy-org | (org) | Qloud-ltd-com has no .github repo — no org-wide default community-health-file mechanism exists |
| SA.agency-notification-process | (org) | no self-attestation provided for this question |
| SA.audit-log-export-fallback | (org) | no self-attestation provided for this question |
| SA.dev-security-training | (org) | no self-attestation provided for this question |
| SA.threat-modeling | (org) | no self-attestation provided for this question |
| SA.vuln-remediation-sla | (org) | no self-attestation provided for this question |
| SA.vuln-triage-sla | (org) | no self-attestation provided for this question |

---

## Methodology

**Status definitions:**

- **[PASS] Verified Pass** — the tool queried the platform API and the returned state satisfies the check's pass condition. Never inferred, only observed.
- **[FAIL] Verified Fail** — the tool queried the platform API and the returned state does not satisfy the check's pass condition. Just as definitive as verified-pass.
- **[PARTIAL] Partial** — the tool queried the platform API and got a mixed or incomplete signal: some but not all of a check's sub-conditions hold, or the evidence is suggestive but not conclusive either way.
- **[SELF-ATTESTED] Self-Attested** — no API call can verify this control; the answer comes from the producer's own self-attestation questionnaire, not platform evidence.
- **[NOT CHECKABLE] Not Checkable** — the tool could not determine an answer at all (plan-gated, insufficient token permission, or an unanswered self-attestation question). An honest "unknown", never inferred as a pass or a fail.

**Lookback window:** 5 releases / 12 months, release tag pattern v\*.

**What this tool does NOT verify:** developer security training, threat-modeling practice
in depth, documented triage/remediation SLAs beyond what a self-attestation records,
agency-notification process, and any control neither an API call nor the self-attestation
questionnaire can reach. This tool is read-only: it never writes to the scanned platform,
and every claim above traces to either a specific API response (verified-*, partial,
not-checkable) or an explicit producer statement (self-attested) — never to inference,
and never faked.
