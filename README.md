<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg" />
    <img src="docs/assets/logo.svg" alt="Attestward" height="96" />
  </picture>
</p>

# Attestward

> **Everyone else helps you fill in the CISA attestation form. This tool proves what you're signing.**

**CLI binary:** `attestward`. **Product name:** Attestward.
**Status:** 1.0 — see [CHANGELOG.md](CHANGELOG.md) for what shipped. From here the CLI
surface and the evidence-pack schema follow [SemVer](https://semver.org/): breaking
changes to either mean a major version, so a pinned `v1` is safe to build against.
**License:** [Apache-2.0](LICENSE)

[![CI](https://gitlab.com/sioakeim/attestward/actions/workflows/ci.yaml/badge.svg)](https://gitlab.com/sioakeim/attestward/actions/workflows/ci.yaml)
[![Self-scan](https://gitlab.com/sioakeim/attestward/actions/workflows/self-scan.yaml/badge.svg)](https://gitlab.com/sioakeim/attestward/actions/workflows/self-scan.yaml)

---

## What this is

An open-source CLI tool that connects to a software producer's source-control and CI/CD
platform (GitHub, Azure DevOps, or a self-hosted Gogs instance) and **verifies** — rather than
asks about — the technical controls
behind a secure-software-development attestation. It maps findings to NIST SSDF (SP 800-218)
practices and the CISA Secure Software Development Attestation (SSDA) Common Form's four
practice clusters, and emits a signed, timestamped **evidence pack** (JSON + human-readable
report) plus a **gap analysis** and a **draft POA&M** for anything that fails.

### The problem

- In September 2022, [OMB M-22-18](https://bidenwhitehouse.archives.gov/wp-content/uploads/2022/09/M-22-18.pdf)
  directed federal agencies to collect a secure-software-development attestation from
  software producers before using their software; CISA published a [Common
  Form](https://www.cisa.gov/sites/default/files/2024-03/Self-Attestation-Common-Form-03082024-FINAL.pdf)
  for it in March 2024, and agencies began collecting attestations against it from then.
  **In January 2026, OMB [M-26-05](https://www.whitehouse.gov/wp-content/uploads/2026/01/M-26-05-Adopting-a-Risk-based-Approach-to-Software-and-Hardware-Security.pdf)
  rescinded the government-wide *mandate* to use that Common Form** — agencies now set
  their own risk-based approach to software security, and may still require the Common
  Form, an equivalent of their own, or nothing at all, at their own discretion.
- That policy change doesn't reduce the stakes of *actually signing* one. Whenever a
  producer attests to something the government relies on — the CISA Common Form, an
  agency-specific equivalent, or any other representation made in connection with a
  federal contract or a claim for payment — an inaccurate attestation is False Claims Act
  exposure, personally, for whoever signs it. DOJ's Civil Cyber-Fraud Initiative (launched
  2021) hasn't slowed down because the mandate did: DOJ's own [January 2026
  report](https://www.justice.gov/opa/pr/false-claims-act-settlements-and-judgments-exceed-68b-fiscal-year-2025)
  puts total FY2025 False Claims Act recoveries at a record $6.8B — its highest ever —
  and independent analyses of DOJ's own published settlement data (not the DOJ report
  itself, which doesn't break out a cyber-specific figure) put cybersecurity-related FCA
  recoveries at roughly $52M across nine settlements for FY2025, more than tripling in
  each of the past two years ([Mayer Brown, March
  2026](https://www.mayerbrown.com/en/insights/publications/2026/03/false-claims-act-enforcement-record-breaking-year-signals-continued-attention-to-cybersecurity)).
- Today's options for the long tail of small federal software vendors: sign-and-hope, or
  pay a consulting firm for a manual assessment. Nothing self-serve verifies the actual
  pipeline before you sign anything — whether what you're signing is the CISA form
  specifically or whatever your own agency now asks for instead.
- Existing "compliance automation" products primarily *ask questions and store documents*.
  This tool's differentiator is **harvested proof**: it reads the real configuration and
  run history and shows what is actually true.

## Product principles

1. **Verify, don't ask.** If a control can be checked via API, check it. Questionnaire items
   are a last resort and are always labeled `self-attested` in output.
2. **Read-only, local-first.** Runs on your machine or in your CI. Never transmits your data
   anywhere. Least-privilege tokens only.
3. **Evidence over score.** Primary output is evidence with provenance (what was checked,
   when, via which API, raw response digest) — not a vanity score.
4. **Single static binary.** Zero-friction install. No server, no database.
5. **Mappings are data, not code.** SSDF/CISA-form mappings live in versioned YAML so the
   community can extend to other frameworks without touching Go.
6. **Boring, auditable code.** Minimal dependencies, no clever magic, everything reviewable.

### What stays free

Anything a single local scan produces is free and open source, permanently: all ten
collectors, the full evidence pack, pack integrity and signing, self-attestation intake,
and every mapping. There is no paid tier of this CLI and no feature behind a licence key.

A separate commercial hosted product exists for things a local scan cannot do by
definition — a server, persistent storage across scans, multi-tenancy. That boundary is
not a pricing decision that could be moved later; [ADR-0004](docs/adr/0004-read-only-local-first.md)
rules those capabilities out of this tool on architectural grounds.

Apache-2.0 was chosen over MIT/BSD for its explicit patent grant and retaliation clause
(§3), which matters for a tool enterprises run inside their own CI. §6 withholds
trademark rights: the code is yours to use and fork, the name is not.

## A note on Gogs

Gogs is supported as a scan target, and what it can evidence is very limited — stated
here up front so nobody adopts it expecting otherwise. Gogs has **no CI, no code
scanning, no dependency alerts, no secret scanning, no environments, no audit log, and
no branch-protection API**. Of the checks below, a Gogs scan verifies the
vulnerability-disclosure ones and reports the rest as `not-checkable`, each with a
reason naming the specific limitation.

That is the tool working as intended rather than failing. The CISA form asks whether a
control exists; "the platform hosting this code cannot demonstrate it" is a truthful,
auditable answer, and it tells a producer exactly where to look instead — usually
whatever external CI system actually builds the code. What Attestward will not do is
quietly omit those checks, which would leave a reader unable to tell "not applicable
here" from "the scanner stopped early".

One specific case is worth naming: a Gogs repo mirrored from GitHub still contains
`.github/workflows/*.yml`, and the API will serve those files. Attestward deliberately
does **not** read them as SAST/SCA evidence — a workflow that provably never executes
on the platform being scanned is not evidence that scanning happened.

## What it verifies (GitHub and Azure DevOps)

The same ten collectors run against both platforms under the same check IDs. The
table below is deliberately about the **control** each collector addresses, not the
per-platform mechanism: which API backs a given check, and whether one exists at all,
is recorded in [docs/checks-reference.md](docs/checks-reference.md), which is generated
from the collector registry and therefore cannot drift away from the code.

| ID | Collector | The control it addresses |
|----|-----------|--------------------------|
| C01 | `org-security` | Organization-level identity and default access |
| C02 | `repo-protection` | The default branch cannot be bypassed |
| C03 | `env-separation` | Production deploys are gated |
| C04 | `secrets-hygiene` | Secrets are scanned for, and not stored in the clear |
| C05 | `sast-history` | SAST is configured *and* actually ran for each release |
| C06 | `sca-history` | Dependency scanning is configured and enforced |
| C07 | `provenance` | A release traces back to the build that produced it |
| C08 | `actions-security` | CI cannot be turned into a supply-chain foothold |
| C09 | `audit-logging` | Security-relevant events are recorded and exportable |
| C10 | `vdp` | There is a way to report a vulnerability |

**Coverage is not symmetric, and the gaps are structural rather than configurable.**
Some controls have no API on one platform at all; a few have one this tool deliberately
does not read. Either way the check reports `not-checkable` permanently — no plan upgrade
and no token scope changes it. The notable cases:

- **Azure DevOps has no release-asset concept**, no tag-signature verification, and no
  task-SHA-pinning feature, so `C07`'s checksum/signature/signed-tag checks and
  `C08.actions.pinned` can never resolve there. It also exposes no org-level default
  repository permission, no `pull_request_target`-equivalent trigger, no private
  vulnerability reporting, and no `.github`-style org default policy.
- **GitHub exposes audit-log streaming only at the Enterprise account level**, which an
  org/repo-scoped tool cannot query — so `C09.audit.log-streaming` is never resolvable
  on GitHub, while it produces real pass/fail results on Azure DevOps. That asymmetry
  runs the opposite way to most of this list.
- **Azure DevOps governs force-push, branch deletion and admin bypass through Git
  repository ACLs** rather than branch-policy configuration, and this tool deliberately
  does not read `_apis/accesscontrollists` (epic #34's non-goals). So `C02`'s
  force-push-blocked, deletion-blocked and admin-enforced checks are never resolvable
  there — note that *bypass* is exactly what `C02`'s control statement is about, so on
  Azure DevOps this collector verifies required reviewers and build validation only.
- **Per-user MFA state on Azure DevOps lives in Microsoft Entra ID**, a separate service
  with its own auth model, so `C01` can report the count of members without 2FA on
  GitHub but not on Azure DevOps — and ADO's 2FA-enforcement check has a ceiling of
  `partial`, because enforcement itself lives in Entra Conditional Access.

Separately from those, how much a scan settles also depends on the org's plan and the
token's scopes: GitHub Advanced Security for Azure DevOps gates most of `C04` there, and
`C06.sca.alerts-triaged`. Do not read that as covering the whole of `C06` — two of its
five Azure DevOps checks (`dependency-review`, `dependabot-config`) make no API call at
all, so no licence changes them.

In total, 15 of Attestward's 48 registered Azure DevOps checks make no API call, against
2 of 46 on GitHub. Every check's own rubric states exactly which statuses it can produce
and what evidence backs each one.

Every check lands in one of five statuses: **`verified-pass`**/**`verified-fail`** (the API
confirmed the answer either way), **`partial`** (real evidence, but not a clean pass —
e.g. some but not all workflows pin their actions), **`not-checkable`** (the platform API
couldn't settle it — a permission gap, a plan limit, or a genuine "no API for this exists" —
never guessed at either direction), or **`self-attested`** (a control the API structurally
can't see, like whether developers get security training; collected via a short
questionnaire, never faked as verified). See the generated [Checks
Reference](docs/checks-reference.md) for exactly what each individual check's own statuses
mean and what API evidence backs them.

## 5-minute quickstart

### 1. Install

**Download a release** (see the [releases page](../../releases) for the current version):

```bash
# Substitute the real version/os/arch from the releases page.
curl -LO https://gitlab.com/sioakeim/attestward/releases/latest/download/attestward_<version>_<os>_<arch>.tar.gz
curl -LO https://gitlab.com/sioakeim/attestward/releases/latest/download/checksums.txt
shasum -a 256 -c checksums.txt --ignore-missing   # macOS; use sha256sum -c on Linux
tar -xzf attestward_<version>_<os>_<arch>.tar.gz
```

**Or with Go installed:**

```bash
go install gitlab.com/sioakeim/attestward/cmd/attestward@latest
```

### 2. Create a fine-grained PAT

GitHub Settings → Developer settings → Personal access tokens → Fine-grained tokens.
Scope it to just the repo(s) you're about to scan, read-only, with the permissions your
target collectors need — see the [token table](#required-token-permissions) below. For a
single repo you don't administer at the org level, `Contents: read-only`, `Actions:
read-only`, and `Administration: read-only` cover most of C02-C08.

### 3. Scan

```bash
export GITHUB_TOKEN=github_pat_...
attestward scan --org my-org --repo my-repo --out ./evidence/
```

No `--repo` scans every non-archived, non-fork repo in the account (with a warning) —
works against a GitHub Organization or a personal user account, either one. For a
personal account specifically, this only lists **public** repos; pass `--repo` explicitly
to include a private one you own.

### 4. Read the result

- **Exit code `0`**: no `verified-fail` or `partial` results — some checks may still be
  `not-checkable` or `self-attested`, which don't count as gaps on their own.
- **Exit code `2`**: at least one `verified-fail` or `partial` — see `evidence/report.md`,
  or run `attestward report ./evidence/evidence.json --format html` for a browser-friendly
  version, and `evidence/poam.md` for a draft remediation plan grouped by SSDF/CISA
  cluster.
- **Exit code `1`**: something actually went wrong (bad token, network failure) — not a
  finding.
- `evidence/evidence.json` is the full evidence pack: every result plus provenance (which
  API call, when, HTTP status, response digest). See
  [examples/demo-org-pack](examples/demo-org-pack) for a real one, and
  [examples/scan-demo.cast](examples/scan-demo.cast) (play with `asciinema play`) for a
  recording of this exact flow against the public demo repo.

That's the whole loop — no config file required for a single scan. `--config` exists for
repeatable, CI-friendly use (see [examples/attestward.yaml](examples/attestward.yaml)):

```
attestward scan --org my-org [--repo my-repo ...] --out ./evidence/
attestward scan --config attestward.yaml
attestward scan --self-attestation-file self-attestation.yaml  # include self-attested answers
attestward scan --org my-org --sign             # also sign evidence.json (see "Verifying an evidence pack")
attestward attest init --out self-attestation.yaml  # generate a commented answers template
attestward verify ./evidence/                   # check evidence.json's hash (and signature, if signed)
attestward report ./evidence/evidence.json      # regenerate reports
attestward diff baseline.json current.json      # semantic pack comparison; exit 2 on posture regressions
attestward checks list                          # show all checks + mappings
attestward checks docs                          # regenerate docs/checks-reference.md
attestward version
```

### Required token permissions

`attestward scan` reads `GITHUB_TOKEN` from the environment (never a CLI flag, never
persisted — see [docs/threat-model.md](docs/threat-model.md)). Use the narrowest scope
that covers the collectors you're running; each collector below lists the minimum. A
token with more than read-only scope still works, but `attestward scan` prints a
least-privilege warning if it detects write access.

| Collector | Minimum scope |
|-----------|----------------|
| `org-security` (C01) | `read:org` |
| `repo-protection` (C02) | `repo` (classic) or `Administration: read-only` (fine-grained) |
| `env-separation` (C03) | `repo` (classic) or `Actions: read-only` (fine-grained) |
| `secrets-hygiene` (C04) | `repo` (classic); fine-grained equivalent requires repo admin-level read access (`security_and_analysis` and `vulnerability-alerts` are both admin-only visible) — exact fine-grained permission category not independently verified against GitHub's docs; org-level check additionally needs org owner or security-manager status |
| `sast-history` (C05) | `repo` (classic) or `Actions: read-only` + `Contents: read-only` (fine-grained) — plus whatever fine-grained category gates the code-scanning default-setup endpoint specifically, not independently verified against GitHub's docs |
| `sca-history` (C06) | `repo` (classic) or `Actions: read-only` + `Contents: read-only` (fine-grained), plus `Administration: read-only` (shared with C02, for the dependency-review required-status-check cross-check) and whatever fine-grained category gates Dependabot alerts specifically — not independently verified against GitHub's docs |
| `provenance` (C07) | `repo` (classic) or `Contents: read-only` (fine-grained) — plus whatever fine-grained category gates git ref/tag reads and the attestations endpoint specifically, not independently verified against GitHub's docs |
| `actions-security` (C08) | `repo` (classic) or `Contents: read-only` (fine-grained) for workflow file content — plus `Administration: read-only` (fine-grained) for the repo default-workflow-permissions context fact, which this collector tolerates failing to read rather than treating as fatal; exact fine-grained category for that one unverified |
| `audit-logging` (C09) | `read:audit_log` (classic OAuth/PAT scope) — the authenticated user must also be an organization owner; GitHub's docs don't distinguish a missing scope from a plan that doesn't include the Enterprise Cloud audit-log API, both surface identically. The per-repo webhooks check needs its own, separate scope: `repo` (classic) or `Webhooks: read-only` (fine-grained) — exact fine-grained category not independently verified against GitHub's docs |
| `vdp` (C10) | `public_repo`/`repo` (classic) or `Contents: read-only` (fine-grained) for SECURITY.md content — private-reporting additionally needs whatever category gates that endpoint, exact fine-grained category unverified |

This table is generated from (and must stay in sync with) `attestward checks list`'s live
`TOKEN SCOPE` column, the authoritative source as more collectors land. Every "not
independently verified against GitHub's docs" hedge above is deliberate: it means this
project confirmed the behavior empirically (against a real token/repo) but couldn't find
GitHub's own documentation stating it outright — see each collector's own `CheckMeta`
doc comments (`attestward checks docs` / [docs/checks-reference.md](docs/checks-reference.md))
for exactly what was and wasn't confirmed. Scanning with a broader token than a check
needs still works — the check just doesn't need the extra access it was given.

The table's classic and fine-grained scope sets were each validated end-to-end as a
whole against the public demo org (issue #29, 2026-07-20). A classic PAT with exactly
`repo` + `read:org` + `read:audit_log`, and a fine-grained PAT (resource owner: the
org; repository permissions, all read-only: Actions, Administration, Attestations,
Code scanning alerts, Contents, Dependabot alerts, Webhooks; organization permissions,
read-only: Administration, Members) each produced a full scan in which every check
matched the demo org's expected results (`fixtures.yaml`). Three limits of that
validation, stated rather than glossed: each token carried its full set at once, so
per-row minimums were not individually exercised (a row needing more than it claims
would be masked by the union); the demo org's Free plan makes the org audit-log check
not-checkable regardless of token, so `read:audit_log`'s sufficiency was not actually
exercised; and because the demo org is public, content-level reads succeed without an
explicit grant there — both sets are validated as *sufficient*, not each entry as
individually *necessary*. A token with fewer permissions than a check needs does not
hard-fail the scan: affected checks degrade to `not-checkable` with a reason naming
what the token couldn't read (diffing the degraded pack against the full one showed no
silently wrong verified result), and only a token that can't see the target account at
all fails preflight outright.

### Azure DevOps: required token scopes

`attestward scan --platform azuredevops` reads `AZURE_DEVOPS_EXT_PAT` from the
environment instead of `GITHUB_TOKEN` (the az-CLI convention, chosen for zero-friction
reuse in an existing az-CLI setup) — never a CLI flag, never persisted, see
[docs/threat-model.md](docs/threat-model.md). `--project <name>` is required for this
platform (rejected for GitHub scans); `--repo` is also required — there is no
Azure DevOps repo-listing support yet (a fast follow), so omitting it errors asking for
it explicitly rather than silently scanning nothing:

```bash
export AZURE_DEVOPS_EXT_PAT=<pat>
attestward scan --platform azuredevops --org my-org --project my-project \
  --repo my-repo --out ./evidence/
```

| Collector | Minimum scope |
|-----------|----------------|
| `org-security` (C01) | `vso.graph` — *Graph (read)* — plus `vso.project` — *Project and Team (read)* — for the members-can-create-public check's own Projects - List call |
| `repo-protection` (C02) | `vso.code` — *Code (read)* |
| `env-separation` (C03) | `vso.environment_manage` — *Environment (read & manage)*: Azure DevOps documents no lower-privilege, read-only variant for the Environments - List endpoint this check depends on at all — plus `vso.build` — *Build (read)* — for the environment's check configurations (Approval/Task Check) |
| `secrets-hygiene` (C04) | `vso.advsec` — *Advanced Security (read)* — for GHAzDO enablement state — plus `vso.variablegroups_read` — *Variable Groups (read)* — for the ADO-only variable-group secret-hygiene check |
| `sast-history` (C05) | `vso.build` + `vso.code` — *Build/Code (read)* — for pipeline discovery and YAML content — plus `vso.advsec` — *Advanced Security (read)* — for GHAzDO CodeQL default-setup state |
| `sca-history` (C06) | `vso.build` + `vso.code` — *Build/Code (read)* — plus `vso.advsec` — *Advanced Security (read)* — for GHAzDO dependency-scanning-injection state and dependency-scanning alerts |
| `provenance` (C07) | `vso.build` + `vso.code` — *Build/Code (read)* |
| `pipeline-security` (C08) | `vso.serviceendpoint` — *Service Connections (read)* — for the OIDC-vs-static-credentials check — plus `vso.build` — *Build (read)* — for the self-hosted check's Pipelines - List/Definitions - Get calls — plus `vso.project` — *Project and Team (read)* — for the pipeline general-settings-backed token-permissions and fork-protection checks |
| `audit-logging` (C09) | `vso.auditlog` — *Audit Log (read)* — plus `vso.project` — *Project and Team (read)* — to resolve the scanned project, and `vso.build`/`vso.code` — *Build/Code (read)* — for the per-project service-hook-subscription (webhooks) check |
| `vdp` (C10) | `vso.code` — *Code (read)* — for SECURITY.md content |

This table's scope names and the `vso.environment_manage` no-read-only-variant caveat
were verified against Microsoft's own [OAuth scopes
reference](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/oauth)
and each collector's own `TokenScope` documentation
([docs/checks-reference.md](docs/checks-reference.md)'s `azuredevops` subsections). As
on the GitHub side, scanning with a broader token than a check needs still works — the
check just doesn't need the extra access it was given; there is no ADO analog of
GitHub's write-scope warning (`HasWriteScope`) — Azure DevOps has no scope-introspection
endpoint this tool could call to detect it (issue #34's own scope note).

**Live-validated 2026-07-23** against the real `dev.azure.com/seciq` organization
(issue #155's S9 harness): a single PAT carrying the scope set documented in this
table produced a full scan whose every one of 81 results matched the demo project's
expected outcomes (`fixtures-ado.yaml`) — note this set is not uniformly read-only:
`vso.environment_manage` is manage-level, since (as its own row above says) no
lower-privilege scope exists for the endpoint it backs. The same honesty this
document's GitHub token table already states applies identically here: this proves
the scope set is *sufficient* as a whole, not that each row is individually
*necessary* — the token carried its full set at once, so per-row minimums were not
individually exercised.

## Verifying an evidence pack

Every scan hashes and hash-verifies itself, always, whether or not you sign anything:

```bash
attestward scan --org my-org --out ./evidence/   # prints the sha256 and writes evidence.json.sha256
attestward verify ./evidence/                    # recomputes the hash and compares it
```

`attestward verify`'s hash check needs nothing but the two files it's checking — you can
verify without `attestward` at all, from inside the output directory:

```bash
sha256sum -c evidence.json.sha256   # Linux
shasum -a 256 -c evidence.json.sha256   # macOS
```

### Signing (optional)

Pass `--sign` to also sign `evidence.json` with [cosign](https://docs.sigstore.dev/)
(`cosign sign-blob`, shelled out to — attestward never links a Sigstore client or manages
key material itself; see [ADR-0006](docs/adr/0006-exec-cosign-not-sigstore-go.md)).
Requires `cosign` on `PATH`; `--sign` without it is a hard error naming the install doc,
never a silent skip.

```bash
# Keyless (Sigstore/Fulcio OIDC) — the same flow this repo's own release pipeline uses.
# Only works where an OIDC identity is available (e.g. GitHub Actions with
# `id-token: write`); on a bare local machine cosign opens a browser instead.
attestward scan --org my-org --sign

# Or with your own key file — attestward passes --sign-args straight through to cosign.
attestward scan --org my-org --sign --sign-args="--key=cosign.key"
```

This writes `evidence.json.bundle` (a single Sigstore bundle — signature, certificate,
and transparency-log proof together; cosign v3 dropped the legacy separate
`--output-signature`/`--output-certificate` files). `attestward verify` checks it
automatically when present — pass whatever `cosign verify-blob` needs to identify the
signer via `--verify-args` (attestward never defaults or infers an identity):

```bash
# Keyless verification needs the identity that signed it:
attestward verify ./evidence/ \
  --verify-args="--certificate-identity-regexp=^https://github.com/my-org/my-repo/" \
  --verify-args="--certificate-oidc-issuer=https://token.actions.githubusercontent.com"

# Key-file verification:
attestward verify ./evidence/ --verify-args="--key=cosign.pub"
```

A pack with no `.bundle` file isn't itself a problem — signing is opt-in, and an unsigned
pack's hash still verifies normally.

## Regenerating reports

`attestward report` re-renders `report.md`, `report.html`, and `poam.md` from an existing
`evidence.json` — no scan, no network access. Useful after a renderer upgrade, for a pack
someone else sent you, or for CI artifact post-processing:

```bash
attestward report ./evidence/evidence.json                    # writes all three alongside the input
attestward report ./evidence/evidence.json --out ./reports/    # or somewhere else
attestward report ./evidence/evidence.json --format md,poam    # only some of them
```

If a `.sha256` sidecar sits next to the input, `attestward report` checks it first. A hash
mismatch is refused unless `--force` is given, in which case every rendered file carries a
visible tamper-warning banner — rendering possibly-tampered evidence has to be a conscious,
visible act, never silent. A pack with no sidecar at all isn't itself a problem; there's
nothing to verify, so it renders normally. An `evidence.json` from a schema version this
build of `attestward` doesn't understand fails with a friendly error rather than a guess.

## Safety posture

- **Read-only, forever.** No code path in this tool makes a write call against any
  platform API — see [ADR-0004](docs/adr/0004-read-only-local-first.md). Enforced
  structurally, not just by review: every API call shares one transport that rejects any
  request that isn't `GET`/`HEAD` before it ever reaches the network. If a future feature
  seemed to need a write, it would be flagged and stopped, not added.
- **Local-first, no telemetry.** No network egress besides the platform API you point it
  at. No update checks, no crash reporting, no phone-home of any kind.
- **Tokens are never persisted.** `GITHUB_TOKEN` is read from the environment for the life
  of the process only; never logged, never written to disk, never included in evidence
  output.
- **Secret-shaped strings are scrubbed** from every log/error path and evidence output
  before it's written, as a second line of defense beyond "never log the token."

Full detail, trust boundaries, and residual risks: [docs/threat-model.md](docs/threat-model.md).

## Self-scan

The repo is its own first case study: [`self-scan.yaml`](.github/workflows/self-scan.yaml)
runs `attestward scan` against `sioakim/attestward` on every release (plus manual dispatch),
then publishes the evidence pack and rendered `report.html` as a downloadable
workflow artifact — see the [latest self-scan runs](../../actions/workflows/self-scan.yaml)
for a real (not demo-org) sample pack. The workflow fails the build on any gap outside a
small, deliberately documented exception list — each entry on it cites why it is there and
where the real fix is tracked (see the workflow file's own comments) — rather than
silently ignoring failures. The list is deliberately short and shrinking: dependency
review came off it once the repo went public and the check could actually run.

## Documentation

- [GitHub Action](docs/action.md) — run scans in your own CI with a pinned,
  cosign-verified release binary; drift detection against a baseline pack
- [Checks Reference](docs/checks-reference.md) — every check's rubric, API evidence, SSDF/CISA
  citations, and remediation, generated from `mappings/*.yaml` and the collector registry
  (never hand-edited — regenerate with `make checks-docs`)
- [Architecture](docs/architecture.md) — components, data flow, extension seams
- [Threat model](docs/threat-model.md) — what the tool accesses, what it never does
- [Architecture decision records](docs/adr/) — permanent, Nygard-format; superseded rather than edited
- [CHANGELOG.md](CHANGELOG.md) — what shipped in each release

## Contributing

Work is tracked entirely in [GitHub Issues](../../issues). Read
[CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR. New verification checks and scanner signatures have dedicated
[issue templates](../../issues/new/choose).

## Security

See [SECURITY.md](SECURITY.md). This repo aims to practice what the tool preaches: branch
protection, pinned actions, signed releases — and publicly scans itself (see "Self-scan"
above).
