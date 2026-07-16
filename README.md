# SSDF Evidence Engine

> **Everyone else helps you fill in the CISA attestation form. This tool proves what you're signing.**

**Working name:** `attestor` (final name TBD — see [DECISIONS.md](DECISIONS.md))
**Status:** pre-alpha — v0.1 under active, issue-driven development. Nothing here is usable yet.
**License:** [Apache-2.0](LICENSE)

[![CI](https://github.com/sioakim/ssdf/actions/workflows/ci.yaml/badge.svg)](https://github.com/sioakim/ssdf/actions/workflows/ci.yaml)

---

## What this is

An open-source CLI tool that connects to a software producer's source-control and CI/CD
platform (GitHub first) and **verifies** — rather than asks about — the technical controls
behind the CISA Secure Software Development Attestation (SSDA) form. It maps findings to
NIST SSDF (SP 800-218) practices and the form's four practice clusters, and emits a signed,
timestamped **evidence pack** (JSON + human-readable report) plus a **gap analysis** and a
**draft POA&M** for anything that fails.

### Why

- Software producers selling to US federal agencies must sign the CISA SSDA form. An officer
  signs **under False Claims Act exposure**. DOJ's Civil Cyber-Fraud Initiative actively
  prosecutes inaccurate cybersecurity representations.
- Today's options for the long tail of small federal software vendors: sign-and-hope, or pay
  a consulting firm for a manual assessment. Nothing self-serve verifies the actual pipeline.
- Existing "compliance automation" products primarily *ask questions and store documents*.
  This tool's differentiator is **harvested proof**: it reads the real configuration and run
  history and shows what is actually true.

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

## Planned CLI (v0.1)

```
attestor scan --org my-org [--repo my-repo ...] --out ./evidence/
attestor scan --config attestor.yaml          # repeatable, CI-friendly
attestor scan --self-attestation-file self-attestation.yaml  # include self-attested answers
attestor scan --org my-org --sign             # also sign evidence.json (see "Verifying an evidence pack")
attestor attest init --out self-attestation.yaml  # generate a commented answers template
attestor verify ./evidence/                   # check evidence.json's hash (and signature, if signed)
attestor report ./evidence/evidence.json      # regenerate reports
attestor checks list                          # show all checks + mappings
attestor version
```

Exit codes: `0` all verified-pass · `2` gaps found (for CI usage) · `1` execution error.

## What v0.1 verifies (GitHub only)

| ID | Collector | Verifies |
|----|-----------|----------|
| C01 | `org-security` | Org 2FA/MFA enforcement, default repo permissions |
| C02 | `repo-protection` | Branch protection / rulesets on default + release branches |
| C03 | `env-separation` | GitHub Environments, protection rules, deployment branch policies |
| C04 | `secrets-hygiene` | Secret scanning, push protection, Dependabot alerts |
| C05 | `sast-history` | SAST tooling detected + run cadence over last N releases |
| C06 | `sca-history` | SCA/dependency review tooling + run history |
| C07 | `provenance` | Signed tags, release checksums/signatures, Sigstore/SLSA workflows |
| C08 | `actions-security` | Action pinning, token permissions, OIDC vs long-lived creds |
| C09 | `audit-logging` | Org audit-log availability, event visibility |
| C10 | `vdp` | SECURITY.md intake channel, private vulnerability reporting |

Controls that cannot be verified via API (training, threat modeling, triage SLAs) are
collected via a small questionnaire and clearly flagged `self-attested` — the tool never
fakes verification where none is possible.

### Required token permissions

`attestor scan` reads `GITHUB_TOKEN` from the environment (never a CLI flag, never
persisted — see [docs/threat-model.md](docs/threat-model.md)). Use the narrowest scope
that covers the collectors you're running; each collector below lists the minimum. A
token with more than read-only scope still works, but `attestor scan` prints a
least-privilege warning if it detects write access.

| Collector | Minimum scope |
|-----------|----------------|
| `org-security` (C01) | `read:org` |
| `repo-protection` (C02) | `repo` (classic) or `Administration: read-only` (fine-grained) |
| `env-separation` (C03) | `repo` (classic) or `Actions: read-only` (fine-grained) |
| `secrets-hygiene` (C04) | `repo` (classic); fine-grained equivalent needs repo admin-level read access — exact permission category unverified, see `attestor checks list`'s notes for that collector |
| `sast-history` (C05) | `repo` (classic) or `Actions: read-only` + `Contents: read-only` (fine-grained) — plus code-scanning read access for the default-setup check specifically; exact fine-grained category for that one unverified |
| `sca-history` (C06) | `repo` (classic) or `Actions: read-only` + `Contents: read-only` (fine-grained) — plus `Administration: read-only` (shared with C02, for the dependency-review required-status-check cross-check) and Dependabot-alerts read access; exact fine-grained category for the latter unverified |
| `provenance` (C07) | `repo` (classic) or `Contents: read-only` (fine-grained) — plus whatever fine-grained category gates git ref/tag reads and the attestations endpoint specifically; exact fine-grained category for those unverified |
| `actions-security` (C08) | `repo` (classic) or `Contents: read-only` (fine-grained) for workflow file content — plus `Administration: read-only` (fine-grained) for the repo default-workflow-permissions context fact, which this collector tolerates failing to read rather than treating as fatal; exact fine-grained category for that one unverified |
| `audit-logging` (C09) | `read:audit_log` (classic OAuth/PAT scope) plus organization-owner status for the org audit-log checks — GitHub's docs don't distinguish a missing scope from a plan without the Enterprise Cloud audit-log API, both surface identically; `repo` (classic) or `Webhooks: read-only` (fine-grained, unverified) for the webhooks check |
| `vdp` (C10) | `public_repo`/`repo` (classic) or `Contents: read-only` (fine-grained) for SECURITY.md content; private-reporting additionally needs whatever category gates that endpoint, exact fine-grained category unverified |

This table only lists collectors that exist as code today; `attestor checks list` is
the live source of truth as more land (each row's `TOKEN SCOPE` column). For what each
check's own pass/fail/partial/not-checkable statuses actually mean, the API evidence
behind it, and its SSDF task/CISA cluster citations, see the generated
[Checks Reference](docs/checks-reference.md).

## Verifying an evidence pack

Every scan hashes and hash-verifies itself, always, whether or not you sign anything:

```bash
attestor scan --org my-org --out ./evidence/   # prints the sha256 and writes evidence.json.sha256
attestor verify ./evidence/                    # recomputes the hash and compares it
```

`attestor verify`'s hash check needs nothing but the two files it's checking — you can
verify without `attestor` at all, from inside the output directory:

```bash
sha256sum -c evidence.json.sha256   # Linux
shasum -a 256 -c evidence.json.sha256   # macOS
```

### Signing (optional)

Pass `--sign` to also sign `evidence.json` with [cosign](https://docs.sigstore.dev/)
(`cosign sign-blob`, shelled out to — attestor never links a Sigstore client or manages
key material itself; see [ADR-0006](docs/adr/0006-exec-cosign-not-sigstore-go.md)).
Requires `cosign` on `PATH`; `--sign` without it is a hard error naming the install doc,
never a silent skip.

```bash
# Keyless (Sigstore/Fulcio OIDC) — the same flow this repo's own release pipeline uses.
# Only works where an OIDC identity is available (e.g. GitHub Actions with
# `id-token: write`); on a bare local machine cosign opens a browser instead.
attestor scan --org my-org --sign

# Or with your own key file — attestor passes --sign-args straight through to cosign.
attestor scan --org my-org --sign --sign-args="--key=cosign.key"
```

This writes `evidence.json.bundle` (a single Sigstore bundle — signature, certificate,
and transparency-log proof together; cosign v3 dropped the legacy separate
`--output-signature`/`--output-certificate` files). `attestor verify` checks it
automatically when present — pass whatever `cosign verify-blob` needs to identify the
signer via `--verify-args` (attestor never defaults or infers an identity):

```bash
# Keyless verification needs the identity that signed it:
attestor verify ./evidence/ \
  --verify-args="--certificate-identity-regexp=^https://github.com/my-org/my-repo/" \
  --verify-args="--certificate-oidc-issuer=https://token.actions.githubusercontent.com"

# Key-file verification:
attestor verify ./evidence/ --verify-args="--key=cosign.pub"
```

A pack with no `.bundle` file isn't itself a problem — signing is opt-in, and an unsigned
pack's hash still verifies normally.

## Regenerating reports

`attestor report` re-renders `report.md`, `report.html`, and `poam.md` from an existing
`evidence.json` — no scan, no network access. Useful after a renderer upgrade, for a pack
someone else sent you, or for CI artifact post-processing:

```bash
attestor report ./evidence/evidence.json                    # writes all three alongside the input
attestor report ./evidence/evidence.json --out ./reports/    # or somewhere else
attestor report ./evidence/evidence.json --format md,poam    # only some of them
```

If a `.sha256` sidecar sits next to the input, `attestor report` checks it first. A hash
mismatch is refused unless `--force` is given, in which case every rendered file carries a
visible tamper-warning banner — rendering possibly-tampered evidence has to be a conscious,
visible act, never silent. A pack with no sidecar at all isn't itself a problem; there's
nothing to verify, so it renders normally. An `evidence.json` from a schema version this
build of `attestor` doesn't understand fails with a friendly error rather than a guess.

## Documentation

- [v0.1 epic](../../issues/1) — canonical scope and build-phase tracking (GitHub Issues)
- [Checks Reference](docs/checks-reference.md) — every check's rubric, API evidence, SSDF/CISA
  citations, and remediation, generated from `mappings/*.yaml` and the collector registry
  (never hand-edited — regenerate with `make checks-docs`)
- [Architecture](docs/architecture.md) — components, data flow, extension seams
- [Threat model](docs/threat-model.md) — what the tool accesses, what it never does
- [Architecture decision records](docs/adr/)
- [Archived planning docs](docs/archive/) — original product brief and roadmap, superseded by GitHub Issues

## Contributing

Work is tracked entirely in [GitHub Issues](../../issues) — see the
[v0.1 epic](../../issues/1) for the full build plan. Read [CONTRIBUTING.md](CONTRIBUTING.md)
before opening a PR. New verification checks and scanner signatures have dedicated
[issue templates](../../issues/new/choose).

## Security

See [SECURITY.md](SECURITY.md). This repo aims to practice what the tool preaches: branch
protection, pinned actions, signed releases — and will publicly scan itself.
