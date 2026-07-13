# SSDF Evidence Engine

> **Everyone else helps you fill in the CISA attestation form. This tool proves what you're signing.**

**Working name:** `attestor` (final name TBD — see [DECISIONS.md](DECISIONS.md))
**Status:** pre-alpha — v0.1 under active, issue-driven development. Nothing here is usable yet.
**License:** [Apache-2.0](LICENSE)

[![CI](https://github.com/sioakim/ssdf/actions/workflows/ci.yaml/badge.svg)](https://github.com/sioakim/ssdf/actions/workflows/ci.yaml)
[![CodeQL](https://github.com/sioakim/ssdf/actions/workflows/codeql.yaml/badge.svg)](https://github.com/sioakim/ssdf/actions/workflows/codeql.yaml)

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

## Documentation

- [v0.1 epic](../../issues/1) — canonical scope and build-phase tracking (GitHub Issues)
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
protection, pinned actions, signed releases, CodeQL — and will publicly scan itself.
