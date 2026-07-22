# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-07-22

### Added

- **`attestward diff`** — semantic comparison of two evidence packs from the same
  org: status transitions classified as regressions (exit 2), improvements, coverage
  changes (verified ↔ not-checkable, reported separately from posture drift), and
  informational changes; volatile fields ignored; tool/mapping/scope changes surfaced
  as context. `--format text|md|json`. The foundation for continuous-mode drift
  detection (#36); consumed by the new
  [attestward-action](https://github.com/sioakim/attestward-action), which runs
  pinned, signature-verified release binaries in CI and fails on posture drift.

## [0.1.0] - 2026-07-21

First release: the complete v0.1 evidence engine for GitHub (epic #1, Phases 0–6).
Pre-1.0 caveat: CLI flags and output formats may still change between 0.x versions.

### Added

- **`attestward scan`** — read-only scan of a GitHub org (or personal user account):
  runs every registered collector concurrently, rolls results up through the SSDF/CISA
  mappings, and writes an evidence pack to `--out`. Exit codes: 0 all verified-pass,
  2 gaps found (any verified-fail/partial), 1 execution error.
- **Ten collectors** — C01 org-security, C02 repo-protection, C03 env-separation,
  C04 secrets-hygiene, C05 sast-history, C06 sca-history, C07 provenance,
  C08 actions-security, C09 audit-logging, C10 vdp.
- **Self-attestation intake** (`attestward attest`, `scan --self-attestation-file`)
  for controls no platform API can reach. Self-attested answers are always labeled as
  such and never upgrade a CISA form cluster to fully verified.
- **Evidence pack outputs** — `evidence.json` (schema-versioned; every check result
  carries API provenance: endpoint, timestamp, HTTP status, response digest),
  `report.md`, `report.html` (single self-contained file, opens offline), and
  `poam.md` (POA&M remediation tracking for every gap).
- **Pack integrity** — `evidence.json.sha256` sidecar always written; optional cosign
  signing via `scan --sign`; **`attestward verify`** re-checks the hash offline (and
  the signature, if a bundle is present, via `cosign verify-blob`).
- **`attestward report`** — re-render report.md/report.html/poam.md from an existing
  `evidence.json` without rescanning; refuses a hash-mismatched pack unless `--force`,
  which stamps a visible warning banner on every rendered file.
- **`attestward checks list` / `checks docs`** — the full check matrix (collector,
  SSDF tasks, CISA form cluster, minimum token permission) as CLI output and as the
  generated `docs/checks-reference.md`.
- **Mappings as versioned data** — `mappings/ssdf-800-218.yaml` and
  `mappings/cisa-ssda-form.yaml` (every ID traced to NIST SP 800-218 / CISA SSDA form
  primary sources), plus `mappings/scanner-signatures.yaml` (fixture-backed scanner
  detection for C05/C06).
- **Read-only, enforced at runtime** — the GitHub HTTP transport rejects any
  non-GET/HEAD request outright (ADR-0004; see docs/threat-model.md for the full
  claim-by-claim audit).
- **Release pipeline** — goreleaser cross-builds for linux/darwin (amd64 + arm64)
  and windows (amd64), with cosign keyless-signed `checksums.txt`; verification
  instructions in SECURITY.md.
- Documentation set: README with 5-minute quickstart and minimal-PAT table,
  architecture doc, threat model, generated checks reference, ADRs, community health
  files, and a worked example pack from the public demo org in `examples/`.

[Unreleased]: https://github.com/sioakim/attestward/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/sioakim/attestward/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sioakim/attestward/releases/tag/v0.1.0
