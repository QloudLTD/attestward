# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).

## [Unreleased]

This is the release the repository went public in. Entries are condensed; the full
reasoning for any of them is in the linked issue and its pull request.

### Added

- **The GitHub Action now lives in this repo** (`action.yml` at the root, docs in
  [docs/action.md](docs/action.md)). It was a separate private repository, which stopped
  resolving the moment this one went public — a public repo cannot use an action from a
  private one (#138).
- **`agents/`** — agent skills for AI coding agents working with this tool.
  `attestward-scan` takes a newcomer from clone to a rendered evidence pack (#138).
- **CodeQL and `dependency-review-action` restored.** Both need GitHub Advanced Security
  on a private repo and are free on a public one, so the original blocker is gone rather
  than worked around (#138).
- **Release archives carry third-party attribution and our own `NOTICE`.** Five of the
  binary's statically-linked dependencies require notice with binary redistribution and
  were shipping without it. New generated `THIRD-PARTY-NOTICES.md` with a CI drift guard
  (#282).
- **`syft` (SBOM) and `trivy` Azure Pipelines detection** added to the scanner-signature
  registry, and every signature now carries an explicit absence marker rather than a
  silent gap (#243, #253).
- **New CI guards:** `rubricguard` catches a status-assignment change with an untouched
  `checkRubrics` (#209); `threatmodelguard` guards the ADO collector list (#274);
  `make examples-check` guards the rendered example pack (#228).
- **`model.Scrub` redacts Azure DevOps PAT-shaped secrets**, closing the gap between the
  two platforms' secret patterns (#192).

### Changed

- **All CI, release and scanning workflows moved to GitHub-hosted runners**, and every
  self-hosted runner was deregistered. Hosted runners are free on a public repo, which
  was the only reason self-hosted machines were used here. This retires a documented
  supply-chain risk rather than relocating it: CI had shared one persistent machine, user
  account and login keychain with runners for seven unrelated repositories (#138, #316).
- **`self-scan.yaml` runs on releases only.** Its output is a release artifact, so the
  weekly cron produced packs nothing consumed (#138).
- **README rewritten for a public reader.** The quickstart opened by telling visitors the
  repo was private and that install only worked for invited collaborators; both v0.1-epic
  pointers are gone (#138).
- **`docs/threat-model.md`'s runner and endpoint sections rewritten** for the hosted-runner
  reality, and the endpoint table drops line-number citations that could drift (#274, #316).
- **`C04.vars.secret-hygiene`'s sensitive-name pattern widened**, and report/POA&M's `Repo`
  column renamed to `Scope` to stop mislabelling org-scoped Azure DevOps results (#296).
- **`integration-scan.yaml` gains a path-filtered push trigger**; every `actions/setup-go`
  call site sets `cache: false` so builds resolve from `go.sum` against the real proxy
  (#278, #313).

### Removed

- **`CLAUDE.md` and `DECISIONS.md` are no longer tracked.** Both documented internal
  reasoning. Nothing load-bearing was lost — both hard rules already live in `README.md`,
  `CONTRIBUTING.md` and the ADRs, and `DECISIONS.md`'s one user-facing commitment (what
  stays free) is now a README section (#138).
- **Obsolete documentation deleted:** `docs/archive/` and the point-in-time handoff note,
  all marked historical and describing a project state that no longer exists (#138).
- **Every self-hosted runner and its supporting tooling** — `runner-maintenance.yaml`,
  `aorus-keepalive.yaml`, `tools/aorus.sh` — plus `threatmodelguard`'s self-hosted job
  enumeration, which had nothing left to compare against (#138).

### Fixed

- **A recurring false-inference defect class, found on 15 separate surfaces.** The shape
  is `x := err == nil && resp.Field`: a value that silently defaults when an API call
  fails, then gets asserted as a confirmed observation. Every instance produced a
  `verified-fail` or a confirmed `Facts` value from a query that never returned. Fixed
  across GitHub and Azure DevOps `sasthistory`/`scahistory`/`provenance`, C05/C06
  `tool-configured` and `ran-per-release`, and the GHAzDO enablement reads. Each surface
  needed its own fix because fixing one reached none of the others (#226, #235, #236,
  #244, #245, #248, #251, #254, #258, #259, #266, #268, #287, #289).
- **`self-scan.yaml`'s exception list corrected against a real run**, and four repo
  security features enabled that were found switched off — secret scanning, push
  protection, Dependabot security updates and private vulnerability reporting (#211, #319).
- **Drift detection actually runs on a release now.** `on: release` never fired, because
  GitHub does not cascade events triggered by `GITHUB_TOKEN` into new workflow runs
  (#211).
- **Markdown injection and escaping bugs in the renderers:** `check_id` rendered raw
  inside an unescaped code span at five sites, pack-level scope/version fields unescaped
  in `report.md`/`poam.md`, and an out-of-enum `status` reaching an unescaped fallback
  because `Status.Valid()` was never called on the report path (#240).
- **`go.mod` is now tidy and guarded in CI**, and goreleaser no longer runs `go mod tidy`
  during release — so published binaries provably build from the tagged tree (#249).
- **`MappingVersionMismatch` compares all four mapping files**, not two, and the banner
  names which actually drifted (#265).
- **`github.sha` is no longer interpolated directly into `run:` blocks**, and artifact
  retention no longer silently inherits the 90-day default (#232, #242).
- **`threatmodelguard` hardened repeatedly**: its guarded enumeration was itself
  incomplete, it verified mention rather than membership, and its section scope missed
  two Markdown shapes (#286, #299, #302, #309).


## [0.3.0] - 2026-07-23

### Added

- **Azure DevOps support** (epic #34) — the full C01–C10 check matrix now runs against
  Azure DevOps behind the same collector seam: `attestward scan --platform azuredevops
  --org <org> --project <project> --repo <repo>...`, authenticated via
  `AZURE_DEVOPS_EXT_PAT`. 94 registered checks across the two platforms: 46 mirrored
  under the same check IDs (honest per-platform degradation where ADO has no
  equivalent — every not-checkable carries a reason naming the exact platform gap),
  plus two new ADO-only checks: `C04.vars.secret-hygiene` (plaintext sensitive-named
  variables in variable groups) and `C08.pipelines.fork-protection`. Includes the
  four-host read-only client (the same transport-level write rejection as GitHub's),
  azure-pipelines scanner-signature matching, per-platform sections in
  `docs/checks-reference.md`, an ADO token-scope table in the README (live-validated),
  and a live-proven demo project with a weekly drift-scanning integration job. (The
  first live scan found and fixed an audit-streams envelope decode bug within this
  release's own dev cycle — no released version carried it.)
- **SAST in CI** (#157): a pinned semgrep workflow scans the codebase on every push to
  main, every PR, and weekly — registry-recognized, so the tool's own self-scan sees it.
- **Signed release tags** (#158, DECISIONS.md D12): from v0.3.0 onward, release tags
  are signed with a dedicated Ed25519 SSH key registered to the repository owner's
  GitHub account.

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

[Unreleased]: https://github.com/sioakim/attestward/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/sioakim/attestward/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/sioakim/attestward/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sioakim/attestward/releases/tag/v0.1.0
