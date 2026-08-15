# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).


## [Unreleased]

### Fixed

- **C04's dependabot-alerts check could false-`verified-fail` on a GHES install without
  GitHub Connect configured** (issue #26, found auditing v1.2.0's GHES support). GitHub
  represents this endpoint's boolean as a status code — 204 enabled, 404 disabled — and
  a 404 is unambiguous on github.com, where the feature is always free and available.
  On GitHub Enterprise Server the same 404 also fires when GitHub Connect hasn't been
  configured to sync github.com's advisory database at all, which this endpoint cannot
  distinguish from a repo that genuinely has alerts turned off. Now `not-checkable` on
  GHES for the "off" case specifically — an observed `enabled` (204) still passes on
  either host, since a direct positive observation is never discarded in favor of a
  licensing inference (the same principle `evalGHASGatedFeature` already applies to
  secret scanning and push protection).


## [1.2.0] - 2026-08-15

### Added

- **GitHub Enterprise Server support** (`--github-url` / `github_url:` / `GITHUB_URL`).
  The same `github` platform against a self-hosted install: REST `/api/v3/` and GraphQL
  `/api/graphql` derived from the browser-facing URL, `GITHUB_CA_CERT` for private roots,
  and the resolved host recorded as `scope.github_url` so a pack says which install
  produced it. Gating distinguishes a plan tier (github.com) from a licence or version
  limitation (GHES) at every one of the nine collector packages that can hit it, rather than
  claiming a plan tier self-hosted installs don't have — this took four review rounds
  to get right (three independent reviews found real correctness and security defects,
  including a token-leaking redirect, an empty Fact written into a signed pack, and —
  found while porting this onto this repo's history — the routing fix itself surviving
  a full revert with a green suite because only the shared helper was guarded, never
  the nine individual call sites; see `internal/collect/github/gatekind.go`'s doc
  comment for the fix history). Every fix is mutation-verified at its actual call site,
  not just the shared helper: reverting any of them, including the load-bearing
  `Scope.IsGHES` assignment, fails the suite.
  **Not verified against a real GHES install** — no instance was available, so routing
  and gating are proven against fixtures and mutation tests only. See the README.

### Security

- **The redirect-following fix already shipped for `internal/collect/gogs` now also
  applies to the GitHub client**, which became reachable to the same class of attack
  the moment `--github-url` made its base URL user-supplied too. Host-scoped rather
  than refuse-all, unlike Gogs: GitHub documents a 301 for renamed repos/orgs that
  `net/http` previously followed transparently, so refusing every redirect would have
  been a regression for existing github.com users. Cross-host hops and same-host
  https→http downgrades are still refused — that's where the token leak lived.
- **Credentials in `--github-url` are rejected**, the same way `--gogs-url` already is.
  `scope.github_url` is recorded into the evidence pack and `EvidencePack.Scrub` walks
  results only, never scope, so a `https://user:pass@host` base URL would have written
  the password into a signed artifact verbatim.

### Fixed

- **README's Windows quickstart used `tar -xzf` on a `.zip`.** The manual-download
  instructions used one `<os>_<arch>.tar.gz` pattern for every platform; the real
  Windows release asset is `attestward_<version>_windows_amd64.zip` (goreleaser
  `format_overrides`), which `tar` cannot extract. Added a Windows-specific paragraph
  with the real filename, a `CertUtil`/`sha256sum` verify option, and
  `Expand-Archive`/zip-tool extraction.

### Changed

- **`CONTRIBUTING.md` corrected to describe the actual GitLab-based workflow.** It still
  described a GitHub-Issues/PR/squash-merge process; the project has run entirely on
  GitLab issues and merge requests (real merge commits, not squashed) for some time. Also
  ported the two GitHub Issue Forms (`.github/ISSUE_TEMPLATE/`) to GitLab issue
  description templates (`.gitlab/issue_templates/`), since GitHub Issues are disabled on
  the read-only GitHub mirror and those forms were otherwise unreachable.
- **The code is now also mirrored, read-only, to GitHub
  ([QloudLTD/attestward](https://github.com/QloudLTD/attestward)) and Gogs
  ([gogs.ioakeim.com/sioakim/attestward](https://gogs.ioakeim.com/sioakim/attestward))**,
  for visibility. GitLab remains the sole issue tracker, CI, and release pipeline — both
  mirrors have Issues/Actions disabled or unmonitored.


## [1.1.0] - 2026-08-14

The first release cut on the GitLab CI release pipeline (the previous GitHub Actions
pipeline stopped working when its GitHub account was banned; see `docs/adr/` and
`SECURITY.md` for the replacement's keyless-signing design). `v1.1.0-beta.1` validated
the pipeline end to end — real release, real cosign-verified signature, both example CI
templates run against a live download — before this tag.

### Added

- **Gogs support** (`--platform gogs`). A third platform behind the ADR-0005 collector
  seam, for self-hosted Gogs instances: a read-only client with its own base URL
  (`--gogs-url`, `GOGS_TOKEN`), the C10 vulnerability-disclosure collector, the C02
  repo-protection collector, a repo lister, and an honest `not-checkable` result for
  every control Gogs has no mechanism for. A Gogs scan is mostly negative evidence —
  the platform has no CI, code scanning, dependency alerts, secret scanning,
  environments, audit log or branch-protection API — and reports that explicitly
  rather than omitting the checks. See the README for what it can and cannot evidence.
- **A GitLab CI release pipeline** replaces the non-functional GitHub Actions one:
  `goreleaser` plus GitLab's native OIDC (`id_tokens: SIGSTORE_ID_TOKEN`) for keyless
  cosign signing, no signing key to manage. See `SECURITY.md` for the verify command.

### Security

- **`internal/collect/gogs` never follows HTTP redirects.** Auth is injected inside the
  transport, below Go's redirect machinery, so its cross-domain header stripping cannot
  see it: a redirecting instance would have handed a third-party host a valid token and
  had its response body accepted as the API's answer. Found in review of the first
  platform package to take a user-supplied base URL; Azure DevOps and github.com target
  constant hosts and were unaffected at this point.
- **Credentials in `--gogs-url` are rejected.** `BaseURL()` is recorded as a pack fact,
  and `url.URL.String()` prints a password verbatim, so a `https://user:pass@host` base
  URL would have written the password into a signed evidence pack.

### Fixed

- **A drift regression could permanently freeze the evidence baseline** (#211). Found by
  the v1.0.0 release, which walked straight into it. `attach-to-release` carried
  `needs: self-scan` and no `always()`, so it inherited an implicit success requirement:
  a posture regression failed the scan job via `fail-on-drift`, which skipped the attach,
  which meant the baseline was never refreshed — so the *next* release diffed against the
  same stale pack and failed identically. One regression wedged the chain forever. The
  alarm's job is to report that posture moved, not to prevent the new posture from being
  recorded, so the pack now attaches either way and the failed run remains the alarm. A
  genuinely broken scan writes no pack and the download step fails loudly instead.
- **The self-scan ran a scanner three releases behind the code it was scanning** (#211).
  `version:` was pinned at `0.2.0`; bumped to `1.0.0` and now bumps with each release.
- **The demo org's owning GitHub account was banned, orphaning it.** Rebuilt the same
  `demo-good`/`demo-bad` fixture pair under a fresh org, re-signed the release tag with a
  newly-registered SSH key, and re-scanned — every check produced the same status as the
  original org.
- **README's manual-download instructions used GitHub's `/releases/latest/download/`
  URL shape**, which doesn't exist on GitLab and actually 302-redirected to GitLab's
  sign-in page rather than erroring cleanly. Replaced with GitLab's real permalink,
  `/-/releases/permalink/latest/downloads/<file>`.


## [1.0.0] - 2026-07-29

This is the release the repository went public in. Entries are condensed; the full
reasoning for any of them is in the linked issue and its pull request.

### Added

- **The GitHub Action now lives in this repo** (`action.yml` at the root, docs in
  [docs/action.md](docs/action.md)). It was a separate private repository, which stopped
  resolving the moment this one went public — a public repo cannot use an action from a
  private one.
- **`agents/`** — agent skills for AI coding agents working with this tool.
  `attestward-scan` takes a newcomer from clone to a rendered evidence pack.
- **CodeQL and `dependency-review-action` restored.** Both need GitHub Advanced Security
  on a private repo and are free on a public one, so the original blocker is gone rather
  than worked around.
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
  account and login keychain with runners for seven unrelated repositories (#316).
- **`self-scan.yaml` runs on releases only.** Its output is a release artifact, so the
  weekly cron produced packs nothing consumed.
- **README rewritten for a public reader.** The quickstart opened by telling visitors the
  repo was private and that install only worked for invited collaborators; both v0.1-epic
  pointers are gone.
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
  stays free) is now a README section.
- **Obsolete documentation deleted:** `docs/archive/` and the point-in-time handoff note,
  all marked historical and describing a project state that no longer exists.
- **Every self-hosted runner and its supporting tooling** — `runner-maintenance.yaml`,
  `aorus-keepalive.yaml`, `tools/aorus.sh` — plus `threatmodelguard`'s self-hosted job
  enumeration, which had nothing left to compare against.

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
  `attestward-action` (since folded into this repository; see `docs/action.md`), which runs
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

[Unreleased]: https://gitlab.com/sioakeim/attestward/compare/v1.2.0...HEAD
[1.2.0]: https://gitlab.com/sioakeim/attestward/compare/v1.1.0...v1.2.0
[1.1.0]: https://gitlab.com/sioakeim/attestward/compare/3ac0707...v1.1.0
[1.0.0]: https://gitlab.com/sioakeim/attestward/compare/v0.3.0...v1.0.0
[0.3.0]: https://gitlab.com/sioakeim/attestward/compare/v0.2.0...v0.3.0
[0.2.0]: https://gitlab.com/sioakeim/attestward/compare/v0.1.0...v0.2.0
[0.1.0]: https://gitlab.com/sioakeim/attestward/releases/tag/v0.1.0
