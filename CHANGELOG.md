# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).

## [Unreleased]

### Added

- **`model.Scrub` redacts Azure DevOps PAT-shaped secrets** (#192): the defense-in-depth
  secret scrubber previously covered GitHub token prefixes, AWS access keys, and PEM
  blocks only. It now also matches the documented Azure DevOps PAT shape (84 characters
  total, fixed `AZDO` signature — both offset readings Microsoft's own self-inconsistent
  PAT format reference admits, boundary-anchored to avoid matching inside a longer benign
  alphanumeric run). Meaningfully narrows the gap `docs/threat-model.md` had flagged as
  an open residual risk; the exact character alphabet of the non-signature portion
  remains unverified without a real token sample, so the risk entry is updated, not
  removed.
- **CI guard: `tools/rubricguard` catches a status-assignment change with an untouched
  `checkRubrics` entry** (#209). `make checks-docs-check` only compares
  `docs/checks-reference.md` against its rubric *source*; it has no opinion on whether a
  rubric matches the collector's own status-assignment logic, so a check could start
  producing a status its published rubric never describes and nothing would catch it —
  exactly what #202's review round 1 found by chance, and #203 (same batch, same class
  of change) avoided only because it happened to update its rubric in the same commit.
  `rubric-drift-check` (wired into `ci.yaml`, same PRs `checks-docs-drift` already
  gates) AST-parses each internal/collect/** package touched by a diff and flags one
  whose non-test `.go` files gained a changed `model.Status*` value reference while its
  `checkRubrics` var went untouched in the same diff — deliberately coarse (a reviewer
  can wave off a false positive; silence is what #202 hit), verified against this
  repo's own history: correctly silent across 40 real merged PRs, and correctly flags
  #202's actual pre-fix commit (all three collectors it originally missed).

### Fixed

- **Report/POA&M renderers no longer mislabel Azure DevOps project-scoped results as
  org-level** (#176). `report.md`/`report.html`'s Gaps and Not Checkable tables, and
  `poam.md`'s Findings section, rendered every result with an empty `Scope.Repo` as
  `(org)`/`(org-level)` — correct for a genuinely org-scoped result, factually wrong
  for an Azure DevOps project-scoped one (e.g. C03 env-separation, C08
  pipeline-security), which also has `Scope.Repo` empty; `Scope.Project` can't
  disambiguate the two either, since the orchestrator stamps it onto every result from
  an ADO scan regardless of the check's own scope level. Scope level is now classified
  via a new `CheckMeta.ScopeLevel` field, set explicitly only for the checks that are
  project-scoped, rather than inferred from `(Repo, Project)` presence at each render
  site. The pack-header scope table and `poam.md`'s Summary now also surface
  `Scope.Project` when present, which neither did before.
- **self-scan.yaml: drift detection actually runs on a release now** (#211). Its
  `on: release: types: [published]` trigger never fired for any of this repo's real
  releases — `release.yaml` creates every release with the ambient `GITHUB_TOKEN`, and
  GitHub deliberately doesn't cascade GITHUB_TOKEN-authenticated events into new
  workflow runs. Switched to `workflow_run` on the `Release` workflow's completion,
  which isn't subject to that restriction. Separately, a missing baseline (the latest
  release has no `evidence.json` attached) used to fail open silently and look
  identical to a genuine first run either way; the two are now distinguished — an
  older release carrying the asset while the latest doesn't is a broken chain, loudly
  annotated (`::error::`) and worked around by falling back to that older release's
  pack, *except* on the one release-triggered run where that's actually expected (the
  just-published release's own pack isn't attached until later in the same run) — that
  case falls back quietly instead of alarming on every single release, forever.
  `gh` itself failing (rate limit, transient 5xx) is now distinguished from the asset
  genuinely being absent too, rather than the two looking identical to a fallback scan
  and silently reproducing the same defect through a different door. "Latest" is now
  resolved the same way on both the read and write side (previously the write side
  could target a prerelease the read side's `isLatest` filter would never see again).
  The baseline-fetch logic moved to `hack/fetch-drift-baseline.sh` so all of the above
  is testable against a mocked `gh` (`fetch-drift-baseline_test.sh`, wired into
  `ci.yaml`) without a real release.
- **The artifact storage quota exhausted outright, and `continue-on-error` made it
  completely invisible** (#217). 10.82 GB across 1362 artifacts at discovery — 5.69 GB
  of it pre-rename `attestor-*` debris no workflow references any more (deleted with
  the owner's approval), the rest almost entirely `ci.yaml`'s `attestward-builds`: five
  ~18 MB binaries uploaded on every PR *and every push to an open PR's branch*, not
  just once per PR. That upload now only runs on `push` events (a merge or direct push
  to `main`) — the `build` job's compile-and-execute proof, which is the actual point
  of the job, still runs unconditionally on every PR. Every `continue-on-error`-guarded
  artifact upload across `ci.yaml`, `self-scan.yaml`, and `multi-arch-build-sample.yaml`
  now emits a `::warning::` annotation on a genuine failure (checked via the upload
  step's own `outcome`, which `continue-on-error` doesn't mask) — silent before, now
  noticeable without reddening a build that otherwise passed. This was the second,
  independent layer at which the drift baseline chain #211 fixes could still break
  silently: on a release run, a quota-exhausted upload means `attach-to-release` has
  nothing to download, same outcome as #211's own original defect, arrived at from a
  different direction.
- **C05 sast-history / C06 sca-history: a workflow/pipeline this tool couldn't fully
  inspect no longer reads as a confirmed absence** (#178). A workflow (GitHub) or
  pipeline (Azure DevOps) that failed to fetch, decode, or parse was silently dropped
  rather than counted as evidence-gathering failure — a repo whose only SAST/SCA
  mechanism happened to be that one unreadable workflow read `verified-fail` ("no tool
  detected") instead of an honest `not-checkable`. Fixed on both platforms: skips are
  now surfaced in each affected check's `tool-configured` **and `ran-per-release`**
  Facts (name/path + reason per entry), and cap both checks at `not-checkable` instead
  of `verified-fail` when a same-repo skip exists and no other evidence resolved it —
  the two checks previously disagreed with each other over the identical evidence.
  Every affected check's status rubric (and the generated `docs/checks-reference.md`)
  is updated to describe the new not-checkable case. GitHub C07 provenance and three
  other `ran-per-release`-style checks had the identical, pre-existing gap, out of
  scope for this fix — see #207.
- **C05 sast-history (Azure DevOps): `ran-per-release` no longer contradicts
  `tool-configured` for default-setup-only repos** (#184). A repo whose only SAST
  mechanism is GHAzDO CodeQL default setup (zero signature-matched pipelines) got
  `tool-configured = verified-pass` but `ran-per-release = verified-fail` ("no matched
  SAST run at all") — self-contradictory, since default-setup scans aren't observable
  through the Pipelines/Builds APIs this collector uses. `ran-per-release` now reads
  `not-checkable` in that case, mirroring the identical fix already shipped for C06
  sca-history's `injectionOnly` guard.
- **GitHub C07 provenance / Azure DevOps C06 sca-history: two more
  `ran-per-release`-style checks no longer read a confirmed absence over an inspection
  failure** (#207), completing #178's own scope. `github/provenance`'s
  `checkProvenanceWorkflow` (C07.provenance.workflow) was the one tool-configured-shaped
  check on either platform that still discarded its skip list entirely;
  `azuredevops/scahistory`'s `checkRanPerRelease` (C06.sca.ran-per-release) had the
  identical gap #178 already fixed for its sibling checks. Both now surface same-repo
  skips in Facts and cap at `not-checkable` instead of `verified-fail`. #207 also listed
  `azuredevops/provenance`'s and `github/provenance`'s own `checkCommitLinkage` as having
  the same gap — verified false: both fetch every build/run in the repo unfiltered by
  pipeline/workflow identity (they ask "did ANY build run on this commit", not "did a
  category-matched pipeline"), so a same-repo skip has no bearing on their evidence — no
  fix needed there, and a stale forward-reference in `azuredevops/provenance`'s own
  rubric claiming otherwise is corrected.
- **`C06.sca.alerts-triaged` (Azure DevOps): a confirmed "alerts not enabled" state now
  reads `verified-fail`, not `not-checkable`** (#190). GHAzDO's actual "not enabled"
  signal for the Alerts - List endpoint turned out to be HTTP 400 with typeKey
  `AdvSecNotEnabledException` — neither of the two codes (403/404) this check's own
  hedge previously considered. This codebase had already decided the opposite for the
  identical org state: the same unlicensed org read `verified-fail` for "dependency
  scanning is off" (`C04.deps.dependabot-alerts`, `C04.secrets.*`,
  `C05.sast.default-setup`) and `not-checkable` for "triage the alerts it would
  produce" — that mismatch is resolved, not introduced, by this change, which mirrors
  the GitHub twin's identical treatment of its own confirmed-disabled signal. Several
  other `[fixture-verify]` hedges this same live run settled are also retired: an
  unlicensed org/project's GHAzDO enablement endpoints read HTTP 200 with every flag
  false/null, never a 403/404 gate as previously guessed, and
  `codeQLEnabled`/`dependencyScanningInjectionEnabled`/`dependabotEnabled`/
  `autofixEnabled` are genuinely null (not merely undocumented-but-never-null) when
  `codeSecurityEnabled` is false, contradicting Microsoft's own "Null is never
  explicitly set" reference claim. A 403 reaching any of these checks is now
  understood as most likely a missing `vso.advsec` token scope (licensing is ruled
  out as the cause), though other permission causes can't be excluded from the
  response alone — this project's own scan PAT already carried that scope, so a
  missing-scope 403 was never actually observed, only inferred by elimination.
- **Report/POA&M `Repo` column/field renamed to `Scope`** (#215). After #176's fix, the
  column could hold three different kinds of thing (an actual repo name, `(org)`, or
  `(project: payments)`) — the header was wrong for two of the three cases it rendered.
  Renamed across `report.md`, `report.html`, and `poam.md`'s `- **Repo:**` line; the
  inline `Repo: ` reason prefix's own label (both renderers) is untouched by this
  rename, since it's only ever shown when the value genuinely is a repo — "Repo:" was
  never the wrong word there, only the standalone column/field header was. Also
  (#216): the hostile-strings escaping regression tests gained a hostile
  `Scope.Project` value, previously untested. Review of that fix (#222) found two real
  escaping holes in `report.md`'s Cluster Detail block — that same inline `Repo:`
  prefix's *value*, plus its Evidence line's (Method/Endpoint/ResponseSHA256) — reached
  output completely unescaped and not inside a code span either, unlike `poam.md`'s
  identical fields — undetected because the hostile fixture's main result used a check
  ID cited by no SSDF task, so it never reached the block those two lines live in; the
  whole Facts-escaping path had been passing vacuously as a result. Fixed by escaping
  both as plain text (no surrounding backticks — CommonMark doesn't process backslash
  escapes inside a code span, so escaping the value while keeping the code-span
  notation would have produced a visible, spurious backslash instead), and
  `internal/mdescape` (the shared markdown escaper every renderer's `esc` template func
  calls) gained its own test file — it previously had none.
- **Azure DevOps packs no longer stamp `scope.project` onto genuinely org-scoped
  results** (#221). `stampResultsWithPlatform` set every result's `Scope.Project` to
  the scan's project unconditionally, so a signed `evidence.json` recorded a project
  scope on org-wide findings too — e.g. `C01.org.2fa-required`, the org-level C09
  audit-logging checks. Reports rendered correctly regardless (labelling keys off
  `CheckMeta.ScopeLevel`, not `Scope.Project`'s presence — see #176), which is why this
  went unnoticed: only the pack itself, the artifact that gets checksummed and
  cosign-signed, carried the wrong claim. `Scope.Project` is now cleared only for a
  result that's genuinely org-scoped (no repo of its own, and its check isn't
  registered `ScopeLevelProject`); it's kept for project-scoped checks as before, and
  now also for every repo-scoped result, since an Azure DevOps repo genuinely lives
  inside a project — clearing it there would have removed accurate context, not a false
  claim. No schema change and nothing to migrate: existing packs aren't rewritten, and
  no downstream consumer reads `scope.project` on a per-result basis (`internal/report`'s
  own renderers do, but only for the checks that keep it, so they're unaffected).

### Changed

- **Harmonized `CheckMeta.Endpoints` host formatting across Azure DevOps collectors**
  (#179): C09 audit-logging and C10 vdp used a path-first style with the host named in
  a trailing parenthetical; every other ADO collector uses host-first
  (`GET <host>/{org}/...`). Both now match the majority convention. Strings and
  `docs/checks-reference.md` only — no behavior change. C10 vdp's `security-md` rubric
  now names its two candidate paths (`/SECURITY.md`, `/docs/SECURITY.md`) explicitly,
  restoring detail the old `Endpoints` parenthetical carried and the trim would
  otherwise have dropped from the published reference.

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
