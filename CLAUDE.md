# CLAUDE.md

Guidance for Claude Code sessions working in this repo. Keep this file's **Progress
tracker** section current as issues land — update it in the same PR/commit that closes
an issue.

## What this is

`attestward` (CLI binary; product name **Attestward**, see [DECISIONS.md](DECISIONS.md)
D1) is a read-only CLI that verifies the technical controls behind the CISA SSDA form
against a GitHub org/repo or Azure DevOps project and emits a signed evidence pack.
Full mission and rationale: [README.md](README.md).

Status: **v0.3.0 released** (2026-07-23 — Azure DevOps support (epic #34, ten
collectors on both platforms), semgrep SAST, and the first signed + GitHub-verified
release tag; verified from a clean machine). The repo stays private for now: the public
flip and everything gated on it land with v1.0 (DECISIONS.md D7, issue #138). All v0.1
phases (0–6) are closed, as is the v0.2 Azure DevOps epic; open work in *this* repo is
the v1.0 public flip (#138), the post-v0.1 backlog, and an ongoing correctness/
hardening stream — review-spawned fixes to guards, renderers, and docs-drift that
don't belong to either bucket above, currently 11 open issues (e.g. #217, #260, #268 —
not enumerated in full here since that list is exactly the kind of hand-maintained
snapshot this section was just corrected for; see the [issue tracker](../../issues)
for the live count) — see **Progress tracker** below. The hosted tier (separate repo
`attestward-cloud`) is tracked entirely there now, not here — every hosted-tier issue
this repo once held (#121–#126) is closed, one delivered, the rest re-filed as
`attestward-cloud` stories.

## The one rule that overrides convenience

**Read-only, forever.** No PR/commit may add a write operation against any platform API.
See [ADR-0004](docs/adr/0004-read-only-local-first.md). If a task seems to need a write
call, stop and flag it rather than adding one.

**Never invent SSDF task IDs, CISA form language, or regulatory citations.** Every ID in
`mappings/ssdf-800-218.yaml` and `mappings/cisa-ssda-form.yaml` must trace to NIST SP
800-218 or the CISA SSDA form primary sources. Paraphrases are marked as paraphrases.
This applies to issues #6, #7, and any docs touching compliance mappings.
`mappings/scanner-signatures.yaml` (issue #16) is a different kind of file — original
data about how tools present in GitHub Actions workflow files and, since #149, Azure
Pipelines YAML too — not a regulatory citation, so this specific rule doesn't apply to
it; see that file's own header comment for the accuracy standard that does (every
signature backed by a real fixture workflow, or for ADO, a fixture pipeline).

## Where things live

| Path | Purpose |
|---|---|
| `docs/checks-reference.md` | Generated (issue #30) — never hand-edit; regenerate with `make checks-docs` from `mappings/*.yaml` + the collector registry, CI enforces via `make checks-docs-check` |
| `docs/architecture.md` | Living architecture doc — update in the same PR as any structural change |
| `docs/threat-model.md` | Living threat model — finalized in issue #31, update as claims change |
| `docs/adr/` | Permanent decision records (Nygard format) — never edited after acceptance, superseded instead |
| `docs/archive/` | Superseded planning docs (product-brief.md, roadmap.md) — historical context only, do not update; GitHub Issues are canonical |
| `DECISIONS.md` | Open questions needing the owner's call — resolve here, promote to an ADR if architectural |
| `mappings/` | SSDF/CISA-form mappings + scanner-signature registry as versioned YAML (issues #6, #7, #16) |
| `CONTRIBUTING.md` | Full workflow rules — branch naming, commit format, PR size, testing conventions |
| `tools/progress/` | Local-only build-progress dashboard (issue #37) — dev convenience, not shipped, not hosted, not linked from README |
| `hack/demo-org-setup.sh` | Idempotent setup script for the public demo org (`Qloud-LTD`) the integration test scans — see DECISIONS.md's D5 |
| `fixtures.yaml` | Expected check status per check per demo repo — the integration test's assertion table; grows as C05–C10 land |
| `hack/demo-ado-setup.sh` | Azure DevOps twin of `demo-org-setup.sh` (issue #155) — idempotent REST 7.1 setup script for the `attestward-demo` project on `dev.azure.com/seciq` |
| `fixtures-ado.yaml` | Azure DevOps twin of `fixtures.yaml` (issue #155) — all 81 entries captured from the definitive 2026-07-23 live scan, kept as a separate file so `fixtures.yaml`/its integration test stay untouched |
| `hack/fetch-drift-baseline.sh` | self-scan.yaml's drift-baseline resolution (issue #211), factored out of the workflow YAML so it's testable against a mocked `gh` — see `fetch-drift-baseline_test.sh`, wired into `ci.yaml`'s `test` job |
| `examples/demo-org-pack/` | Rendered output (`report.md`/`report.html`/`poam.md`) is generated from the pack's own `evidence.json` — never hand-edit; regenerate with `make examples`, CI enforces via `make examples-check` (issue #228, `hack/check-examples-drift.sh`) |
| `tools/rubricguard/` | CI guard (issue #209) — flags a collector package whose status-assignment code changed without its own `checkRubrics` following along in the same diff; dev/CI tooling, not part of the shipped `attestward` binary, wired into `ci.yaml`'s `rubric-drift-check` job |
| `tools/threatmodelguard/` | CI guard (issue #260) — flags any self-hosted-macOS job in `.github/workflows/*.yaml`/`*.yml` not backtick-quoted in `docs/threat-model.md`'s "Shared, persistent runner state" bullet; dev/CI tooling, not part of the shipped `attestward` binary, wired into `ci.yaml`'s `threat-model-drift` job |

Work is tracked entirely in [GitHub Issues](../../issues) — see the
[v0.1 epic (#1)](../../issues/1) for the full build plan across Phases 0–6. There is no
separate local TODO list; if you find work that needs doing, it either already has an
issue or needs one opened before starting.

## Workflow (see CONTRIBUTING.md for the full version)

- Branch from `main`: `<type>/<issue-number>-<short-description>` (types: `feature|fix|hotfix|chore|docs`)
- Conventional commits (`feat|fix|chore|docs|refactor|test|style|perf`), imperative mood, `Fixes #N` in the footer
- Small PRs: target under 200 changed lines, hard ceiling 400 — split bigger work
- Squash merge only; delete branch after merge
- Every collector change ships with fixture-based unit tests (`testdata/`, no live network calls in `go test ./...`)
- Behavior/architecture changes update `docs/` in the same PR; significant design choices get an ADR

## Dev commands

```bash
go version   # 1.26+ installed (1.25+ required — go.mod pins go 1.25.0)
make build   # or: go build ./cmd/attestward
make test
make lint    # golangci-lint run (v2 config — see .golangci.yml)
make tidy    # go mod tidy
```

## Progress tracker

Source of truth is always the [GitHub issues](../../issues) themselves — this table is a
fast local glance, not authoritative. Update the checkbox when a PR closing that issue
merges to `main`. For a visual/live view, regenerate `tools/progress/index.html` with
`python3 tools/progress/generate.py` and open it locally — it pulls current issue state
itself, so re-run it any time rather than hand-editing it.

**Phase 0 — Skeleton**
- [x] #2 Go module, project skeleton, Makefile
- [x] #3 CI — lint, test, build matrix (CodeQL workflow removed — private repo without
  GitHub Advanced Security can't run it; see [DECISIONS.md](DECISIONS.md) D7)
- [x] #4 Release pipeline — goreleaser + cosign

**Phase 1 — Model + mappings**
- [x] #5 Evidence/check data model + JSON Schema
- [x] #6 `mappings/ssdf-800-218.yaml`
- [x] #7 `mappings/cisa-ssda-form.yaml`
- [x] #8 `attestward checks list`

**Phase 2 — Foundation + collectors C01–C04**
- [x] #9 Collector interface + GitHub client foundation
- [x] #10 `attestward scan` orchestrator
- [x] #11 C01 org-security
- [x] #12 C02 repo-protection
- [x] #13 C03 env-separation
- [x] #14 C04 secrets-hygiene
- [x] #15 Demo org + fixtures + integration harness

**Phase 3 — Collectors C05–C07**
- [x] #16 Scanner-signature registry
- [x] #17 C05 sast-history
- [x] #18 C06 sca-history
- [x] #19 C07 provenance

**Phase 4 — Collectors C08–C10 + self-attestation**
- [x] #20 C08 actions-security
- [x] #21 C09 audit-logging
- [x] #22 C10 vdp
- [x] #23 Self-attestation YAML intake

**Phase 5 — Outputs + integrity**
- [x] #24 evidence.json writer
- [x] #25 report.md/html (renderers + non-engineer sign-off complete)
- [x] #26 poam.md
- [x] #27 pack integrity
- [x] #28 `attestward report`

**Phase 6 — Polish & launch**
- [x] #30 Generated checks-reference (`docs/checks-reference.md`, CI drift guard)
- [x] #32 Self-scan workflow + badge (verified live: clean run + deliberate-red/revert test)
- [x] #29 README rewrite (closed for v0.1 — everything doable pre-flip is done; the
  cold-visitor timed test + legal sign-off moved to the v1.0 public-flip issue #138)
- [x] #31 threat model finalization (runtime read-only guard + claim-by-claim audit + external-reader sign-off)
- [x] #33 launch checklist (rescoped per D7 — public flip + its gated items moved to
  #138; the private v0.1.0 release itself is done: changelog + release-notes verify
  footer (#140), logo in report header (#141, resolving D2), release path validated
  via a disposable `v0.1.0-rc.1` then deleted, `v0.1.0` tagged and cosign-verified
  from an independent machine)

**Post-v0.1 backlog** (the "seams only, do not build" rule was v0.1-scoped and has
lapsed — this is now active work)
- [x] #36 Continuous mode (built + closed 2026-07-22: `attestward diff` via
  #143/#144/#145 shipped in v0.2.0; the action lives in the separate
  [attestward-action](https://github.com/sioakim/attestward-action) repo, v1.0.0;
  ADR-0007 write boundary; self-scan migrated as first consumer in #147, drift
  baseline attached to the v0.2.0 release; the first live run correctly caught two
  real gaps, both since fixed: #157 (no SAST covers releases, closed 2026-07-26) and
  #158 (unsigned release tags, closed 2026-07-24 once the signing identity was
  decided). A third, unrelated drift-detection gap surfaced later — #211, still open
  pending live re-verification of its fix (#213))
- [x] #34 Azure DevOps — epic closed 2026-07-23: stories S1–S9 all shipped
  (#148–#156), all ten collectors live on both platforms, 94 registered checks, 18
  collector-phase PRs each through independent session-level review. S9 (#155,
  closed 2026-07-23) delivered `hack/demo-ado-setup.sh` proven live against
  dev.azure.com/seciq (found + fixed 5 real bugs across two review rounds), the
  definitive 81-result fixture capture in `fixtures-ado.yaml`,
  `TestIntegration_ADODemoOrgMatchesFixtures` passing live against the real org, and
  `integration-scan-ado` wired into CI. #190 (retire the [fixture-verify] ledger) is
  also closed. Of the epic's six review-spawned follow-ups, five are closed (#166,
  #176, #178, #179, #184); #181 (secret-hygiene regex v2) remains open as ordinary
  low-priority backlog, not a gate on the now-complete epic.
- [ ] #35 GitLab/SLSA/VEX

**v1.0 milestone**
- Hosted tier (commercial, separate from the OSS CLI; DECISIONS.md D4) — #121–#126,
  this repo's original placeholders, are all closed now: #121 (portfolio dashboard) is
  actually delivered, live at attestward.com/app (built as `attestward-cloud` S4);
  #122–#126 closed NOT_PLANNED, each re-filed as its own story under
  `attestward-cloud`'s epic #11 instead — S8 export/retention (drift itself already
  shipped in cloud S5, closed), S7 team collaboration/POA&M, S10 RSAA-ready packaging
  (still research-first), S9 org SSO, S6 managed continuous mode. Nothing hosted-tier
  is open in this repo anymore; check `attestward-cloud` directly for current status.
- #138 public flip of this OSS repo — the v0.1-deferred launch items (runner trust,
  CodeQL/dependency-review re-add, cold-visitor test, legal sign-off, trademark
  clearance, flip-time secret rescan, the flip + announcement themselves; DECISIONS.md
  D7)
