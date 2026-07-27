# CLAUDE.md

Guidance for Claude Code sessions working in this repo. Work status lives in
[GitHub Issues](../../issues), never in this file — see **Current status** below.

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
don't belong to either bucket above. Current count and specifics are always the
[issue tracker](../../issues) itself, never a number written here — see **Current
status** below for why. The hosted tier (separate repo `attestward-cloud`) is tracked
entirely there now, not here — every hosted-tier issue this repo once held
(#121–#126) is closed, one delivered, the rest re-filed as `attestward-cloud` stories.

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
| `docs/archive/` | Superseded planning docs (product-brief.md, roadmap.md) and the relocated build narrative (progress-narrative.md, issue #276) — historical context only, do not update; GitHub Issues are canonical |
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

## Current status

Tracked entirely in [GitHub Issues](../../issues) and its milestone view — never in
this file. This section used to be a hand-maintained checkbox table mirroring that
state; it repeatedly drifted from the truth (a "closed" epic still shown open, among
other gaps — found only by being asked to specifically audit the file, not caught by
the "update it in the same PR" rule that was supposed to prevent exactly this), which
is worse than no table at all — a wrong checkbox actively misleads a reader, where no
table would have sent them straight to the issues themselves. Removed entirely in
issue #276, including the Phase 0–6 history: it was accurate and stable, but a
partial table invites the same "is the rest of this current?" doubt a fully-drifted
one does.

For current work: the [issue tracker](../../issues) directly, or
`python3 tools/progress/generate.py` for a live visual dashboard
(`tools/progress/index.html`) that pulls issue state itself and so can't go stale the
way a hand-typed table did. For how development actually unfolded — review rounds,
live-verification steps, bugs found along the way, the texture no API can
reconstruct from issue titles alone —
[docs/archive/progress-narrative.md](docs/archive/progress-narrative.md) preserves it,
marked historical/not-maintained the same way `docs/archive/roadmap.md` already is.
