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
| `THIRD-PARTY-NOTICES.md` | Generated (issue #282) — never hand-edit; regenerate with `make notices` from the resolved module graph (`go list -deps`, every OS/arch the release ships) + each dependency's own LICENSE in the module cache, CI enforces via `make notices-check`; ships in every release archive alongside `LICENSE`/`NOTICE` (`.goreleaser.yaml`'s `archives.files`) |
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
- Conventional commits (`feat|fix|chore|docs|refactor|test|style|perf`), imperative mood, `Refs #N` in the footer
- **Never `Fixes`/`Closes #N`** in a commit or PR body — squash-merge auto-closes the issue, losing the close comment that records the evidence. Verify with `gh pr view <N> --json closingIssuesReferences` → `[]`
- Small PRs: target under 200 changed lines, hard ceiling 400 — split bigger work
- Squash merge only; delete branch after merge — **except a stacked PR's parent**: merge it *without* `--delete-branch` so the child auto-retargets, since deleting the base auto-closes the child unrecoverably. After a squash-merged parent the child hits add/add conflicts; cherry-pick its own commits onto `main` rather than resolving
- Every collector change ships with fixture-based unit tests (`testdata/`, no live network calls in `go test ./...`)
- Behavior/architecture changes update `docs/` in the same PR; significant design choices get an ADR

## Dev commands

```bash
go version   # 1.26+ installed (1.25+ required — go.mod pins go 1.25.0)
make build   # or: go build ./cmd/attestward
make test
make lint    # golangci-lint run (v2 config — see .golangci.yml)
make tidy    # go mod tidy

make checks-docs-check examples-check tidy-check   # drift guards, all wired into CI
go run ./tools/rubricguard <base> <head>           # status-vs-checkRubrics drift
go run ./tools/threatmodelguard                    # threat-model job enumeration
gh workflow run integration-scan.yaml              # live demo-org scan (otherwise weekly only)
```

## Only statuses are guarded

`rubricguard` compares a package's status-assignment code against that package's own
`checkRubrics`; the integration test's `assertFixtureChecks` compares `Status` and reads
`Reason` only inside its failure message. **Nothing asserts on a `Reason` string, rubric
prose, or a `Facts` value.** Treat all three as untested customer-facing output.

They do not all surface in the same place, and the difference sets how bad a wrong one is.
`Reason` and `Facts` are schema properties on every result, so they **render verbatim into
signed evidence packs**. Rubric prose does not: `CheckMeta.Rubric`'s only non-collector
consumer is `internal/checksref/render.go` → the generated `docs/checks-reference.md`, and
`docs/schema/evidence-pack.v1.schema.json` has no rubric field at all. So a stale rubric
misleads a reader of the generated reference, not an auditor of a signed pack — still worth
fixing, but don't weight it as if it shipped inside the attestation artifact.

The tell for the recurring defect class is `x := err == nil && resp.Field`: a value that
silently defaults on error, then gets asserted as a confirmed observation. The same false
inference was found on five separate surfaces because fixing one reached none of the
others — see `docs/handoff-2026-07-28.md`.

`rubricguard` is also blind to cross-package drift: a change in `cmd/attestward` can
invalidate rubrics in six collector packages without flagging.

## CI signals that mislead

- `continue-on-error: true` normalizes a step's `conclusion` to success — only `outcome`
  shows the truth. A green run can hide a failed artifact upload.
- A **cancelled** job renders identically to a **failed** one in `gh pr checks`; check the
  job's step conclusions (`gh api repos/{o}/{r}/actions/jobs/{id}`) before assuming a real failure.
- "no checks reported" ≠ failing — a branch GitHub can't merge cleanly never gets a
  `pull_request` run. Merge `main` in first.
- A run can read `status=queued`/`conclusion=null` at the **run** level while `lint` and
  `test` inside it already completed `success` — non-required jobs (`build`,
  `gomod-tidy-drift`) keep the run open. Unlike the two above, this hides a ready merge
  rather than inventing a failure. Read job conclusions (`.../runs/{id}/jobs`), never the run.
- Only `lint` and `test` are required (`gh api repos/{o}/{r}/rulesets`); `--admin` bypasses
  the 1-approval rule, not status checks. It is needed on **every** merge here: the PR author
  and the `gh` account are the same identity, so GitHub won't let it approve its own PR and
  `reviewDecision` stays `REVIEW_REQUIRED` permanently.
- `gh pr merge --delete-branch` exits **non-zero on a successful merge** when a worktree
  still holds the local branch. The merge landed; confirm with `gh pr view <N> --json state`
  rather than reading the exit code as failure.
- A context expression inside a `run:` block is substituted **before the shell sees it,
  including inside a `#` comment** — an empty `${{ }}` is a hard syntax error and a valid
  one silently interpolates. `actionlint` catches only the former, and isn't run in CI.

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
