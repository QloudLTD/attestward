# CLAUDE.md

Guidance for Claude Code sessions working in this repo. Keep this file's **Progress
tracker** section current as issues land — update it in the same PR/commit that closes
an issue.

## What this is

`attestor` (working name — see [DECISIONS.md](DECISIONS.md) D1) is a read-only CLI that
verifies the technical controls behind the CISA SSDA form against a GitHub org/repo and
emits a signed evidence pack. Full mission and rationale: [README.md](README.md).

Status: pre-alpha. v0.1 has no code yet as of 2026-07-13; build is issue-driven and
in progress (see Progress tracker below).

## The one rule that overrides convenience

**Read-only, forever.** No PR/commit may add a write operation against any platform API.
See [ADR-0004](docs/adr/0004-read-only-local-first.md). If a task seems to need a write
call, stop and flag it rather than adding one.

**Never invent SSDF task IDs, CISA form language, or regulatory citations.** Every ID in
`mappings/*.yaml` must trace to NIST SP 800-218 or the CISA SSDA form primary sources.
Paraphrases are marked as paraphrases. This applies to issues #6, #7, #16, and any docs
touching compliance mappings.

## Where things live

| Path | Purpose |
|---|---|
| `docs/architecture.md` | Living architecture doc — update in the same PR as any structural change |
| `docs/threat-model.md` | Living threat model — finalized in issue #31, update as claims change |
| `docs/adr/` | Permanent decision records (Nygard format) — never edited after acceptance, superseded instead |
| `docs/archive/` | Superseded planning docs (product-brief.md, roadmap.md) — historical context only, do not update; GitHub Issues are canonical |
| `DECISIONS.md` | Open questions needing the owner's call — resolve here, promote to an ADR if architectural |
| `mappings/` | SSDF/CISA-form mappings as versioned YAML (once authored — issues #6, #7, #16) |
| `CONTRIBUTING.md` | Full workflow rules — branch naming, commit format, PR size, testing conventions |
| `tools/progress/` | Local-only build-progress dashboard (issue #37) — dev convenience, not shipped, not hosted, not linked from README |

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
go version   # 1.26+ installed (1.22+ required)
make build   # or: go build ./cmd/attestor
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
- [x] #3 CI — lint, test, build matrix, CodeQL
- [x] #4 Release pipeline — goreleaser + cosign

**Phase 1 — Model + mappings**
- [ ] #5 Evidence/check data model + JSON Schema
- [ ] #6 `mappings/ssdf-800-218.yaml`
- [ ] #7 `mappings/cisa-ssda-form.yaml`
- [ ] #8 `attestor checks list`

**Phase 2 — Foundation + collectors C01–C04**
- [ ] #9 Collector interface + GitHub client foundation
- [ ] #10 `attestor scan` orchestrator
- [ ] #11 C01 org-security · #12 C02 repo-protection · #13 C03 env-separation · #14 C04 secrets-hygiene
- [ ] #15 Demo org + fixtures + integration harness

**Phase 3 — Collectors C05–C07**
- [ ] #16 Scanner-signature registry
- [ ] #17 C05 sast-history · #18 C06 sca-history · #19 C07 provenance

**Phase 4 — Collectors C08–C10 + self-attestation**
- [ ] #20 C08 actions-security · #21 C09 audit-logging · #22 C10 vdp
- [ ] #23 Self-attestation YAML intake

**Phase 5 — Outputs + integrity**
- [ ] #24 evidence.json writer · #25 report.md/html · #26 poam.md · #27 pack integrity · #28 `attestor report`

**Phase 6 — Polish & launch**
- [ ] #29 README rewrite · #30 generated checks-reference · #31 threat model finalization · #32 self-scan badge · #33 launch checklist

**Post-v0.1 (seams only, do not build)**
- #34 Azure DevOps · #35 GitLab/SLSA/VEX · #36 Continuous mode GitHub Action
