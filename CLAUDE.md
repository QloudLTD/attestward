# CLAUDE.md

Guidance for Claude Code sessions working in this repo. Keep this file's **Progress
tracker** section current as issues land — update it in the same PR/commit that closes
an issue.

## What this is

`attestward` (the CLI binary name; the product's public name is **Attestward** — see
[DECISIONS.md](DECISIONS.md) D1, resolved 2026-07-19) is a read-only CLI that verifies
the technical controls behind the CISA SSDA form against a GitHub org/repo and emits a
signed evidence pack. Full mission and rationale: [README.md](README.md). The GitHub
repo itself was renamed from `ssdf` to `attestward` (still private, per D7), and the Go
module path (`go.mod`'s `module github.com/sioakim/attestward`, and every internal
import) was updated to match in the same 2026-07-19 pass — verified via a full
`go build`/`go vet`/`go test`/`make lint` run, not assumed clean from the mechanical
find-replace alone.

Status: pre-alpha. Phase 0 (skeleton, CI, release pipeline), Phase 1 (data model,
SSDF/CISA mappings, `checks list`), Phase 2 (C01–C04 collectors, demo org +
integration harness), and Phase 3 (#16 scanner-signature registry, #17 C05
sast-history, #18 C06 sca-history, #19 C07 provenance) are merged to `main`.
Phase 4 (#20 C08 actions-security, #21 C09 audit-logging, #22 C10 vdp, #23
self-attestation intake) is merged to `main` — the full v0.1 check matrix
(C01–C10 plus self-attestation) is now in place. Phase 5 is in progress:
#24 (evidence.json writer — determinism, atomic writes, pre-write schema
validation) is merged; the `internal/report` renderers for #25 (report.md/html)
are code-complete and merged, but #25 itself stays open pending the issue's
own non-engineer sign-off requirement (see the PR/issue for details); #26
(poam.md — `collect.CheckMeta.Remediation` backfilled across all 46 C01–C10
checks, renderer merged, cross-linked with report.md's Gaps table via shared
POA&M finding IDs) is merged; #27 (pack integrity) is merged — SHA-256
hashing, the `.sha256` sidecar, `attestward verify` (hash + cosign
signature), and `attestward scan --sign` are all in place (ADR-0006 records
why cosign is shelled out to rather than vendored). #28 (`attestward
report`) is merged — regenerates report.md/report.html/poam.md from an
existing evidence.json with no scan and no network access, gates on
schema_version, checks the .sha256 sidecar when present (refusing to
render a hash mismatch unless `--force`, which then renders with a visible
banner), and sets Integrity.SHA256 so report.md/html always show the hash
of the exact bytes rendered. Phase 5 is otherwise complete; #25 stays open
pending its own non-engineer sign-off requirement (renderers themselves
are merged). Phase 6 is in progress: #30 (generated `docs/checks-reference.md`)
is merged — the `internal/checksref` renderer plus `attestward checks docs`
(`--check` for the CI drift guard, wired into `.github/workflows/ci.yaml`)
generate the reference from `mappings/*.yaml` and the C01–C10 registry, with
the file itself committed and cross-linked from the README. #32 (self-scan
workflow) is also merged and closed — `.github/workflows/self-scan.yaml`
runs `attestward scan` against `sioakim/attestward` itself on release/weekly/manual
dispatch, verified live (not just reasoned about) under the real restricted
`GITHUB_TOKEN`: a first clean run, a deliberate-red test (disabled
Dependabot alerts, confirmed the job failed, reverted, confirmed green
again), badge + a "Self-scan" README section linking real (not demo-org)
sample runs. Building it surfaced and fixed #102 (`attestward scan` couldn't
target a personal-GitHub-account-owned repo — this repo itself — at all)
and 3 of 8 real gaps in this repo's own posture (PR #104); 2 more gaps are
tracked as their own issues (#105, #106) rather than fixed unilaterally,
and one (GHAS-gated dependency review) is a documented, accepted gap
(DECISIONS.md D7) alongside CodeQL. #29 (README rewrite) had PR #110
merged — the narrative arc, PAT table cross-checked against the live
registry, a real `/examples` sample pack + asciinema recording, and a
legal-claims accuracy pass that caught a real staleness issue (OMB
M-26-05 rescinded the CISA Common Form mandate in January 2026) — but
#29 itself stays open, same shape as #25, pending gates only a human or
a public repo can satisfy: the cold-visitor timed quickstart test,
PAT-minimality testing, and a professional legal sign-off. #31 (threat
model finalization) is merged and closed — `docs/threat-model.md` was
rewritten with every normative claim traced to specific code/tests
(re-verified against v0.1, not the pre-implementation draft it started
as), and `provenanceTransport.RoundTrip`
(`internal/collect/github/transport.go`) now structurally rejects any
non-GET/HEAD request before auth injection or the network call — the
"read-only, forever" claim (ADR-0004) is enforced at runtime, not just
by review, covering both the REST and GraphQL clients since they share
one transport. Unlike #25/#29, #31's external-reader review requirement
was genuinely satisfiable in this session: an independent review agent
adversarially verified every claim against the code, found two real
gaps across two passes (three missing orchestrator-level call sites,
then an overstated call-frequency claim), both fixed and re-verified,
before posting its own sign-off comment directly on the issue. Build is
issue-driven and in progress (see Progress tracker below).

## The one rule that overrides convenience

**Read-only, forever.** No PR/commit may add a write operation against any platform API.
See [ADR-0004](docs/adr/0004-read-only-local-first.md). If a task seems to need a write
call, stop and flag it rather than adding one.

**Never invent SSDF task IDs, CISA form language, or regulatory citations.** Every ID in
`mappings/ssdf-800-218.yaml` and `mappings/cisa-ssda-form.yaml` must trace to NIST SP
800-218 or the CISA SSDA form primary sources. Paraphrases are marked as paraphrases.
This applies to issues #6, #7, and any docs touching compliance mappings.
`mappings/scanner-signatures.yaml` (issue #16) is a different kind of file — original
data about how tools present in GitHub Actions workflows, not a regulatory citation —
so this specific rule doesn't apply to it; see that file's own header comment for the
accuracy standard that does (every signature backed by a real fixture workflow).

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
- [ ] #25 report.md/html (renderers merged; issue open pending non-engineer sign-off)
- [x] #26 poam.md
- [x] #27 pack integrity
- [x] #28 `attestward report`

**Phase 6 — Polish & launch**
- [x] #30 Generated checks-reference (`docs/checks-reference.md`, CI drift guard)
- [x] #32 Self-scan workflow + badge (verified live: clean run + deliberate-red/revert test)
- [ ] #29 README rewrite (PR #110 merged; issue open pending cold-visitor timed test + PAT-minimality test + legal sign-off)
- [x] #31 threat model finalization (runtime read-only guard + claim-by-claim audit + external-reader sign-off)
- [ ] #33 launch checklist

**Post-v0.1 backlog (seams only, do not build)**
- #34 Azure DevOps · #35 GitLab/SLSA/VEX · #36 Continuous mode GitHub Action

**v1.0 milestone — hosted tier** (commercial, separate from the OSS CLI; DECISIONS.md D4)
- #121 portfolio dashboard · #122 evidence retention/drift · #123 team
  collaboration/POA&M · #124 RSAA-ready packaging (undefined, research-first) · #125 org
  SSO · #126 managed continuous mode (builds on #36)
