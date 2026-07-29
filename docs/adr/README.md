# Architecture Decision Records

Significant architectural decisions are recorded here using the
[Nygard format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions):
**Context → Decision → Consequences**, one file per decision, never edited after
acceptance (superseded instead).

| ADR | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-go-single-static-binary.md) | Go, single static binary | Accepted |
| [0003](0003-mappings-as-data.md) | Compliance mappings are data, not code | Accepted |
| [0004](0004-read-only-local-first.md) | Read-only, local-first, zero telemetry | Accepted |
| [0005](0005-collector-interface-seam.md) | Collector interface is the platform seam | Accepted |
| [0006](0006-exec-cosign-not-sigstore-go.md) | Exec cosign, don't embed sigstore-go | Accepted |
| [0007](0007-continuous-mode-write-boundary.md) | Continuous mode's writes live in workflow steps, never the CLI | Accepted |

To add one: copy the newest file, increment the number, open a PR.

Two accepted ADRs now name things that no longer exist. Both are left **unedited on
purpose**: accepted ADRs are superseded, never rewritten, so each stands as an accurate
record of what was decided at the time rather than of what is true today.

- **ADR-0001** refers to a root `DECISIONS.md` for open questions. That file was removed
  when the repo went public — its resolved entries were either folded into the
  docs that needed them or dropped as internal reasoning.
- **ADR-0007** refers to the `sioakim/attestward-action` repository. That action now
  lives in this repo as `action.yml` at the root, documented in
  [docs/action.md](../action.md); the separate repository was deleted. The ADR's
  actual decision — the write boundary continuous mode may not cross — is unaffected by
  where the code sits.
