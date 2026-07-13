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

To add one: copy the newest file, increment the number, open a PR. Decisions that are
still open questions belong in [DECISIONS.md](../../DECISIONS.md) until resolved.
