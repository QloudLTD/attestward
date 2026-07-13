# ADR-0005: Collector interface is the platform seam

**Status:** Accepted · **Date:** 2026-07-13

## Context

v0.1 targets GitHub only, but v0.2 (Azure DevOps) and v0.3 (GitLab) must mirror the same
check semantics (C01–C10). If GitHub assumptions leak into the model, mapping, or report
layers, every new platform becomes a rewrite.

## Decision

All platform-specific code lives behind a narrow interface in `internal/collect`:

```go
type Collector interface {
    ID() string
    Collect(ctx context.Context, scope Scope) ([]CheckResult, error)
}
```

- `CheckResult` is platform-neutral pure data; mapping and rendering layers never import
  platform packages.
- Check IDs (C01–C10) and their semantics are defined at the model/mapping layer;
  a platform implements a check or reports it `not-checkable`.
- `Scope` describes the target (org/project, repos, release pattern, lookback window) in
  platform-neutral terms; each platform package translates it.

## Consequences

- Azure DevOps/GitLab collectors are additive packages plus mapping updates — no changes
  to model, mapping, or report layers.
- Slight up-front cost: v0.1 must resist "just pass the GitHub client through" shortcuts.
- Integration tests are written against the interface, so platform fixtures are parallel
  and comparable.
