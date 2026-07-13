# ADR-0002: Go, single static binary

**Status:** Accepted · **Date:** 2026-07-13

## Context

The audience is security and compliance engineers at small-to-mid software vendors. They
will not stand up a server, install a runtime, or `pip install` a dependency tree to
evaluate a compliance tool. The tool must also be trivially auditable — it runs with a
token that can read an entire GitHub org.

## Decision

Go 1.22+, compiled to a single static binary per platform (linux/amd64+arm64,
darwin/amd64+arm64, windows/amd64), released via goreleaser with checksums and cosign
signatures. Distribution: direct download, `go install`, Homebrew tap later.

Dependencies are kept to a short, boring list: `google/go-github`, `shurcooL/githubv4`,
`spf13/cobra`, `gopkg.in/yaml.v3`. Every new dependency must be justified in its PR.

## Consequences

- Zero-friction install and air-gap-friendly operation.
- Go is the lingua franca of security tooling (trivy, grype, cosign, gh) — contributors
  and auditors expect it.
- No plugin system in v0.1: new collectors compile into the binary. Acceptable because
  mappings/signatures are data ([ADR-0003](0003-mappings-as-data.md)).
- Windows build is produced from day one to catch platform issues early, even though
  Windows-specific build-server analysis is out of scope.
