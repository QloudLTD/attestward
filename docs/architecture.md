# Architecture

Status: pre-implementation reference. This document describes the intended v0.1
architecture; it is updated in the same PR as any change that affects it.

## Overview

`attestor` is a single static Go binary that:

1. **Collects** — queries the GitHub REST + GraphQL APIs (read-only) for the org/repos in
   scope and produces normalized `CheckResult` records with evidence provenance.
2. **Maps** — rolls results up through data-driven YAML mappings:
   check → SSDF task (SP 800-218) → CISA SSDA form cluster.
3. **Renders** — emits `evidence.json` (machine-readable), `report.md` / `report.html`
   (human-readable), and `poam.md` (draft Plan of Action & Milestones for gaps).
4. **Seals** — hashes the evidence pack (SHA-256) and optionally signs it
   (`cosign sign-blob`).

```
                ┌─────────────┐
 GitHub APIs ──▶│  collectors │──┐
                └─────────────┘  │  []CheckResult
 self-attest ──▶ questionnaire ──┤
   YAML                          ▼
                          ┌─────────────┐     ┌──────────────┐
                          │   mapping   │────▶│   renderers  │──▶ evidence.json
                          │   engine    │     │              │──▶ report.md/html
                          └─────────────┘     └──────────────┘──▶ poam.md
                           mappings/*.yaml           │
                                                     ▼
                                              ┌─────────────┐
                                              │  integrity  │──▶ SHA-256 + cosign
                                              └─────────────┘
```

## Directory layout

```
/cmd/attestor/            # main
/internal/collect/        # collector interface + github/ implementation
/internal/model/          # evidence, check, finding types (versioned schema)
/internal/mapping/        # YAML loader, rollup logic
/internal/report/         # md/html/poam renderers (go templates)
/internal/integrity/      # hashing, optional cosign signing
/mappings/                # ssdf-800-218.yaml, cisa-ssda-form.yaml, scanner-signatures.yaml
/docs/                    # architecture.md, checks reference (generated), threat-model.md
/examples/                # sample config, sample output (from a public demo org)
/.github/workflows/       # ci.yaml, release.yaml, self-scan demo
```

## Key design decisions

Recorded as ADRs in [docs/adr/](adr/). Summary:

- **Go 1.22+, single static binary** ([ADR-0002](adr/0002-go-single-static-binary.md)) —
  standard in security tooling, trivial install, easy audit.
- **Mappings are data, not code** ([ADR-0003](adr/0003-mappings-as-data.md)) — SSDF/CISA
  mappings and scanner signatures live in versioned YAML; community extensions never touch Go.
- **Read-only, local-first, zero telemetry** ([ADR-0004](adr/0004-read-only-local-first.md)).
- **Collector interface as the platform seam** ([ADR-0005](adr/0005-collector-interface-seam.md)) —
  Azure DevOps / GitLab slot in behind the same interface in v0.2+.

## Collector contract

```go
type Collector interface {
    ID() string                    // e.g. "repo-protection"
    Collect(ctx context.Context, scope Scope) ([]CheckResult, error)
}
```

- Results are **pure data**; no rendering or mapping logic inside collectors.
- Platform-specific code stays behind the interface.
- Each collector is independently unit-tested against recorded API fixtures.

## Evidence provenance

Every `CheckResult` stores:

- API endpoint(s) called and HTTP method
- Timestamp (UTC, RFC 3339)
- SHA-256 digest of the raw API response body (never the full payload — responses may
  contain sensitive content)
- A minimal extracted fact set (only the fields the check needs)
- Check status: `verified-pass | verified-fail | partial | self-attested | not-checkable`

Tokens are never stored. Anything secret-shaped is scrubbed defensively before persistence.

## Concurrency & rate limiting

- Per-repo worker pool, default concurrency 4, flag-tunable.
- Respect GitHub primary and secondary rate limits: honor `Retry-After`,
  exponential backoff with jitter, and stop-the-world on secondary-limit responses.

## Versioning

Three independently versioned surfaces, all recorded in `evidence.json`:

1. **Tool version** — semver, from git tag via goreleaser.
2. **Evidence schema version** — bump on any breaking change to the JSON structure;
   JSON Schema published under `/docs`.
3. **Mapping versions** — each YAML mapping file carries its own `version:` field.

### Evidence schema versioning policy

`model.SchemaVersion` (currently `1`) and `docs/schema/evidence-pack.v<N>.schema.json` move
together — a schema bump always ships a new schema file alongside the Go type change in the
same PR; the old file stays for packs written under it (evidence packs are long-lived legal
artifacts, so old packs must remain re-readable and re-verifiable against the schema version
they declare).

**Breaking (bump `SchemaVersion`):** removing/renaming a field, changing a field's type or
JSON name, changing the meaning of an existing value (e.g. narrowing what `partial` means),
adding a new required field, tightening an existing constraint (`additionalProperties` stays
`false` throughout — nothing may silently pass validation that didn't before).

**Non-breaking (no bump):** adding a new optional field; adding a member to an open-ended
enum, as long as it's documented as extensible.

**Exception — `Status` is not an open-ended enum:** the five values in
`internal/model/status.go` are exhaustive by design (every consumer, including third-party
report readers, is expected to switch on exactly those five), so adding a sixth status value
is treated as breaking even though JSON Schema additive changes are usually safe elsewhere.

`internal/model/schema_test.go` enforces the wiring: the fixture pack must validate against
the schema, and a deliberately invalid pack must fail — so code and schema cannot drift
apart silently.

## Dependencies (keep minimal)

`google/go-github`, `shurcooL/githubv4`, `spf13/cobra`, `gopkg.in/yaml.v3`,
`goreleaser` (build-time). Avoid heavyweight frameworks. Every new dependency needs
justification in the PR description.

## Explicitly out of scope for v0.1

- Azure DevOps, GitLab, Bitbucket collectors (v0.2+ — the interface is the seam)
- Any hosted service, web UI, database, telemetry
- Auto-remediation or write operations of any kind
- Filling/submitting the actual CISA form; RSAA integration
- SBOM generation (detect existing SBOM workflows only)
