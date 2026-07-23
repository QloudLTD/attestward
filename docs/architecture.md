# Architecture

Status: pre-implementation reference. This document describes the intended v0.1
architecture; it is updated in the same PR as any change that affects it.

## Overview

`attestward` is a single static Go binary that:

1. **Collects** — queries the GitHub REST + GraphQL APIs (read-only) for the org/repos in
   scope and produces normalized `CheckResult` records with evidence provenance.
2. **Maps** — rolls results up through data-driven YAML mappings:
   check → SSDF task (SP 800-218) → CISA SSDA form cluster.
3. **Renders** — emits `evidence.json` (machine-readable), `report.md` / `report.html`
   (human-readable), and `poam.md` (draft Plan of Action & Milestones for gaps).
4. **Seals** — hashes the evidence pack (SHA-256) and optionally signs it
   (`cosign sign-blob`).
5. **Compares** — `attestward diff` reports the semantic difference between two packs
   from the same org (`internal/packdiff`): status transitions classified as
   regressions / improvements / coverage changes, volatile fields ignored, checker
   changes surfaced as context. Exit 2 on regressions, so CI drift detection (issue
   #36) is a plain exit-code check.

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
/cmd/attestward/          # main
/internal/collect/        # collector interface + github/, azuredevops/ implementations
/internal/model/          # evidence, check, finding types (versioned schema)
/internal/mapping/        # YAML loader, rollup logic
/internal/report/         # md/html/poam renderers (go templates)
/internal/packdiff/       # semantic pack comparison (attestward diff)
/internal/integrity/      # hashing, optional cosign signing
/mappings/                # ssdf-800-218.yaml, cisa-ssda-form.yaml, scanner-signatures.yaml,
                           # self-attestation-questions.yaml
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
  Azure DevOps slots in behind the same interface per the v0.2 Azure DevOps epic
  (#34, see below) — ships in the next tagged release; GitLab remains backlog (issue #35).

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

## Azure DevOps (`internal/collect/azuredevops/`)

A second platform behind the same `collect.Collector` seam (ADR-0005; the v0.2 Azure
DevOps epic, issue #34): full C01–C10 parity, same check IDs, `not-checkable` with an
honest, specific reason wherever Azure DevOps has no equivalent control — ships in the
next tagged release. Package tree:

```
/internal/collect/azuredevops/
  client.go, transport.go, ratelimit.go, plangate.go   # foundation
  adofixture/          # recorded-response test harness (twin of github/'s ghfixture)
  orgsecurity/         # C01
  repoprotection/      # C02
  envseparation/       # C03
  secretshygiene/      # C04 (+ ADO-only C04.vars.secret-hygiene)
  pipelinehistory/     # shared pipeline discovery + YAML scanner-signature matching,
                       # used by sasthistory, scahistory, provenance, pipelinesecurity
  sasthistory/         # C05
  scahistory/          # C06
  provenance/          # C07
  pipelinesecurity/    # C08 (+ ADO-only C08.pipelines.fork-protection)
  auditlogging/        # C09
  vdp/                 # C10
```

**Multi-host client.** Unlike GitHub's single `api.github.com`, one Azure DevOps scan
spreads across four hosts, each a `HostXxx` constant in `client.go`: `dev.azure.com`
(`HostCore` — projects, repositories, pipelines, builds; most collector traffic),
`vssps.dev.azure.com` (`HostGraph` — org membership/Graph; no scope-introspection
analog to GitHub's `X-OAuth-Scopes` exists here), `advsec.dev.azure.com` (`HostAdvSec`
— GitHub Advanced Security for Azure DevOps, GHAzDO, licensed per active committer
with no free tier), and `auditservice.dev.azure.com` (`HostAudit` — the Audit Log API,
available only for Azure AD/Entra-backed organizations). `Provenance.Endpoint` and the
`adofixture` recorded-response cache key both carry host, not just path, since a bare
path (e.g. `/{org}/_apis/projects`) would otherwise be ambiguous about which of the
four it went to.

Authentication is HTTP Basic (`Authorization: Basic base64(":"+pat)` — empty username,
the PAT as password), not GitHub's Bearer token: a different scheme injected by the
same single `provenanceTransport` choke point (`transport.go`) that also rejects any
request whose method isn't `GET`/`HEAD`, before auth injection or the network call —
ADR-0004's read-only guard, ported to this package (not shared with the GitHub
client's own copy) per ADR-0005's sibling-implementations framing.

**Rate limiting** (`ratelimit.go`) honors Azure DevOps's TSTU (**Azure DevOps
throughput unit** — Microsoft's own term, an abstract blend of database/compute/storage
load, not an acronym for a literal "time" unit) model, which differs from GitHub's
primary/secondary limits on a structural
axis, not just header names: a **delay** (HTTP 200 — the request still succeeds,
`Retry-After` asks the caller to slow down before its *next* request) and a **block**
(HTTP 429, error code `TF400733` — retried in place, bounded, before surfacing as an
error) are already distinguished by status code alone, with no response-header
inspection needed the way telling GitHub's two tiers apart requires.

**Plan-gating** (`plangate.go`): `IsAdvSecGated`/`IsAuditGated` name the response(s) a
collector treats as "this feature isn't licensed/available for this org" on the
`HostAdvSec`/`HostAudit` surfaces respectively — mirroring `internal/collect/github`'s
own `IsPlanGated`. Several of these paths were only confirmed against a real org
during S9 (issue #155, 2026-07-23); see `docs/threat-model.md` and issue #190 for what
that live run settled versus what's still an open, honestly-hedged assumption.

## Evidence provenance

Every `CheckResult` stores:

- API endpoint(s) called and HTTP method
- Timestamp (UTC, RFC 3339)
- SHA-256 digest of the raw API response body (never the full payload — responses may
  contain sensitive content)
- A minimal extracted fact set (only the fields the check needs)
- Check status: `verified-pass | verified-fail | partial | self-attested | not-checkable`

`CheckResult.Scope` (`model.ScopeRef`) and `EvidencePack.Scope` (`model.ScanScope`) both
additionally carry `Platform` (`"github"` or `"azuredevops"`) and `Project` (the Azure
DevOps project name a scan is scoped to; always empty for a GitHub scan, which has no
equivalent concept) — additive/optional fields (the v0.2 Azure DevOps epic, issue #34)
requiring no `SchemaVersion` bump per the versioning policy below. The scan orchestrator, not each
collector, stamps both fields from the scan's own resolved config, so every result from
one scan — including the not-checkable ones the orchestrator synthesizes itself — is
attributed consistently rather than trusting N collector implementations across two
platforms to each remember to set them.

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

## Explicitly out of scope for v0.1 (Azure DevOps is covered by the v0.2 epic — see above)

- GitLab, Bitbucket collectors (backlog — issue #35 — the interface is the seam)
- Any hosted service, web UI, database, telemetry
- Auto-remediation or write operations of any kind
- Filling/submitting the actual CISA form; RSAA integration
- SBOM generation (detect existing SBOM workflows only)
