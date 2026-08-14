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

- **Go 1.25+, single static binary** ([ADR-0002](adr/0002-go-single-static-binary.md)) —
  standard in security tooling, trivial install, easy audit.
- **Mappings are data, not code** ([ADR-0003](adr/0003-mappings-as-data.md)) — SSDF/CISA
  mappings and scanner signatures live in versioned YAML; community extensions never touch Go.
- **Read-only, local-first, zero telemetry** ([ADR-0004](adr/0004-read-only-local-first.md)).
- **Collector interface as the platform seam** ([ADR-0005](adr/0005-collector-interface-seam.md)) —
  Azure DevOps slots in behind the same interface per the v0.2 Azure DevOps epic
  (#34, see below) — shipped in v0.3.0; GitLab remains backlog (issue #35).

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
honest, specific reason wherever Azure DevOps has no equivalent control — shipped in
v0.3.0. Package tree:

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


## Gogs (`internal/collect/gogs/`)

A third platform behind the same `collect.Collector` seam (ADR-0005), and the one that
tests the seam's central claim most directly: *a platform implements a check or reports
it `not-checkable`.* Gogs implements two of forty-six.

**No hosted instance.** Unlike `api.github.com` or `dev.azure.com`, every Gogs install
lives at its own hostname, so `Client` carries a caller-supplied base URL (`--gogs-url`)
and joins paths onto it — Gogs supports being served under a suburl, so concatenating
would silently scan the wrong location. An unusable base URL fails at construction
rather than falling back to a default: a scan attributed to the wrong subject is the
most dangerous kind of wrong output this tool can produce.

**Token-only auth.** The Gogs REST API rejects HTTP basic auth outright — 401 even with
a correct username and password — so `Authorization: token <t>` is the only scheme, and
there is no fallback. Note that Gogs tokens are not scopable: any token carries the full
permissions of the issuing account, so least privilege here means choosing the account,
not narrowing the token.

**No rate limiting, no pagination.** Gogs sends no rate-limit headers, so there is no
analog of the other two platforms' rate-limit transports — `retryTransport` handles
transient 5xx and nothing else. Nor do list endpoints paginate: verified against Gogs
0.15, `GET /user/repos` returned all 48 repositories in one response and the identical
48 for `?page=1` and `?page=2`, so a pagination loop would never terminate.

**Provenance records the path only, never the host** — matching the GitHub transport
rather than the multi-host ADO one, and for a reason specific to self-hosting: a Gogs
instance is routinely on a private address, and an evidence pack is a document handed to
a customer or a regulator. Recording which checks ran is the point; publishing internal
network topology in the same artifact is not. `Client.BaseURL()` is the single place
instance identity comes from.

**`internal/collect/gogs/unsupported/`** is where most of the platform lives: one
collector per check family, each emitting `not-checkable` results with a reason naming
the specific limitation. Its doc comment distinguishes the two kinds of not-checkable it
carries — *no mechanism exists* (CI, environments, audit log) versus *a signal exists
that this build does not read yet* (repo webhooks, deploy keys, tags, releases) —
because conflating them would be a lie of exactly the kind this tool exists to
eliminate.
## GitHub Enterprise Server (GHES)

GHES is **not** a third `platform` value — it's the same `"github"` platform against a
configurable host (issues #11-#14's GHES epic; settled in #11 rather than left implied by
the first commit). Check IDs, mappings, remediation text, and collector code are
identical; only the base URL, TLS trust, and feature-availability gating differ.

**Base URL and CA trust** (`internal/collect/github/hostconfig.go`): `--github-url` /
`github_url:` / `GITHUB_URL` (in that precedence, resolved once by
`cmd/attestward`'s `resolveGitHubURL`) accepts either a GHES install's browser-facing URL
(`https://ghe.example.com`) or an already-API URL (`https://ghe.example.com/api/v3/`) —
`ResolveHostConfig` derives both the REST base (via go-github's own
`Client.WithEnterpriseURLs`, which handles the "/api/v3" suffix idempotently) and the
GraphQL endpoint (`{host}/api/graphql`, hand-derived since neither go-github nor
`githubv4` has an enterprise-URL helper for GraphQL). The resulting `ClientConfig` is a
single factory argument every one of the ten collectors' own `ghcollect.NewClient` call
sites carries — `rg 'NewClient\(' internal/collect/github cmd/attestward` shows none
built without it. `GITHUB_CA_CERT` (env-only, no flag/config key) loads a private CA into
the shared `http.Client`'s TLS trust store via a cloned `http.Transport` (never mutating
`http.DefaultTransport` itself, and preserving its `HTTPS_PROXY` support). Empty
`--github-url`/`GITHUB_CA_CERT` is a no-op — every existing github.com setup is
byte-for-byte unchanged.

**Host/version detection** (`internal/collect/github/hostinfo.go`,
`internal/collect/github/gatekind.go`): `Client.GHESVersion()` observes the
`X-GitHub-Enterprise-Version` response header on the first call that actually carries it.
github.com never sends it, so its presence is positive evidence of GHES — but its
**absence proves nothing**: a proxy stripping unknown `X-*` headers, or an error
generated by a load balancer in front of GHES, is indistinguishable from github.com at
this layer. So "is this GHES" comes from the configured `--github-url`
(`Scope.IsGHES`), and the version is carried separately as whatever was learned
(`Scope.GHESVersion`), both resolved at preflight — the same "resolve once, carry it"
pattern `Scope.AccountType` follows. Keying the classification on the version instead
was a real defect: a GHES install whose header was stripped produced a pack asserting a
GitHub Enterprise *Cloud* plan tier alongside its own `scope.github_url`.

`ghcollect.ClassifyGate`/`GateReason` replace a single `IsPlanGated`-derived "not
available on this org's plan" Reason (still correct on github.com, unchanged) with
`GateKindLicence` on a GHES target — GHES has no per-org plan tier at all, so "plan" is
simply wrong there. The licence Reason deliberately **names no cause**: GitHub returns
the same status for an unlicensed feature, a version predating the endpoint, and a token
missing the required scope, so it lists all three rather than ranking them. An earlier
draft said "most likely not licensed (e.g. GitHub Advanced Security)", which was untrue
for the org audit log (no Advanced Security dependency) and dropped the token-scope
alternative the github.com Reason is careful to keep. `GateKindVersion` exists but is
unreachable today: no check carries verified minimum-version data, and inventing one
would be the fabricated claim this machinery exists to prevent. Wired into C09 audit-logging's org audit-log probe
and C05 sast-history's CodeQL default-setup probe as of issue #12 — the two collectors
with a genuinely verifiable, single status-code-gated endpoint from the epic's audit;
C04 secrets-hygiene's field-presence-based GHAS gating and C06 sca-history's
message-substring-based Dependabot gating were deliberately left on their existing,
github.com-verified logic rather than guessed at for GHES.

**Per-check divergence audit** (issue #13): every registered `collect.CheckMeta` with
`Endpoints` also carries a `GHESNote` — one of three canonical strings
(`ghcollect.GHESNoteSupported` / `GHESNoteLicenceGated` / `GHESNoteUnverified`,
`internal/collect/github/ghesnotes.go`) rendered into
[docs/checks-reference.md](checks-reference.md) alongside each check's Endpoints/Rubric.
`GHESNoteUnverified` marks a check whose endpoint is recent or unusual enough on
github.com (Artifact Attestations, Private Vulnerability Reporting, Dependabot's GitHub
Connect dependency) that this tool's authors have no confirmed knowledge of its GHES
availability — an honest "don't know" rather than a guess presented as fact.

**Provenance paths are real, not normalized**: `Provenance.Endpoint` records
`req.URL.Path` unmodified, so a GHES scan's provenance naturally comes out prefixed
`/api/v3` (e.g. `/api/v3/orgs/{org}`) — a side effect of go-github's request builder
resolving against `Client.BaseURL`, not special-cased in `provenanceTransport`. This was
a deliberate choice (issue #13), not an oversight: a provenance entry should describe the
request that actually happened, which matters for `attestward diff` comparing two packs'
provenance and for anyone auditing a signed GHES pack against the install it came from.

**This support is fixture-only.** There is no GHES instance in this project's CI or test
infrastructure — every scenario above is proven with `httptest`/`ghfixture` against
GHES-shaped routing and responses, never a real install. State this plainly to anyone
evaluating whether to point `attestward` at a production GHES: the mechanism is real and
tested, but "GHES support" here means "known-correct routing and honest gating logic,"
not "exercised against GitHub's own GHES software."

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
DevOps project name; always empty for a GitHub scan, which has no equivalent concept) —
additive/optional fields (the v0.2 Azure DevOps epic, issue #34) requiring no
`SchemaVersion` bump per the versioning policy below. The scan orchestrator, not each
collector, is authoritative for both — no collector's own value is trusted. `Platform`
is stamped onto every result unconditionally, including the not-checkable ones the
orchestrator synthesizes itself. `Project`, on `CheckResult.Scope` specifically, is
stamped onto a result whenever it's genuinely true of that result: the check is
registered project-scoped (`CheckMeta.ScopeLevel == ScopeLevelProject`, issue #176), or
the result carries a `Repo` (an Azure DevOps repo lives inside a project, so `Project`
is real context there too) — a genuinely org-scoped result (no repo of its own, not
registered project-scoped) has it cleared instead: a signed pack asserting a project
scope for a finding that isn't actually about one project would itself be a factual
inaccuracy (issue #221). `EvidencePack.Scope.Project`, the pack-level field, is
unaffected by this and still always records the scan's own `--project` value.

`EvidencePack.Scope` (not `CheckResult.Scope`) additionally carries `GitHubURL` (issue
#11's GHES epic): the resolved `--github-url`/`github_url:`/`GITHUB_URL` value for a
github scan, empty for github.com or any azuredevops scan — so a reader of a signed pack
can tell which GitHub install actually produced it, rather than assuming
`api.github.com`. Also additive/optional, no `SchemaVersion` bump.

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
