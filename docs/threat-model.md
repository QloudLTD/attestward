# Threat Model

**Status: finalized (issue #31).** Every normative claim below carries a code and/or test
reference, re-verified against the actual v0.1 codebase rather than the pre-implementation
draft this document started as. A threat model that doesn't match the implementation is
worse than none, because security teams use this document to clear the tool for org-wide
token access.

## What the tool is

A local, read-only CLI that queries source-control APIs with a user-supplied token and
writes evidence files to a user-chosen local directory. No server component, no database,
no telemetry, no network destinations other than the platform API in scope for a given
scan — `api.github.com` for `--platform github` (the default), or, per the v0.2 Azure
DevOps epic (issue #34, ships in the next tagged release), exactly four first-party
Azure DevOps hosts for `--platform azuredevops`: `dev.azure.com`, `vssps.dev.azure.com`
(Graph), `advsec.dev.azure.com` (GHAzDO), and `auditservice.dev.azure.com` (Audit Log) —
see `docs/architecture.md`'s "Azure DevOps" section for what each one serves. One scan
targets exactly one platform, never both — `cmd/attestward/scan.go`'s own comment on
this ("pack is one scan of one platform (no mixed-platform packs)") and
`cmd/attestward/report.go`'s ("A pack covers exactly one platform (no mixed-platform
packs)", guarding against silently overwriting one platform's remediation text with
another's when rendering). The only other network egress at all, on either platform, is
— only when `--sign`/`attestward verify` invoke it — the separately-trusted `cosign`
subprocess (see "Signing egress is a distinct, opt-in exception" below).

## Assets

| Asset | Sensitivity | Handling |
|---|---|---|
| GitHub token (`GITHUB_TOKEN`) | High — grants org read access | Read from env var only; never persisted, never logged, never included in evidence output |
| Azure DevOps PAT (`AZURE_DEVOPS_EXT_PAT`) | High — grants org/project read access | Read from env var only; never persisted, never logged, never included in evidence output; injected as an HTTP Basic `Authorization` header by `internal/collect/azuredevops/transport.go`'s `provenanceTransport`, the same single choke point as the GitHub client's own token handling |
| Raw API responses | Medium — may contain member lists, security-alert details | Only SHA-256 digests + minimal extracted facts are persisted |
| Evidence pack | Medium — reveals security posture and gaps | Written locally only; user decides distribution; pack hash enables tamper-evidence |
| Self-attestation answers | Medium | Treated as user-authored input, echoed into evidence clearly labeled `self-attested` |

## Trust boundaries

1. **User ↔ tool**: the user supplies the token and config; the tool must honor
   least-privilege guidance (fine-grained PAT, read-only scopes, documented precisely).
2. **Tool ↔ platform API**: TLS only; responses are untrusted input — parsed defensively,
   size-limited, never executed or templated into shell commands. Identical posture for
   both platforms this tool talks to: `api.github.com` for `--platform github`, or
   Azure DevOps's four hosts (`dev.azure.com`, `vssps.dev.azure.com`,
   `advsec.dev.azure.com`, `auditservice.dev.azure.com`) for `--platform azuredevops`.
3. **Tool ↔ filesystem**: writes only under the user-specified `--out` directory.
4. **Tool ↔ `cosign` subprocess** (opt-in, `--sign`/pack verification only): a separate
   trusted binary the user must install themselves; attestward shells out to it and never
   parses or trusts its stdout beyond an exit code (see "Signing egress" below).

## What the tool never does — and how that's enforced

Every claim here previously rested on code review alone (ADR-0004). As of this
finalization, the read-only claim also has a structural, tested enforcement point; the
others are traced to the specific code and tests that make them true today, not just
asserted.

### No write operations

**Enforcement:** `provenanceTransport.RoundTrip`
(`internal/collect/github/transport.go`) rejects any HTTP request whose method isn't
`GET` or `HEAD` — before auth injection, before the network call — for every request
issued through `Client` (both the REST and GraphQL clients share this one transport; see
`NewClient`'s doc comment in `internal/collect/github/client.go`). Regression tests:
`TestProvenanceTransportRejectsWriteMethods` (POST/PUT/PATCH/DELETE all rejected,
confirmed the base transport is never reached) and `TestProvenanceTransportAllowsHead`
(HEAD, a legitimate read method, still passes) in `internal/collect/github/transport_test.go`.

This closes a real gap: before this finalization, "read-only" was enforced only by
review discipline, with no runtime guard at all. The guard was mutation-tested during
this issue's own work (temporarily removed, confirmed the new tests catch it, restored)
before landing.

GraphQL note: `Client.GraphQL` is wired up (`internal/collect/github/client.go`) but no
collector calls it as of this writing (`git grep -n '\.GraphQL\.' internal/collect/github`
returns nothing at all). Since GraphQL "query" and "mutation" operations both
travel as an HTTP `POST`, the transport-level guard can't currently distinguish a
read-only GraphQL query from a mutation — it rejects both, which is the correct, honest
behavior for a code path nothing uses today. The first real GraphQL query added to this
codebase will need to deliberately extend this guard (e.g. inspecting the request body
for a leading `query` keyword) rather than have it silently pass; building that
allow-list now, before anything needs it, would be speculative engineering.

**Azure DevOps (the v0.2 epic, issue #34):** the identical structural guard, ported rather than
shared (ADR-0005's sibling-implementations framing) — `provenanceTransport.RoundTrip`
(`internal/collect/azuredevops/transport.go`) rejects any request whose method isn't
`GET`/`HEAD`, before auth injection or the network call, for every request issued
through `azuredevops.Client` across all four hosts. Regression tests:
`TestProvenanceTransportRejectsWriteMethods` and `TestProvenanceTransportAllowsHead`
in `internal/collect/azuredevops/transport_test.go` — the same two-test shape as the
GitHub twin's own tests above. Every ADO REST call any collector makes is a `GET`; none
of the ten ADO collector packages (`internal/collect/azuredevops/{orgsecurity,
repoprotection, envseparation, secretshygiene, sasthistory, scahistory, provenance,
pipelinesecurity, auditlogging, vdp}/`) is exhaustively enumerated here the way
GitHub's table below is — `docs/checks-reference.md`'s `azuredevops` subsections are
the generated, per-check equivalent (every check there lists its own backing
endpoint(s)), kept current by the same drift guard (`make checks-docs-check`) as the
GitHub side.

**Enumerated call sites** (every REST method any collector calls, `git grep`'d and each
individually confirmed against go-github v75's own source to issue exactly the HTTP verb
named — not inferred from the method name):

| go-github call | Endpoint (verb confirmed against source) |
|---|---|
| `Actions.ListRepositoryWorkflowRuns` | `GET /repos/{owner}/{repo}/actions/runs` |
| `Actions.ListWorkflowRunsByID` | `GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs` |
| `Actions.ListWorkflows` | `GET /repos/{owner}/{repo}/actions/workflows` |
| `CodeScanning.GetDefaultSetupConfiguration` | `GET /repos/{owner}/{repo}/code-scanning/default-setup` |
| `Dependabot.ListRepoAlerts` | `GET /repos/{owner}/{repo}/dependabot/alerts` |
| `Git.GetRef` | `GET /repos/{owner}/{repo}/git/ref/{ref}` |
| `Git.GetTag` | `GET /repos/{owner}/{repo}/git/tags/{tag_sha}` |
| `Organizations.Get` | `GET /orgs/{org}` |
| `Organizations.GetAuditLog` | `GET /orgs/{org}/audit-log` |
| `Organizations.ListMembers` | `GET /orgs/{org}/members` |
| `Repositories.Get` | `GET /repos/{owner}/{repo}` |
| `Repositories.GetBranchProtection` | `GET /repos/{owner}/{repo}/branches/{branch}/protection` |
| `Repositories.GetContents` | `GET /repos/{owner}/{repo}/contents/{path}` |
| `Repositories.GetDefaultWorkflowPermissions` | `GET /repos/{owner}/{repo}/actions/permissions/workflow` |
| `Repositories.GetRuleset` | `GET /repos/{owner}/{repo}/rulesets/{ruleset_id}` |
| `Repositories.GetRulesForBranch` | `GET /repos/{owner}/{repo}/rules/branches/{branch}` |
| `Repositories.GetVulnerabilityAlerts` | `GET /repos/{owner}/{repo}/vulnerability-alerts` |
| `Repositories.IsPrivateReportingEnabled` | `GET /repos/{owner}/{repo}/private-vulnerability-reporting` |
| `Repositories.ListAttestations` | `GET /repos/{owner}/{repo}/attestations/{subject_digest}` |
| `Repositories.ListEnvironments` | `GET /repos/{owner}/{repo}/environments` |
| `Repositories.ListHooks` | `GET /repos/{owner}/{repo}/hooks` |
| `Repositories.ListReleases` | `GET /repos/{owner}/{repo}/releases` |

Three more calls happen outside any collector, in the scan orchestrator itself
(`cmd/attestward/scanrepos.go`, using the bare `*github.Client` that `runScan` gets from
`NewClient(...).REST` in `cmd/attestward/scan.go`) — a `.REST.`-style `git grep` scoped to
`internal/collect/github` misses them entirely, so they're listed separately.
`Users.Get` runs on every scan (the unconditional account-type preflight); the two
repo-listing calls run only when no explicit repo list is configured (`resolveRepos`
makes zero API calls otherwise):

| go-github call | Endpoint (verb confirmed against source) | Call site |
|---|---|---|
| `Users.Get` | `GET /users/{account}` | `cmd/attestward/scanrepos.go:122` |
| `Repositories.ListByOrg` | `GET /orgs/{org}/repos` | `cmd/attestward/scanrepos.go:46` |
| `Repositories.ListByUser` | `GET /users/{user}/repos` | `cmd/attestward/scanrepos.go:75` |

All three route through the same `client.REST` / `provenanceTransport` as every
collector call above, so the read-only guard covers them identically — this was a gap in
this table's derivation method (grep scope), not in the enforcement itself.

This table is a point-in-time enumeration, and a GitHub-only one — see the Azure
DevOps paragraph above for that platform's equivalent, deliberately not enumerated to
the same per-endpoint depth here (re-derive this one with the `git grep` above for
collectors, plus a manual check for bare-`*github.Client` call sites like the
orchestrator's — a grep scoped to `internal/collect/github` won't catch those); the
transport guard above is what actually holds the invariant going forward, not this table
by itself. `docs/checks-reference.md` (generated, `attestward checks docs`) is the live,
per-check breakdown of which endpoint backs which check, for both platforms — this
table is the flip side for GitHub specifically: every endpoint the code calls, grouped
by API surface instead of by check.

### No network egress besides the platform API

**Enforcement:** `internal/collect/github/client.go`'s `NewClient` never calls
`WithEnterpriseURLs` or otherwise overrides `BaseURL`, so go-github's own default
(`https://api.github.com/`, `github.go`'s `defaultBaseURL`) is the only host the REST
client ever targets; the GraphQL client shares the same underlying `http.Client`.
`internal/collect/azuredevops/client.go`'s `NewClient` builds its own `http.Client`
too, but only ever targets its four hardcoded `HostXxx` constants (`dev.azure.com`,
`vssps.dev.azure.com`, `advsec.dev.azure.com`, `auditservice.dev.azure.com`) — nothing
in that package accepts a caller-supplied host or reads one from the environment.
`git grep -rln 'http.Client\|net/http"' --include=*.go | grep -v _test | grep -v
internal/collect/github/ | grep -v internal/collect/azuredevops/` returns nothing — no
package in this codebase other than these two platform clients constructs an HTTP
client or makes a direct HTTP call.

**Signing egress is a distinct, opt-in exception, not a violation of this claim:**
`attestward scan --sign` and `attestward verify` (when a `.bundle` is present) shell out to
the `cosign` binary (`internal/integrity/sign.go`, `exec.CommandContext` — ADR-0006
records why cosign is invoked as a subprocess rather than vendored as a Go dependency).
Keyless cosign signing/verification itself talks to Sigstore's Fulcio (certificate
issuance) and Rekor (transparency log) over the network — real egress, but it is
`cosign`'s own, separately-trusted process making it, not attestward's Go code, and it
only happens when the user explicitly opts in via `--sign` or hands attestward a pack that
already carries a `.bundle` to verify. No scan without `--sign` ever triggers it.

### Tokens never persisted, logged, or included in evidence output

**Enforcement:**
- `internal/collect/github/transport.go`'s own doc comment on `provenanceTransport`:
  "the token lives only in this struct's field and the Authorization header of outgoing
  requests; it is never written to Provenance, never logged." `model.Provenance`
  (`internal/model/check_result.go`) has no field capable of holding a token — only
  `Endpoint`, `Method`, `Timestamp`, `HTTPStatus`, `ResponseSHA256`.
- `Endpoint` deliberately records the request path only (`req.URL.Path`, not the full
  URL) — a token or other secret accidentally placed in a query parameter can never
  reach an evidence pack through this field, by construction, not by later scrubbing.
- `cmd/attestward/scan.go` reads `GITHUB_TOKEN` from the environment only (never a CLI
  flag, which would appear in shell history/process listings) and never writes it
  anywhere.
- Defense in depth beyond the above: `internal/model/scrub.go`'s `secretPatterns`
  (GitHub token prefixes `ghp_`/`gho_`/`ghs_`/`ghr_`/`ghu_`/`github_pat_`, AWS access
  keys, PEM private-key blocks) redact any secret-shaped string found anywhere in a
  `Facts`/`Reason` value before the pack is serialized — `pack.Scrub()` in
  `runScan` and `model.ScrubBytes` again in `writeEvidencePack` (both in
  `cmd/attestward/scan.go`) as a last line of defense. Tested in
  `internal/model/scrub_test.go`.

**Azure DevOps (the v0.2 epic, issue #34):**
- `internal/collect/azuredevops/transport.go`'s `provenanceTransport` carries the
  identical guarantee, in its own doc comment: "the PAT lives only in this struct's
  field and the Authorization header of outgoing requests; it is never written to
  Provenance, never logged." Same `model.Provenance` type as the GitHub side, same
  field set — no field capable of holding a PAT here either. Authentication is HTTP
  Basic (`Authorization: Basic base64(":"+pat)`), not GitHub's Bearer token, but the
  handling is otherwise identical: injected at this one choke point, never elsewhere.
- `Endpoint` here records **host + path**, deliberately no query string or fragment —
  a real, deliberate divergence from the GitHub client's path-only `Endpoint`, needed
  because one ADO scan spreads across four hosts and a bare path (e.g.
  `/{org}/_apis/projects`) would be ambiguous about which one it went to. The same
  "a token can never reach evidence through this field" guarantee holds regardless,
  since neither the GitHub nor the Azure DevOps `Endpoint` ever carries a query string.
- `cmd/attestward/scan.go`'s `resolveScanToken` reads `AZURE_DEVOPS_EXT_PAT` from the
  environment only for `--platform azuredevops` — never a CLI flag, and `GITHUB_TOKEN`
  is deliberately never consulted on this path (nor is `AZURE_DEVOPS_EXT_PAT` consulted
  for a GitHub scan) — and never writes it anywhere.
- **Improved, not fully closed (issue #192):** `internal/model/scrub.go`'s
  `secretPatterns` now includes a pattern for the Azure DevOps PAT shape — the same
  distinctive, detectable shape a GitHub `ghp_`/`github_pat_` prefix has. Microsoft's own
  [PAT format
  reference](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate#pat-format)
  states "84 characters long" with a fixed `AZDO` signature "at positions 76-80" — five
  positions named for a four-character literal, so the source is self-inconsistent about
  the exact offset; the pattern matches both readings that reconcile to 84 total (76
  leading + `AZDO` + 4 trailing, or 75 + `AZDO` + 5), each anchored with a token boundary
  (`\b`) so it can't consume part of an unrelated, longer alphanumeric run. What remains
  unverified without a real token sample: the alphabet of the 80 non-signature
  characters, documented only as "randomized data" — the pattern assumes
  alphanumeric-only, which under-matches if the real alphabet includes other characters
  (e.g. `-`, `_`). `internal/model/scrub_test.go` covers both offset readings, the
  length/position near-misses the pattern must reject, and the token-boundary guard. As
  before, the primary enforcement above (PAT confined to the auth header, `Endpoint`
  never carrying one) is what actually prevents a PAT from reaching evidence in the
  normal path; this pattern is the second, defense-in-depth line for the case a future
  ADO collector bug ever put a raw PAT into a `Facts`/`Reason` value some other way, and
  it is meaningfully stronger than before #192 — but not a guaranteed catch for every
  real PAT given the unconfirmed alphabet.

### Digests, not payloads

**Enforcement:** `model.Provenance` (`internal/model/check_result.go`) has no field for
a raw response body — only `ResponseSHA256 string`, populated by
`provenanceTransport.RoundTrip` via `sha256.Sum256(body)` over the actual response bytes
before they're discarded. This is a compiler-enforced invariant (the struct has nowhere
to put a payload), not a runtime check that could be bypassed. Facts values extracted
from a response are separately size-capped: `internal/model/validate.go`'s
`MaxFactValueBytes = 65536` and `OversizedFacts`/`ValidateFactsSizes`, which
`writeEvidencePack` runs (as a warning, not a hard failure — see that function's own
doc comment for why an oversized-but-genuine finding shouldn't destroy a scan's
evidence) before every write.

## Mitigations table

| Risk | Mitigation | Where |
|---|---|---|
| Tool performs a write against the scanned platform | Transport-level GET/HEAD-only guard | `internal/collect/github/transport.go` + `internal/collect/azuredevops/transport.go`, both with their own `transport_test.go` |
| Token leaks into logs, evidence, or a URL fragment | Token confined to auth header; `Endpoint` records path only (GitHub) or host+path (Azure DevOps, no query string either way); no CLI-flag token intake | `internal/collect/github/transport.go`, `internal/collect/azuredevops/transport.go`, `cmd/attestward/scan.go` |
| A secret-shaped string reaches evidence some other way | Regex-based scrubber over every `Facts`/`Reason` value, applied twice (build time + write time) — GitHub token/AWS-key/Azure DevOps PAT (issue #192)/PEM shapes | `internal/model/scrub.go`, `scrub_test.go` |
| Evidence pack tampered after generation | SHA-256 pack hash always computed + `.sha256` sidecar; optional cosign signature | `internal/integrity/`, `cmd/attestward/scan.go` |
| A raw API response (possibly containing sensitive detail) ends up in evidence | `Provenance` structurally has no payload field, digest only | `internal/model/check_result.go` |
| An oversized Fact silently bloats/leaks via evidence | Size cap + validation warning | `internal/model/validate.go` |
| Injection via API-derived content into rendered reports | `html/template` auto-escaping, structural (report.html — every interpolated value, not opt-in per field); hand-written escaping (`mdescape.Escape`) neutralizing markdown/link-injection syntax before interpolation into report.md/poam.md — issue #222's review found two report.md.tmpl call sites (the Cluster Detail block's inline Repo mention and its Evidence line) that had been missed, since text/template has no auto-escaping and this project's own hostile-string fixture didn't reach them; fixed, and `internal/mdescape` gained its own test file so a regression there can't hide behind report.md's coverage again. Issue #231 found and fixed the same class one level up, in the pack-level header/Summary block neither #222's review nor its fixture (which only ever varied *per-result* content) reached: `Pack.Scope.Org` (report.md.tmpl and poam.md.tmpl), `Pack.ToolVersion`/`Pack.MappingVersions.*` (report.md.tmpl's Summary line), and the release-tag-pattern line — the last one a code-span variant of #222's exact lesson (CommonMark doesn't process backslash escapes inside a code span, so the fix drops the span rather than escaping inside it, matching poam.md.tmpl's already-correct digest-line shape); hostile-pack.json now plants a marker on every one of these. Not yet covered by this mitigation, found during #231's own sweep and deliberately not folded into that fix (each reshapes rendering/formatting rather than adding an `esc` call, so each needs its own scoped change): a `check_id` string reaching an unescaped code span for a result that cites no real SSDF task — report.md.tmpl's Gaps/Self-Attested/Not-Checkable blocks and poam.md.tmpl's Findings/Requires-Attention-Outside-This-Tool block all render one this way; a check_id that *does* match a real task is safe wherever it renders, because matching means the string is byte-identical to a trusted mapping-file ID and therefore carries no attacker-chosen characters at all — which is why the two blocks that render only matched IDs (Cluster Detail, and the Paired list, whose IDs come from the self-attestation mapping's own pairing field) are not affected by this gap; and an out-of-enum `status` value reaching `statusBadge`/`statusLabel`'s unescaped fallback branch, reachable via a `rollup` entry naming a real cluster/task ID or a result whose check_id matches a real check but whose status doesn't match any of the five defined values — `attestward report` renders third-party packs without ever calling `EvidencePack.ValidateAgainstSchema` or `Status.Valid`, so neither is actually enum-constrained against a hostile pack despite the schema declaring one | `internal/mdescape/mdescape.go`, `internal/report/templates/*.tmpl` |
| Supply-chain attack on the tool's own release artifacts | Pinned GitHub Actions (full SHA), minimal dependency tree, keyless cosign-signed releases | `.github/workflows/release.yaml`, `.goreleaser.yaml`, [ADR-0006](adr/0006-exec-cosign-not-sigstore-go.md) |
| Dependency confusion / typosquatting on install | Official release artifacts with checksums; documented install paths only | [SECURITY.md](../SECURITY.md), [README](../README.md) |
| Over-privileged tokens | README documents minimum permissions/scopes per collector, per platform; GitHub scans additionally warn on write scopes (best-effort, `HasWriteScope`) — no scope-introspection endpoint exists on Azure DevOps for the same warning there | `internal/collect/github/scopes.go`, README's token tables |

## Data flow

```
 ┌──────────────┐  GITHUB_TOKEN   ┌───────────────────────────────┐
 │ user/CI env  │ ───(env var)──▶ │ cmd/attestward (scan)         │
 └──────────────┘                 │  reads token; never persists  │
                                   └───────────────┬───────────────┘
                                                    │ Bearer auth header
                                                    │ (GET/HEAD only —
                                                    │  transport.go guard)
                                                    ▼
                                   ┌───────────────────────────────┐
                                   │ https://api.github.com        │
                                   │ (the only host attestward's   │
                                   │  Go code ever talks to)       │
                                   └───────────────┬───────────────┘
                                                    │ JSON response body
                                                    ▼
                                   ┌───────────────────────────────┐
                                   │ provenanceTransport            │
                                   │  sha256(body) → ResponseSHA256 │
                                   │  body itself discarded         │
                                   └───────────────┬───────────────┘
                                                    │ CheckResult{Facts, Reason, Provenance}
                                                    ▼
                                   ┌───────────────────────────────┐
                                   │ model.Scrub / ScrubBytes       │
                                   │  redact secret-shaped strings  │
                                   └───────────────┬───────────────┘
                                                    ▼
                          ┌─────────────────────────────────────────────┐
                          │ --out/ (user-chosen local directory)         │
                          │  evidence.json (+ .sha256 sidecar)           │
                          │  report.md / report.html / poam.md           │
                          │  evidence.json.bundle  (only if --sign)      │
                          └───────────────────┬───────────────────────┬─┘
                                               │                       │
                                (--sign only)  ▼                       │
                                   ┌───────────────────────┐           │
                                   │ cosign subprocess       │          │
                                   │  (separate trust        │          │
                                   │   boundary — ADR-0006)  │          │
                                   │  talks to Sigstore's    │          │
                                   │  Fulcio/Rekor over the  │          │
                                   │  network                │          │
                                   └─────────────────────────┘          │
                                                                        ▼
                                                          user decides distribution
                                                          (never sent anywhere by
                                                           attestward itself)
```

An `--platform azuredevops` scan follows the identical shape, substituting
`AZURE_DEVOPS_EXT_PAT` for `GITHUB_TOKEN`, HTTP Basic auth for a Bearer header, and
Azure DevOps's four hosts (`dev.azure.com`/`vssps.dev.azure.com`/
`advsec.dev.azure.com`/`auditservice.dev.azure.com`) for `api.github.com` — see
`docs/architecture.md`'s "Azure DevOps" section for the client-level detail this
diagram doesn't redraw per platform.

## Residual risks (documented, not hidden)

- **`not-checkable` can hide a real gap, not just an inconclusive one.** A plan-gated
  API, a token missing one scope, or a genuine platform limitation all surface as
  `not-checkable` identically — the tool is deliberately conservative (never asserts
  `verified-fail` from an ambiguous signal), but a reader must not treat a
  `not-checkable`-heavy report as equivalent to a clean scan. `report.md`'s own
  Methodology section (`internal/report/templates/report.md.tmpl`) states this; repeated
  here because it's a genuine limitation, not just a rendering note.
- **The tool cannot verify controls GitHub does not expose via API** (e.g., real MFA
  hardware type). Such checks are marked `partial` or `not-checkable`, never inferred.
  The same applies on Azure DevOps — e.g. `C01.org.2fa-required` is deliberately capped
  at `partial` even on a fully Entra-backed org, since MFA enforcement itself lives in
  Microsoft Entra Conditional Access, a surface no `vso.*` PAT scope reaches (epic #34
  open decision 3).
- **`internal/model/scrub.go`'s Azure DevOps PAT pattern doesn't verifiably cover every
  real PAT.** Issue #192 added a pattern for the documented 84-character/`AZDO`-signature
  shape (both offset readings the source's own inconsistent wording admits — see "Tokens
  never persisted..." above), but the alphabet of the other 80 characters is documented
  only as "randomized data," and the pattern assumes alphanumeric-only. If the real
  alphabet includes non-alphanumeric characters, a real PAT containing one would not
  match. As with the offset itself, this is unconfirmed without a real token sample —
  the primary enforcement (PAT confined to the Basic-auth header) is what actually keeps
  a PAT out of evidence in the normal path, so this residual gap is in the *second* line
  of defense only.
- **`exec`-ing `cosign` extends trust to that binary and the user's PATH resolution of
  it.** `cosignPath()` (`internal/integrity/sign.go`) uses `exec.LookPath("cosign")` —
  standard PATH-based resolution, the same trust model as any other CLI tool a user
  installs and invokes. A malicious or compromised `cosign` binary earlier on PATH than
  the legitimate one could substitute its own signing/verification behavior; mitigated
  only by the user installing cosign from the same trustworthy source they'd trust for
  any other security tool (see [SECURITY.md](../SECURITY.md)'s verification instructions
  for attestward's own releases, which face the identical bootstrapping problem — verify
  the tool that verifies things).
- **GitHub API truthfulness assumption.** Every `verified-pass`/`verified-fail` is only
  as honest as GitHub's own API response — attestward has no independent way to confirm
  GitHub isn't itself compromised, misconfigured, or serving stale/cached data. This is
  an accepted, unavoidable trust dependency of "verify via the platform API" as a
  strategy; the alternative (asking the producer, self-attestation) is *less* reliable,
  not more, which is the tool's whole premise.
- **A user with a tampered binary defeats pack signing.** Users should verify release
  signatures/checksums on install (see SECURITY.md) — the same bootstrapping caveat as
  the cosign-trust risk above.
- **Self-hosted CI/release infrastructure is a supply-chain trust dependency**
  (flagged during this finalization by independent review of PRs #84 and the
  self-hosted-runner migration commits; expanded here to cover this repo's now-larger
  self-hosted footprint):
  - **Release integrity rests on a persistent personal machine, not an ephemeral hosted
    VM.** `release.yaml`'s `goreleaser` job (which publishes real artifacts with
    `contents: write` and keyless-signs real checksums) runs on `spyros-mac-mini-ssdf`.
    If that machine were compromised during a release run, tampered binaries could get
    published *and* validly Sigstore-signed with the exact workflow identity
    [SECURITY.md](../SECURITY.md) tells consumers to verify — keyless signing attests
    which workflow signed, not that the build host itself was clean. A hosted runner
    gave every release a fresh, GitHub-managed build environment; that property doesn't
    hold for this specific job today. Mitigation (not yet done): move the release job
    specifically to a hosted or dedicated hardened runner before public launch — tracked
    on #138 (the v1.0 public-flip issue; DECISIONS.md D7).
  - **Shared, persistent runner state is not wiped between jobs or workflows.**
    `actions/checkout`'s default clean only resets the checked-out source tree — it
    doesn't touch `~/go/pkg/mod`, `~/Library/Caches/go-build`, or a runner's Go
    toolcache, all of which persist across every job/workflow sharing one physical
    machine. That's `spyros-mac-mini-ssdf` (every macOS-labeled job in this repo:
    `lint`, `test`, `checks-docs-drift`, `gomod-tidy-drift` (added with issue #249's
    drift guard — its own `go mod tidy` step is the clearest example of this
    paragraph's own point: it leans on this exact persistence to avoid a network
    fetch on every run, see that job's own comment), `examples-drift` (added with
    issue #228's drift guard), `rubric-drift-check` (added with issue #209's drift
    guard), `threat-model-drift` (issue #260's own drift guard, keeping this very
    enumeration current, including its own entry), `build`
    (cross-compiles every target platform — see `ci.yaml`'s own
    comment for why this replaced four separate per-arch runners), `goreleaser-dry-run`,
    the `release.yaml` `goreleaser` job, `integration-scan`,
    `integration-scan-ado` (added with issue #155's S9 harness),
    `sign-verify`, `self-scan`, `attach-to-release` (self-scan.yaml's own second job,
    attaches a scan's evidence pack to a matching GitHub release), `semgrep.yaml`'s
    own `semgrep` job, `runner-maintenance.yaml`'s own `clean` job (a weekly scheduled
    wipe of the Go build/module caches, added specifically to bound this risk), and
    the aorus `keepalive` job — `multi-arch-build-sample.yaml`'s own `build` job
    (a different job from ci.yaml's identically-named one above) lands here too, for
    its darwin/amd64 and darwin/arm64 legs, only when that `workflow_dispatch`-only
    workflow is manually run), `spyros-ionos-ssdf` (`test-linux`, and
    `multi-arch-build-sample.yaml`'s `build` again for its linux/amd64 leg),
    `spyros-parallels-ssdf` (`multi-arch-build-sample.yaml`'s `build`, linux/arm64
    leg), and `spyros-aorus-ssdf` — four machines, not
    one, each accumulating shared state across everything routed to it. The latter two
    (and `wake-aorus`/`build-windows`/`sleep-aorus` on `spyros-mac-mini-ssdf` and
    `spyros-aorus-ssdf` respectively) are idle unless `multi-arch-build-sample.yaml` (a
    non-required, `workflow_dispatch`-only reference pipeline) is manually run.
    Low-severity today (private repo, single collaborator with full access already has
    every capability this risk would grant), but a distinct mechanism from "an
    untrusted fork PR executes arbitrary code" (already covered on #138): even *trusted*
    code — a compromised upstream Go dependency, for instance — building once on a
    shared runner could in principle leave state a later job (one doing keyless
    signing, or one with `DEMO_ORG_PAT`/`AZURE_DEVOPS_EXT_PAT` in integration-scan.yaml)
    then trusts. Go's own
    module/build-cache content-addressing (go.sum-verified, hash-keyed) meaningfully
    bounds this relative to ecosystems with less integrity-checked caches, but it isn't
    zero. Mitigation options (isolate via ephemeral/containerized self-hosted runners,
    or periodic cache resets) belong in the same pre-public-launch bucket as #138's
    other self-hosted-runner items — not solved by anything in this document.

## See also

- [SECURITY.md](../SECURITY.md) — vulnerability reporting, release verification
- [README.md](../README.md)'s "Safety posture" section — the short, reader-facing summary
  of this document's claims
- `report.md`'s own "Methodology" section (`internal/report/templates/report.md.tmpl`,
  rendered fresh into every evidence pack) — per-scan status definitions and scope,
  generated alongside the evidence it describes rather than living only here
- [docs/checks-reference.md](checks-reference.md) — per-check API evidence and rubric,
  the check-by-check complement to this document's endpoint-by-endpoint enumeration
- [ADR-0004](adr/0004-read-only-local-first.md) — the read-only/local-first decision this
  entire document verifies the enforcement of
- [ADR-0006](adr/0006-exec-cosign-not-sigstore-go.md) — why cosign is shelled out to
  rather than vendored, and the trust implications that follow
