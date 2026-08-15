# ADR-0008: GitHub Enterprise Server is the `github` platform against a configurable host

**Status:** Accepted · **Date:** 2026-08-15

## Context

Issue #11's GHES epic asked for `attestward scan` to target a self-hosted GitHub
Enterprise Server (GHES) install, not just api.github.com — shipped as
`--github-url`/`github_url:`/`GITHUB_URL` in v1.2.0, with a v1.2.1 follow-up fix. Getting
there safely took four independent review rounds: three on the branch this was
originally developed on (`209e5cf`, `61e307c`, `028e706`, all dated 2026-08-03,
Refs #11/#12/#25), and a fourth (`c3268ce`) found while porting that branch onto this
repo's real, already-migrated history. Each round reproduced a real, working defect —
not a style nit — including a redirect that handed a third-party host a valid token, a
GHES pack asserting a github.com-only plan tier, and a routing fix that survived a full
revert with the test suite staying green. That last class of failure recurred three
times before the fourth round closed it for good, which is itself the most reusable
lesson here for any future collector work.

Four architectural questions came out of that process that are worth recording
independent of the code that answers them.

## Decision

### 1. GHES is a host, not a platform

GHES is not a fourth `collect.Collector` platform value alongside GitHub, GitLab, Azure
DevOps, and Gogs. It is the existing `"github"` platform pointed at a configurable host:
`cmd/attestward/scanconfig.go`'s `GitHubURL` field (`--github-url` / `github_url:` /
`GITHUB_URL`, in that precedence) feeds `internal/collect/github/hostconfig.go`'s
`ResolveHostConfig`, which derives a REST base (via go-github's own
`WithEnterpriseURLs`) and a GraphQL endpoint from it. An empty value is a no-op —
`api.github.com` unchanged, byte-for-byte, for every existing caller. Check IDs,
mappings, remediation text, and collector code are identical between github.com and
GHES; only the base URL, TLS trust (`GITHUB_CA_CERT`), and feature-availability gating
differ.

The alternative — a `--platform ghes` — would have duplicated every one of the eleven
`internal/collect/github/*` collector packages behind a second platform value for a
target that differs from github.com in host and licensing only, not in API shape or
check semantics. Modeling it as a host keeps ADR-0005's collector seam intact: the same
collectors, the same `Scope`, one extra piece of client configuration.

### 2. `Scope.IsGHES` is config-derived, never observation-derived

`internal/collect/github/hostinfo.go`'s `hostVersionTracker` observes the
`X-GitHub-Enterprise-Version` response header GHES sends on every API response and
github.com never sends — captured best-effort, latched only on a response that actually
carried it (an earlier version latched on the *first* response regardless, so one
headerless 502 from a load balancer, or a proxy stripping unknown `X-*` headers, pinned
the version empty for the whole scan). It would be tempting to derive "is this GHES"
from whether that header was ever seen. `internal/collect/collector.go`'s `Scope`
deliberately does not: `IsGHES` is set once, at preflight, from whether `--github-url`
was configured (`cmd/attestward/scan.go`: `IsGHES: cfg.GitHubURL != ""`); `GHESVersion`
is carried separately as whatever was actually learned, and can be empty on a genuine
GHES target.

The distinction is load-bearing, not pedantic. `GHESVersion` is empty both for
github.com and for a GHES install behind a proxy that strips the version header — a
collector that inferred "github.com" from an empty version would write a github.com
plan-tier reason into a pack whose own `scope.github_url` names a self-hosted install
with no plan tier at all. This was a real, shipped defect (round 1, `209e5cf`), and its
fix — keying `IsGHES` on the configured target — was itself reverted to a hardcoded
`false` in testing during round 2 (`61e307c`) with the suite staying green, because
nothing yet asserted the value came from configuration rather than a constant.
`cmd/attestward/scan_test.go`'s `TestRunScan_IsGHESComesFromTheConfiguredTarget` now
pins exactly that, and its own doc comment says why: this is the single most
load-bearing line in the whole feature.

### 3. Gate classification: one shared helper for the common case, one deliberate exception

A gated response (`IsPlanGated`'s 402/404) means something different on each host:
github.com has a plan tier that can exclude a feature; GHES has none, so the same status
there means the feature is not licensed for the install, the installed version predates
the endpoint, or the token lacks scope — GitHub returns the same status for all three,
and `internal/collect/github/gatekind.go`'s `ClassifyGate`/`GateReason` render that
ambiguity honestly rather than guessing a cause. `GatedRepoReason`, built on top of
them, is the one place a repo-scoped gate becomes prose, used directly by seven
collector packages (`actionssecurity`, `envseparation`, `vdp`, `sasthistory`,
`scahistory`, `provenance`, `repoprotection`); `ClassifyGate`/`GateReason` are also
called directly, without that wrapper, by two more checks that need endpoint-specific
wording for a single, cleanly status-code-gated call — `auditlogging`'s org audit-log
probe and `sasthistory`'s CodeQL default-setup probe (wired in as of issue #12's audit,
because these were the two checks the epic could verify a genuinely single, reliable
gate signal for).

`secretshygiene` (C04, GHAS-related checks) is the deliberate exception: its gate
signal is a boolean field in a repo response (`security_and_analysis.*.status`), not an
HTTP status code, and GHES additionally has no free public-repository tier for secret
scanning the way github.com does — a fact the shared status-code helper has no way to
encode. It carries its own GHES-aware logic (`evalGHASGatedFeature`,
`advancedSecurityPublicRepoReason`, `securityAndAnalysisAbsentReason`) rather than being
forced through `ClassifyGate`. `checkDependabotAlerts`, in the same package, is a v1.2.1
follow-up (issue #26) for the identical defect class found by a post-release audit of
v1.2.0: a 404 from the alerts endpoint is unambiguous on github.com (feature genuinely
off) but also fires on GHES when GitHub Connect isn't syncing the advisory database,
which the endpoint cannot distinguish from alerts being off — now `not-checkable` on
GHES for that case, while an observed "enabled" still passes on either host.

The reason a *shared helper alone* was not sufficient: round 1 fixed the helper and one
call site; round 2's audit found the other six of seven `GatedRepoReason` sites still
said "plan-gated" on installs that have no plan tier, because the earlier fix guarded
the helper's own logic, not whether any given site actually called it correctly. Round 3
found an eighth unrouted site (`secretshygiene`, producing a wrong *status*, not just
wrong prose — a false verified-fail). Round 4, found while porting onto this repo's
history, discovered that every one of those nine sites' own routing was still
*unguarded*: a unit test on the shared helper proved the helper was correct in
isolation, but reverting all nine call sites back to their github.com-only branch
simultaneously left the full suite green — the identical failure mode as round 2, just
spread across more sites than round 3's guard covered. **Any future change that touches
gate classification at a new or existing call site must add an end-to-end test at that
call site — driving a real `Collect()` call through the actual gated condition, not just
a unit test on the shared helper — and must be verified by hand-reverting the change and
confirming that specific test fails.** This is the same "mutation-tested" discipline
`docs/threat-model.md` already applies elsewhere in this codebase; it is now a hard
requirement for this call-site pattern specifically, because the shared-helper-only test
already failed to catch the defect twice.

### 4. Redirect policy is host-scoped for GitHub, refuse-all for Gogs — deliberately different

`internal/collect/github/client.go`'s `sameHostRedirectPolicy` follows a redirect only
while it stays on the same host and scheme as the configured target, and refuses
anything else. It exists because making `--github-url` user-supplied made the GitHub
client reachable to a defect first found and fixed in
`internal/collect/gogs/client.go`: a redirect followed with auth injected below the
redirect machinery hands a third-party host a valid token, silently, with a
verified-pass in the resulting pack (reproduced and fixed in round 1, `209e5cf`).

Gogs's client refuses *every* redirect unconditionally
(`CheckRedirect: func(...) error { return http.ErrUseLastResponse }`) — a redirecting
Gogs instance surfaces as a status error a collector branches on like any other non-2xx.
GitHub's client is host-scoped instead, following a same-host hop and refusing only a
cross-host one or a same-host https→http downgrade. This is not an inconsistency
between the two platform packages; it reflects a real difference between the two APIs.
GitHub documents a 301 for a renamed repository or organization, which `net/http`
followed transparently before this fix — refusing every redirect there, the Gogs
approach, would have been a regression for every existing github.com user naming a repo
by its old name. Gogs has no equivalent legitimate rename-redirect semantics to
preserve, so refuse-all costs it nothing. The token-leak fix is the same in both places
(never re-send the token to a host the scan did not target, and never downgrade to
plaintext); the amount of legitimate redirect traffic each platform actually has is
what differs.

## Consequences

- Onboarding GHES cost zero new platform surface: no new `Collector` implementations, no
  new `Scope` shape beyond two additive fields (`IsGHES`, `GHESVersion`), no changes to
  `internal/model` or `internal/mapping`. A future self-hosted GitLab or Azure DevOps
  Server story, if one is ever needed, has this ADR as precedent for "host, not
  platform" — but that is a decision for its own ADR, not an automatic extension of this
  one.
- `Scope.IsGHES` is now the only field any collector may use to ask "does this target
  have a github.com plan tier" — `GHESVersion` being empty must never be read as "this
  is github.com." `docs/architecture.md`'s GHES section and this ADR are the record of
  why; a future refactor that "simplifies" by deriving `IsGHES` from the version header
  would reintroduce the exact defect round 1 fixed.
- Every collector that reaches a gated (402/404) response must route through
  `GatedRepoReason` (or, for a single verifiably-status-code-gated endpoint,
  `ClassifyGate`/`GateReason` directly) and ship a call-site-level end-to-end test,
  mutation-verified by hand-reverting it — a shared-helper-only test is accepted as
  insufficient going forward, not just for this feature.
- `secretshygiene`'s GHAS checks and its `checkDependabotAlerts` are documented,
  intentional exceptions to the shared gate-classification path, not gaps to be
  "cleaned up" into it — their gate signal is not a single HTTP status code, and forcing
  them through `ClassifyGate` would require inventing a status-code shape that does not
  exist.
- **This is not verified against a real GHES install.** There is no GHES instance in
  this project's CI or test infrastructure; every scenario referenced above (routing,
  gating, redirect policy, the per-check `GHESNote` audit) is proven with
  `httptest`/`ghfixture` fixtures and mutation-verified unit/end-to-end tests standing in
  for a live GHES host, never a real one. `README.md`'s GHES section and
  `docs/architecture.md`'s GHES section both state this plainly rather than let "GHES
  support" be read as "exercised against GitHub's own GHES software." The only thing
  that would change this is running a real scan against an actual GHES install and
  reconciling any divergence found — most usefully the version-gating branch
  (`GateKindVersion`), which is currently unreachable because no check yet carries a
  verified minimum-version fact (issue #13), and the per-check `GHESNoteUnverified`
  entries in `docs/checks-reference.md`, which exist specifically because nobody has
  confirmed those endpoints' GHES behavior yet.
