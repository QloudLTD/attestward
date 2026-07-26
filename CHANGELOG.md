# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).

## [Unreleased]

### Added

- **`trivy` gains Azure Pipelines `ado_tasks` detection, and every other signature now
  records an explicit ADO-task decision** (#238, #243). #238: trivy had no `ado_tasks`
  entry at all despite Aqua Security publishing an official marketplace task
  (`AquaSecurityOfficial.trivy-official`, `- task: trivy@2`/legacy `trivy@1`) — an ADO
  pipeline using it as a task rather than a script step matched nothing, a false-negative
  SCA finding in a signed evidence pack. Fixed with a new `ado_tasks` entry (major left
  unpinned, matching `sonarqube`'s own multi-concurrent-majors precedent — both `@1` and
  `@2` remain in real-world use) and a new fixture, `trivy-task.yaml`, alongside the
  existing CLI-script fixture. #243: auditing why trivy was missed found it wasn't
  isolated — only 4 of the registry's 14 signatures carried any ADO detection at all
  (5 and 9, respectively, after this PR — none with neither). Every other signature now
  carries an explicit `no_ado_task` reason: structural absences
  (`dependency-review-action`, `dependabot`, `slsa-generator`, `attest-build-provenance`
  — GitHub-native by construction, no ADO equivalent mechanism exists to register a task
  against) and dated checked negatives (`semgrep`, `grype`, `osv-scanner`, `cosign`,
  `syft` — the Marketplace was searched and nothing found). `grype`'s investigation
  started from a real lead noted during #234's review (Anchore's own
  `AnchoreInc.anchore-scan-task`) that turned out not to apply on inspection: it wraps
  the deprecated Anchore Engine, not Grype, and has since been unpublished from the
  Marketplace entirely — a proof case for why every `ado_tasks` entry in this registry
  stays vendor-published-only: a third-party/deprecated wrapper can be unpublished
  outright, leaving a signature pinned to it as dead weight inside signed packs.
  `semgrep`'s own gap is partial, not total like trivy's: a third-party task exists
  (an unrelated individual's, not Semgrep Inc.'s, so it doesn't meet the
  vendor-published bar above) but a step invoking it still matches at low confidence
  via `workflow_name_patterns`' `displayName:` fallback whenever that displayName
  mentions "semgrep" — trivy had no such fallback (`workflow_name_patterns: []`),
  which is exactly what made its own gap total and #238 urgent. A new registry-level
  test, `TestEveryScannerSignatureHasADOTasksOrAnExplicitAbsenceMarker`, asserts every
  signature has either `ado_tasks` or a non-empty `no_ado_task` reason that also isn't
  itself a YAML 1.1 boolean (`true`/`false`/`yes`/`no`/`on`/`off`/`y`/`n`/`1`/`0`,
  case-insensitive) — `yaml.v3` decodes an untagged `no_ado_task: true` into the Go
  string `"true"` regardless of the scalar's own semantic type (only
  `true`/`false`/`True`/... actually resolve as `!!bool`; the rest resolve as `!!str`
  or `!!int`), which a bare non-empty check alone would have accepted as a real
  decision (found in review) — so a future signature can't silently ship GitHub-only
  again the way this whole class of gap arose in the first place.

- **`syft` (SBOM generation) added to the scanner-signature registry, in a new `sbom`
  category** (#166). Epic #34/story #149's own text assumed syft already had an entry
  among the CLI-driven tools (trivy/cosign/syft/osv-scanner) — it never did; the only
  prior mention anywhere was a code comment. The registry had no `sbom` category at all
  (only `sast`/`sca`/`container`/`secrets`/`provenance` had entries), and filing syft
  under `provenance` was rejected: an SBOM attests a build's *composition*, not its
  *origin*, and conflating the two would be a real, compounding inaccuracy baked into
  every report that detects it. `mappings/scanner-signatures.yaml`'s header comment now
  defines what an `sbom` match asserts and — just as importantly — what it does not
  (generating an SBOM is not scanning it, signing it, or evidence anything downstream
  acted on it). Detects `anchore/sbom-action` (high confidence) and a direct `syft` CLI
  invocation with an explicit `-o`/`--output` flag (medium confidence) — the flag
  requirement is deliberate: syft's own default output is a human-readable table, not a
  machine-readable SBOM, so a bare `syft` mention (a comment, or the install
  one-liner's own URL) doesn't false-positive as a real invocation. Fixture-backed on
  both platforms (`internal/mapping/testdata/workflows/syft.yaml`,
  `testdata/pipelines/syft.yaml` — cosign/osv-scanner/syft genuinely have no ADO
  marketplace task, so all three are cross-platform run_patterns only). Audited
  trivy/cosign/osv-scanner while here, per the same story text: cosign and osv-scanner
  are correctly and completely registered, with real fixtures on both platforms already.
  Trivy's own audit turned up a real, separate gap instead of a clean bill of health —
  Aqua Security publishes an official Azure Pipelines marketplace task
  (`AquaSecurityOfficial.trivy-official`, `- task: trivy@2`, `trivy@1` legacy) this
  registry has no `ado_tasks:` entry for, so an ADO pipeline whose only SCA step is that
  task currently matches nothing — a real false-negative in C06, the same shape of gap
  #167 fixed for SonarCloud. Not fixed here — tracked as #238, its own fixture, its own
  focused change;
  syft was the one category-level gap this issue set out to close.

- **`make examples`/`make examples-check` guard `examples/demo-org-pack` against
  renderer drift** (#228). Nothing regenerated or checked the pack's rendered
  `report.md`/`report.html`/`poam.md` against its own `evidence.json` — it drifted
  silently for two releases (`report.html` still read `size: auto;` after #200 changed
  the template to `size: Letter;`) — undetected because nothing in the repo's own
  tooling checked it, and it mattered more than ordinary stale-sample drift would
  because `README.md` points cold visitors at this exact pack, the one rendered
  artifact in the repo. Mirrors
  `checks-docs`/`checks-docs-check`'s existing shape: `make examples` re-renders in
  place, `make examples-check` (`hack/check-examples-drift.sh`) regenerates into a
  scratch directory and diffs, wired into CI as `examples-drift` alongside
  `checks-docs-drift`. Confirmed empirically before building this — not assumed — that
  re-rendering the same `evidence.json` is byte-stable (three independent renders
  produced identical SHA-256 sums for all three files), so a plain diff is sound with no
  deterministic-render mode needed. This change's own regeneration closes the current
  `size: auto;` drift as a side effect of proving the guard works.

  Review found the render-diff alone covers only one of three ways this pack can go
  stale, so three more checks were added, each running before the render-diff and each
  with its own message (a generic "run `make examples`" would be actively wrong for the
  first two): **mapping-version currency** — a `mappings/*.yaml` version bump since the
  pack was captured makes re-rendering bake a mapping-version-mismatch banner into all
  three files instead of fixing anything, since that needs a live re-scan, not a
  re-render; **check-ID coverage** — a check added to the registry doesn't change
  rendered output at all if `evidence.json` never gained a result for it, so the
  render-diff alone would stay green while the showcase silently under-reports what
  attestward actually checks (the pack's 52 check IDs matching the current registry's
  full GitHub + self-attestation set exactly was a one-time manual check, now enforced
  every run); and **sidecar presence** — a missing `evidence.json.sha256` passes the
  render-diff silently while breaking the `attestward verify` walkthrough
  `examples/README.md` documents. The render-diff itself also moved from a hardcoded
  `report.md`/`report.html`/`poam.md` loop to `diff -r` excluding `evidence.json*`, so a
  future output format isn't silently ignored the same way `report.html` itself was.
- **`model.Scrub` redacts Azure DevOps PAT-shaped secrets** (#192): the defense-in-depth
  secret scrubber previously covered GitHub token prefixes, AWS access keys, and PEM
  blocks only. It now also matches the documented Azure DevOps PAT shape (84 characters
  total, fixed `AZDO` signature — both offset readings Microsoft's own self-inconsistent
  PAT format reference admits, boundary-anchored to avoid matching inside a longer benign
  alphanumeric run). Meaningfully narrows the gap `docs/threat-model.md` had flagged as
  an open residual risk; the exact character alphabet of the non-signature portion
  remains unverified without a real token sample, so the risk entry is updated, not
  removed.
- **CI guard: `tools/rubricguard` catches a status-assignment change with an untouched
  `checkRubrics` entry** (#209). `make checks-docs-check` only compares
  `docs/checks-reference.md` against its rubric *source*; it has no opinion on whether a
  rubric matches the collector's own status-assignment logic, so a check could start
  producing a status its published rubric never describes and nothing would catch it —
  exactly what #202's review round 1 found by chance, and #203 (same batch, same class
  of change) avoided only because it happened to update its rubric in the same commit.
  `rubric-drift-check` (wired into `ci.yaml`, same PRs `checks-docs-drift` already
  gates) AST-parses each internal/collect/** package touched by a diff and flags one
  whose non-test `.go` files gained a changed `model.Status*` value reference while its
  `checkRubrics` var went untouched in the same diff — deliberately coarse (a reviewer
  can wave off a false positive; silence is what #202 hit), verified against this
  repo's own history: correctly silent across 40 real merged PRs, and correctly flags
  #202's actual pre-fix commit (all three collectors it originally missed).

### Fixed

- **`multi-arch-build-sample.yaml`'s uploads no longer inherit the 90-day retention
  default** (#242). Its two `upload-artifact` steps set no `retention-days` at all, so
  both fell back to the repo default of 90 days — 15 live artifacts totalling ~128 MB,
  expiring 2026-10-17, from a `workflow_dispatch`-only reference pipeline nothing
  consumes. Under the GB-hours-across-the-month billing #217 documents, that is close
  to the worst possible shape: small enough not to look alarming in a size listing,
  long-lived enough to dominate the accrual. Both now set `retention-days: 1`, matching
  what #241 did for `attestward-builds` — these binaries demonstrate that the pattern
  still builds, they aren't an input anything downstream reads. Retention applies at
  upload time, so the 15 existing artifacts are unaffected and still expire on their
  own; deleting them early is a separate, deliberate decision. With this, no
  `upload-artifact` step in the repo is left unguarded.
- **`github.sha` no longer interpolated directly into `run:` blocks** (#232). Three
  sites — `ci.yaml`'s `build` job and both of `multi-arch-build-sample.yaml`'s legs —
  used `${{ github.sha }}` straight inside a `run:` script, against this repo's own
  rule that context expressions route through `env:` instead. Not a live
  vulnerability (`github.sha` is a GitHub-generated hex SHA, not attacker-influenceable
  the way `github.event.issue.title` or `head_commit.message` are), but the rule's
  whole value is that it needs no per-site risk judgement, and three standing
  exceptions meant a fourth wouldn't have stood out. Fixed with the ambient
  `$GITHUB_SHA` environment variable at all three sites rather than adding `env:`
  plumbing — GitHub exports it into every step automatically, it's a genuine runtime
  variable the shell reads rather than a context expression textually substituted
  into the script beforehand, and this repo already uses the identical pattern for
  `$GITHUB_REPOSITORY` (`self-scan.yaml`, `hack/fetch-drift-baseline.sh`). Confirmed
  the built binary still reports the right commit rather than an empty string (a
  broken `-X` fails silently) by building locally with `$GITHUB_SHA` set the way CI
  sets it.
- **C05.sast (Azure DevOps): three pre-existing "status correct, prose/Facts wrong"
  defects, all in `sasthistory`** (#246, #248, #252). Same class as #226/#235/#236/#244
  — the status logic was already right, but what the code said about itself wasn't:
  - `checkCadence`'s Reason asserted "no SAST tool is configured" on a failed
    repo-enablement query, right next to `tool-configured`'s own "the cause is
    unconfirmed" for the identical evidence gap — the prose analogue of the
    status-level contradiction #235 fixed. Now reuses `advSecNotCheckableReason`'s
    existing shape and reserves "no SAST tool is configured" for the case where the
    query actually succeeded and reported the tool off. Swept the other three checks
    in the package for the same shape — `checkToolConfigured`, `checkRanPerRelease`,
    and `checkDefaultSetup` all already gate their prose on `enablementErr` correctly;
    `checkCadence` was the only holdout (#246).
  - `tool-configured`'s verified-fail rubric claimed the state was "directly observed,
    not inferred from an error response" — stronger than the code guarantees: a 200
    whose body omits `codeQLEnabled` or the whole `codeSecurityFeatures` block decodes
    to `false` via Go's zero-value fallback, identically to an explicit `false` or
    `null`, so verified-fail is reachable from a defaulted collapse too. Brought up to
    the precise wording #251 already gave C06's identical rubric (#248). Folded in while
    here: `checkCadence`'s own not-checkable rubric had the same "ambiguous whether
    not-configured includes query-failure" imprecision — recreating, one function over,
    the exact asymmetry #248 exists to close — so it's brought up to the same wording
    too, distinguishing a query that succeeded and read `codeQLEnabled` false from one
    that failed outright. Review found a second round of the same asymmetry in that
    first fold-in: the query-failure case was nested *underneath* the "no SAST tool is
    configured at all" heading rather than its own sibling clause, the same subsumption
    `tool-configured`'s own rubric never does for its identical case — promoted to a
    top-level "or" instead. Also completed `checkCadence`'s Reason for that same branch,
    which — unlike its two siblings ("cadence can only be computed from…" / "cadence
    cannot be computed") — never said what the gap meant for cadence specifically, a
    side effect of copying `checkToolConfigured`'s own sentence verbatim.
  - `checkRanPerRelease`'s `defaultSetupOnly` branch attached `Facts` only when
    `sameRepoSkips` was non-empty, so default setup on plus dropped-but-undateable
    release tags returned not-checkable with the dropped-tag record silently gone —
    fixed for that branch, matching the "`dropped_tags` on every return path"
    convention #250 established (#252). Review found a second, identically-shaped
    holdout in the same function's `buildsErr` branch — reachable with a
    signature-matched pipeline, one dateable release, one undateable tag, and a failed
    build-history fetch — fixed the same way.

- **report.md/poam.md's pack-level scope/version fields are now escaped** (#231). Found
  by the confirmation pass on #222, which fixed the *per-result* instances of this same
  bug — these are the *pack-level* ones, outside that PR's scope: `Pack.Scope.Org`
  (report.md.tmpl and poam.md.tmpl), `Pack.ToolVersion`/`Pack.MappingVersions.*`
  (report.md.tmpl's Summary line), and the release-tag-pattern line, which was inside an
  unescaped **code span** — the same trap #222 hit: CommonMark doesn't process backslash
  escapes inside a code span, so the fix drops the span and escapes as plain text instead
  of escaping inside it, matching poam.md.tmpl's already-correct digest-line shape. All
  four are reachable because `docs/schema/evidence-pack.v1.schema.json` declares them as
  unconstrained strings and `attestward report` renders third-party packs
  (`--help`: "rendering a pack received from someone else") without calling
  `EvidencePack.ValidateAgainstSchema`. `hostile-pack.json` now plants a marker on all
  four; report.html was never affected (`html/template` auto-escapes structurally).
  Swept both markdown templates for every remaining `{{` interpolation while here: two
  further gaps of the same shape were found and are tracked as follow-ups rather than
  folded into this fix, since both reshape rendering logic rather than adding an `esc`
  call — an unmapped result's `check_id` reaching an unescaped code span (Gaps,
  Self-Attested, Not-Checkable, and poam.md's equivalents), and an out-of-enum `status`
  value reaching `statusBadge`/`statusLabel`'s unescaped fallback branch (`Status.Valid`
  is defined but never called on the `attestward report` path either). See
  `docs/threat-model.md`'s injection-mitigation row for the full account.
- **C05.sast.tool-configured (Azure DevOps): stop letting an unconfirmed 404 justify a
  verified-fail** (#226). A repo-enablement 404 with
  no other pipeline evidence used to fall through to the same pass/fail logic as a real
  success, treating "the query failed with a 404" as equivalent to "the query
  succeeded and confirmed the tool is off" — grounded in the belief that 404 meant
  GHAzDO wasn't licensed, which #190's S9 live run falsified: an unlicensed org/project
  reads HTTP 200 with every flag false/null, never 404. #225 honestly downgraded the
  doc comment to call this "a deliberate policy choice, not a confirmed fact", but left
  the verdict resting on it — a licensed org with CodeQL default setup genuinely on
  could get a false `verified-fail` ("no SAST tool detected") the moment this
  endpoint's pinned `api-version=7.2-preview.3` is retired or returns a 404 for any
  other reason, in a signed pack backing an SSDA form. Fixed by narrowing
  `verified-fail` to the one directly observable, structured signal — the enablement
  query succeeded (no error) and its response itself says `codeQLEnabled: false` — and
  routing every enablement error, 404 included, to `not-checkable`, matching sibling
  `C05.sast.default-setup`'s existing any-error-is-not-checkable treatment exactly. No
  signal is lost for a genuinely-off org: that state was always observable as this same
  HTTP-200-false response, proven by a pre-existing test unaffected by this change. The
  now-unused `isAdvSecNotFoundErr` predicate is removed rather than left orphaned.
- **C06.sca.tool-configured and C06.sca.ran-per-release (Azure DevOps): stop letting an
  unconfirmed 404 justify a verified-fail** (#236, #244). The same defect #226 fixed in
  C05 existed twice over in C06: `tool-configured` special-cased a 404 as confirmed-off
  and fell through to normal pass/fail logic, and `ran-per-release`'s own
  zero-matched-pipelines guard checked only `len(sameRepoSkips) > 0`, never the
  repo-enablement query's own error — so a 404 with zero matched pipelines and no
  same-repo skip still reached the same confirmed-verdict logic as a real absence.
  Fixing only one of the two (as an earlier version of this change did, in the PR that
  became this one and #235) left C06 internally contradictory in exactly the way this
  fix exists to prevent: `tool-configured` reading not-checkable next to
  `ran-per-release` reading verified-fail for the identical evidence gap. Both checks
  now require the enablement query to have succeeded before asserting any confirmed
  pass/fail, routing every enablement error — 404 included — to not-checkable, mirroring
  #226/#235's identical fix in C05 exactly. `ran-per-release`'s combined guard also
  preserves `Facts.dropped_tags` unconditionally rather than only when a same-repo skip
  is also present, closing a Facts-loss gap review found in this same guard shape in C05.
- **C05.sast.ran-per-release: the sibling gap #226 didn't reach** (#235). #226 fixed
  `C05.sast.tool-configured` to go `not-checkable` on any repo-enablement error, but
  never touched `checkRanPerRelease`, which reads the identical enablement result via
  its own `defaultSetupOnly` guard (`enablementErr == nil` required). So the exact
  scenario #226 fixed for `tool-configured` left `ran-per-release` disagreeing: a 404,
  zero matched pipelines, no same-repo skip fell through to the normal coverage
  computation and reported `verified-fail` — "we can't tell whether SAST is
  configured" next to "SAST did not run for this release", in one signed pack, the
  exact "two panels of one pack, opposite claims" contradiction #202 already fixed for
  the same-repo-skip case. Extended the guard to also fire on an enablement-query
  failure, not just a same-repo pipeline skip, with a Reason naming whichever cause(s)
  apply (they're causally independent and can co-occur). Pinned at both the unit level
  and the full-`Collect` level — extended #226's own 404 regression test to also
  assert `ran-per-release`, proving the two checks no longer disagree for the same
  repo. Also fixed, found in independent review: the combined guard could silently
  drop a repo's `dropped_tags` Facts when an enablement-query failure and dropped,
  undateable release tags applied at once — `dropped_tags` is now always included,
  matching the convention the check's own later branch already uses.
- **Report/POA&M renderers no longer mislabel Azure DevOps project-scoped results as
  org-level** (#176). `report.md`/`report.html`'s Gaps and Not Checkable tables, and
  `poam.md`'s Findings section, rendered every result with an empty `Scope.Repo` as
  `(org)`/`(org-level)` — correct for a genuinely org-scoped result, factually wrong
  for an Azure DevOps project-scoped one (e.g. C03 env-separation, C08
  pipeline-security), which also has `Scope.Repo` empty; `Scope.Project` can't
  disambiguate the two either, since the orchestrator stamps it onto every result from
  an ADO scan regardless of the check's own scope level. Scope level is now classified
  via a new `CheckMeta.ScopeLevel` field, set explicitly only for the checks that are
  project-scoped, rather than inferred from `(Repo, Project)` presence at each render
  site. The pack-header scope table and `poam.md`'s Summary now also surface
  `Scope.Project` when present, which neither did before.
- **self-scan.yaml: drift detection actually runs on a release now** (#211). Its
  `on: release: types: [published]` trigger never fired for any of this repo's real
  releases — `release.yaml` creates every release with the ambient `GITHUB_TOKEN`, and
  GitHub deliberately doesn't cascade GITHUB_TOKEN-authenticated events into new
  workflow runs. Switched to `workflow_run` on the `Release` workflow's completion,
  which isn't subject to that restriction. Separately, a missing baseline (the latest
  release has no `evidence.json` attached) used to fail open silently and look
  identical to a genuine first run either way; the two are now distinguished — an
  older release carrying the asset while the latest doesn't is a broken chain, loudly
  annotated (`::error::`) and worked around by falling back to that older release's
  pack, *except* on the one release-triggered run where that's actually expected (the
  just-published release's own pack isn't attached until later in the same run) — that
  case falls back quietly instead of alarming on every single release, forever.
  `gh` itself failing (rate limit, transient 5xx) is now distinguished from the asset
  genuinely being absent too, rather than the two looking identical to a fallback scan
  and silently reproducing the same defect through a different door. "Latest" is now
  resolved the same way on both the read and write side (previously the write side
  could target a prerelease the read side's `isLatest` filter would never see again).
  The baseline-fetch logic moved to `hack/fetch-drift-baseline.sh` so all of the above
  is testable against a mocked `gh` (`fetch-drift-baseline_test.sh`, wired into
  `ci.yaml`) without a real release.
- **The artifact storage quota exhausted outright, and `continue-on-error` made it
  completely invisible** (#217). 10.82 GB across 1362 artifacts at discovery — 5.69 GB
  of it pre-rename `attestor-*` debris no workflow references any more (deleted with
  the owner's approval), the rest almost entirely `ci.yaml`'s `attestward-builds`: five
  ~18 MB binaries uploaded on every PR *and every push to an open PR's branch*, not
  just once per PR. That upload now only runs on `push` events (a merge or direct push
  to `main`) — the `build` job's compile-and-execute proof, which is the actual point
  of the job, still runs unconditionally on every PR. Every `continue-on-error`-guarded
  artifact upload across `ci.yaml`, `self-scan.yaml`, and `multi-arch-build-sample.yaml`
  now emits a `::warning::` annotation on a genuine failure (checked via the upload
  step's own `outcome`, which `continue-on-error` doesn't mask) — silent before, now
  noticeable without reddening a build that otherwise passed. This was the second,
  independent layer at which the drift baseline chain #211 fixes could still break
  silently: on a release run, a quota-exhausted upload means `attach-to-release` has
  nothing to download, same outcome as #211's own original defect, arrived at from a
  different direction.
  Deleting that 10.82 GB did *not* restore capacity, and neither did deleting a further
  801 MB two days later (account down to ~428 MB) — the error's own "usage is
  recalculated every 6-12 hours" never came true across either. Two facts explain why.
  The quota is billed against the whole **account** (500 MB on Free, 1 GB on Pro; the
  plan isn't verifiable from CI), not per repo, so every per-repo cleanup was aimed at
  the wrong denominator. And the meter is **accrual, not a byte cap**: GitHub bills
  artifact storage in GB-*hours* accumulated across the billing month, and deleting
  bytes does not un-accrue hours already charged. The tell is that this was a cutover
  rather than a slope — uploads were succeeding while the account held 10.82 GB and
  stopped dead on 2026-07-24 (last success 13:51:11Z), which an instantaneous 500 MB cap
  could never have allowed. On that reading the cycle's allowance is simply spent and
  uploads stay blocked until it resets, no matter how much more is deleted. Recorded as
  **unconfirmed**: the test is whether uploads resume at the cycle boundary with no
  further cleanup.
  `retention-days` on that upload drops 7 → 1, which is the right lever precisely
  *because* the cost is bytes × hours — cutting hours 7× cuts the bill 7×. But this
  buys time rather than fixing the budget: at this repo's measured ~10 merges/day
  (30-day median; 30 on the heaviest day) even 1-day retention leaves ~445 MB standing
  from this artifact alone, before `attestward-cloud` (~239 MB) is counted. A ~44 MB
  bundle of five binaries per `main` push, held a week, was the single largest
  contributor and starves `self-scan.yaml`'s evidence-pack upload — the one
  artifact here with real downstream value (#36's drift baseline). Any future increase
  should start from an account-wide measurement, not a per-repo one.
  `multi-arch-build-sample.yaml`'s two `upload-artifact` steps (#242) had the
  identical gap and are now the same 1 day: no `retention-days` at all meant the
  90-day repo default, close to the worst possible shape under the accrual model —
  128 MB standing for three months from a `workflow_dispatch`-only reference
  workflow nothing consumes, small enough not to look alarming in a size listing,
  long enough-lived to dominate the accrual regardless. The 15 existing artifacts this
  produced (2026-07-19, confirmed still live at 127.9 MB total) aren't deleted by this
  change — only new uploads get the shorter retention — and deleting them is a
  decision for the repo owner, not this PR.
- **C05 sast-history / C06 sca-history: a workflow/pipeline this tool couldn't fully
  inspect no longer reads as a confirmed absence** (#178). A workflow (GitHub) or
  pipeline (Azure DevOps) that failed to fetch, decode, or parse was silently dropped
  rather than counted as evidence-gathering failure — a repo whose only SAST/SCA
  mechanism happened to be that one unreadable workflow read `verified-fail` ("no tool
  detected") instead of an honest `not-checkable`. Fixed on both platforms: skips are
  now surfaced in each affected check's `tool-configured` **and `ran-per-release`**
  Facts (name/path + reason per entry), and cap both checks at `not-checkable` instead
  of `verified-fail` when a same-repo skip exists and no other evidence resolved it —
  the two checks previously disagreed with each other over the identical evidence.
  Every affected check's status rubric (and the generated `docs/checks-reference.md`)
  is updated to describe the new not-checkable case. GitHub C07 provenance and three
  other `ran-per-release`-style checks had the identical, pre-existing gap, out of
  scope for this fix — see #207.
- **C05 sast-history (Azure DevOps): `ran-per-release` no longer contradicts
  `tool-configured` for default-setup-only repos** (#184). A repo whose only SAST
  mechanism is GHAzDO CodeQL default setup (zero signature-matched pipelines) got
  `tool-configured = verified-pass` but `ran-per-release = verified-fail` ("no matched
  SAST run at all") — self-contradictory, since default-setup scans aren't observable
  through the Pipelines/Builds APIs this collector uses. `ran-per-release` now reads
  `not-checkable` in that case, mirroring the identical fix already shipped for C06
  sca-history's `injectionOnly` guard.
- **GitHub C07 provenance / Azure DevOps C06 sca-history: two more
  `ran-per-release`-style checks no longer read a confirmed absence over an inspection
  failure** (#207), completing #178's own scope. `github/provenance`'s
  `checkProvenanceWorkflow` (C07.provenance.workflow) was the one tool-configured-shaped
  check on either platform that still discarded its skip list entirely;
  `azuredevops/scahistory`'s `checkRanPerRelease` (C06.sca.ran-per-release) had the
  identical gap #178 already fixed for its sibling checks. Both now surface same-repo
  skips in Facts and cap at `not-checkable` instead of `verified-fail`. #207 also listed
  `azuredevops/provenance`'s and `github/provenance`'s own `checkCommitLinkage` as having
  the same gap — verified false: both fetch every build/run in the repo unfiltered by
  pipeline/workflow identity (they ask "did ANY build run on this commit", not "did a
  category-matched pipeline"), so a same-repo skip has no bearing on their evidence — no
  fix needed there, and a stale forward-reference in `azuredevops/provenance`'s own
  rubric claiming otherwise is corrected.
- **`C06.sca.alerts-triaged` (Azure DevOps): a confirmed "alerts not enabled" state now
  reads `verified-fail`, not `not-checkable`** (#190). GHAzDO's actual "not enabled"
  signal for the Alerts - List endpoint turned out to be HTTP 400 with typeKey
  `AdvSecNotEnabledException` — neither of the two codes (403/404) this check's own
  hedge previously considered. This codebase had already decided the opposite for the
  identical org state: the same unlicensed org read `verified-fail` for "dependency
  scanning is off" (`C04.deps.dependabot-alerts`, `C04.secrets.*`,
  `C05.sast.default-setup`) and `not-checkable` for "triage the alerts it would
  produce" — that mismatch is resolved, not introduced, by this change, which mirrors
  the GitHub twin's identical treatment of its own confirmed-disabled signal. Several
  other `[fixture-verify]` hedges this same live run settled are also retired: an
  unlicensed org/project's GHAzDO enablement endpoints read HTTP 200 with every flag
  false/null, never a 403/404 gate as previously guessed, and
  `codeQLEnabled`/`dependencyScanningInjectionEnabled`/`dependabotEnabled`/
  `autofixEnabled` are genuinely null (not merely undocumented-but-never-null) when
  `codeSecurityEnabled` is false, contradicting Microsoft's own "Null is never
  explicitly set" reference claim. A 403 reaching any of these checks is now
  understood as most likely a missing `vso.advsec` token scope (licensing is ruled
  out as the cause), though other permission causes can't be excluded from the
  response alone — this project's own scan PAT already carried that scope, so a
  missing-scope 403 was never actually observed, only inferred by elimination.
- **Report/POA&M `Repo` column/field renamed to `Scope`** (#215). After #176's fix, the
  column could hold three different kinds of thing (an actual repo name, `(org)`, or
  `(project: payments)`) — the header was wrong for two of the three cases it rendered.
  Renamed across `report.md`, `report.html`, and `poam.md`'s `- **Repo:**` line; the
  inline `Repo: ` reason prefix's own label (both renderers) is untouched by this
  rename, since it's only ever shown when the value genuinely is a repo — "Repo:" was
  never the wrong word there, only the standalone column/field header was. Also
  (#216): the hostile-strings escaping regression tests gained a hostile
  `Scope.Project` value, previously untested. Review of that fix (#222) found two real
  escaping holes in `report.md`'s Cluster Detail block — that same inline `Repo:`
  prefix's *value*, plus its Evidence line's (Method/Endpoint/ResponseSHA256) — reached
  output completely unescaped and not inside a code span either, unlike `poam.md`'s
  identical fields — undetected because the hostile fixture's main result used a check
  ID cited by no SSDF task, so it never reached the block those two lines live in; the
  whole Facts-escaping path had been passing vacuously as a result. Fixed by escaping
  both as plain text (no surrounding backticks — CommonMark doesn't process backslash
  escapes inside a code span, so escaping the value while keeping the code-span
  notation would have produced a visible, spurious backslash instead), and
  `internal/mdescape` (the shared markdown escaper every renderer's `esc` template func
  calls) gained its own test file — it previously had none.
- **Azure DevOps packs no longer stamp `scope.project` onto genuinely org-scoped
  results** (#221). `stampResultsWithPlatform` set every result's `Scope.Project` to
  the scan's project unconditionally, so a signed `evidence.json` recorded a project
  scope on org-wide findings too — e.g. `C01.org.2fa-required`, the org-level C09
  audit-logging checks. Reports rendered correctly regardless (labelling keys off
  `CheckMeta.ScopeLevel`, not `Scope.Project`'s presence — see #176), which is why this
  went unnoticed: only the pack itself, the artifact that gets checksummed and
  cosign-signed, carried the wrong claim. `Scope.Project` is now cleared only for a
  result that's genuinely org-scoped (no repo of its own, and its check isn't
  registered `ScopeLevelProject`); it's kept for project-scoped checks as before, and
  now also for every repo-scoped result, since an Azure DevOps repo genuinely lives
  inside a project — clearing it there would have removed accurate context, not a false
  claim. No schema change and nothing to migrate: existing packs aren't rewritten, and
  no downstream consumer reads `scope.project` on a per-result basis (`internal/report`'s
  own renderers do, but only for the checks that keep it, so they're unaffected).

### Changed

- **Harmonized `CheckMeta.Endpoints` host formatting across Azure DevOps collectors**
  (#179): C09 audit-logging and C10 vdp used a path-first style with the host named in
  a trailing parenthetical; every other ADO collector uses host-first
  (`GET <host>/{org}/...`). Both now match the majority convention. Strings and
  `docs/checks-reference.md` only — no behavior change. C10 vdp's `security-md` rubric
  now names its two candidate paths (`/SECURITY.md`, `/docs/SECURITY.md`) explicitly,
  restoring detail the old `Endpoints` parenthetical carried and the trim would
  otherwise have dropped from the published reference.

## [0.3.0] - 2026-07-23

### Added

- **Azure DevOps support** (epic #34) — the full C01–C10 check matrix now runs against
  Azure DevOps behind the same collector seam: `attestward scan --platform azuredevops
  --org <org> --project <project> --repo <repo>...`, authenticated via
  `AZURE_DEVOPS_EXT_PAT`. 94 registered checks across the two platforms: 46 mirrored
  under the same check IDs (honest per-platform degradation where ADO has no
  equivalent — every not-checkable carries a reason naming the exact platform gap),
  plus two new ADO-only checks: `C04.vars.secret-hygiene` (plaintext sensitive-named
  variables in variable groups) and `C08.pipelines.fork-protection`. Includes the
  four-host read-only client (the same transport-level write rejection as GitHub's),
  azure-pipelines scanner-signature matching, per-platform sections in
  `docs/checks-reference.md`, an ADO token-scope table in the README (live-validated),
  and a live-proven demo project with a weekly drift-scanning integration job. (The
  first live scan found and fixed an audit-streams envelope decode bug within this
  release's own dev cycle — no released version carried it.)
- **SAST in CI** (#157): a pinned semgrep workflow scans the codebase on every push to
  main, every PR, and weekly — registry-recognized, so the tool's own self-scan sees it.
- **Signed release tags** (#158, DECISIONS.md D12): from v0.3.0 onward, release tags
  are signed with a dedicated Ed25519 SSH key registered to the repository owner's
  GitHub account.

## [0.2.0] - 2026-07-22

### Added

- **`attestward diff`** — semantic comparison of two evidence packs from the same
  org: status transitions classified as regressions (exit 2), improvements, coverage
  changes (verified ↔ not-checkable, reported separately from posture drift), and
  informational changes; volatile fields ignored; tool/mapping/scope changes surfaced
  as context. `--format text|md|json`. The foundation for continuous-mode drift
  detection (#36); consumed by the new
  [attestward-action](https://github.com/sioakim/attestward-action), which runs
  pinned, signature-verified release binaries in CI and fails on posture drift.

## [0.1.0] - 2026-07-21

First release: the complete v0.1 evidence engine for GitHub (epic #1, Phases 0–6).
Pre-1.0 caveat: CLI flags and output formats may still change between 0.x versions.

### Added

- **`attestward scan`** — read-only scan of a GitHub org (or personal user account):
  runs every registered collector concurrently, rolls results up through the SSDF/CISA
  mappings, and writes an evidence pack to `--out`. Exit codes: 0 all verified-pass,
  2 gaps found (any verified-fail/partial), 1 execution error.
- **Ten collectors** — C01 org-security, C02 repo-protection, C03 env-separation,
  C04 secrets-hygiene, C05 sast-history, C06 sca-history, C07 provenance,
  C08 actions-security, C09 audit-logging, C10 vdp.
- **Self-attestation intake** (`attestward attest`, `scan --self-attestation-file`)
  for controls no platform API can reach. Self-attested answers are always labeled as
  such and never upgrade a CISA form cluster to fully verified.
- **Evidence pack outputs** — `evidence.json` (schema-versioned; every check result
  carries API provenance: endpoint, timestamp, HTTP status, response digest),
  `report.md`, `report.html` (single self-contained file, opens offline), and
  `poam.md` (POA&M remediation tracking for every gap).
- **Pack integrity** — `evidence.json.sha256` sidecar always written; optional cosign
  signing via `scan --sign`; **`attestward verify`** re-checks the hash offline (and
  the signature, if a bundle is present, via `cosign verify-blob`).
- **`attestward report`** — re-render report.md/report.html/poam.md from an existing
  `evidence.json` without rescanning; refuses a hash-mismatched pack unless `--force`,
  which stamps a visible warning banner on every rendered file.
- **`attestward checks list` / `checks docs`** — the full check matrix (collector,
  SSDF tasks, CISA form cluster, minimum token permission) as CLI output and as the
  generated `docs/checks-reference.md`.
- **Mappings as versioned data** — `mappings/ssdf-800-218.yaml` and
  `mappings/cisa-ssda-form.yaml` (every ID traced to NIST SP 800-218 / CISA SSDA form
  primary sources), plus `mappings/scanner-signatures.yaml` (fixture-backed scanner
  detection for C05/C06).
- **Read-only, enforced at runtime** — the GitHub HTTP transport rejects any
  non-GET/HEAD request outright (ADR-0004; see docs/threat-model.md for the full
  claim-by-claim audit).
- **Release pipeline** — goreleaser cross-builds for linux/darwin (amd64 + arm64)
  and windows (amd64), with cosign keyless-signed `checksums.txt`; verification
  instructions in SECURITY.md.
- Documentation set: README with 5-minute quickstart and minimal-PAT table,
  architecture doc, threat model, generated checks reference, ADRs, community health
  files, and a worked example pack from the public demo org in `examples/`.

[Unreleased]: https://github.com/sioakim/attestward/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/sioakim/attestward/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/sioakim/attestward/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sioakim/attestward/releases/tag/v0.1.0
