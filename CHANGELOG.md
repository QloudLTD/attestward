# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).

## [Unreleased]

### Added

- **Release archives now carry third-party attribution and our own `NOTICE`** (#282).
  `.goreleaser.yaml`'s `archives.files` was just `LICENSE`/`README.md` — every published
  `attestward_<version>_<os>_<arch>` archive shipped without the copyright-notice
  attribution that five of the binary's eight statically-linked third-party modules'
  licenses explicitly require to accompany binary redistribution (BSD-3:
  `google/go-github/v75`, `google/go-querystring`, `spf13/pflag`; MIT:
  `shurcooL/githubv4`, `gopkg.in/yaml.v3`), and without our own `NOTICE`, which
  Apache-2.0 §4(d) binds a redistributor of derivative works to carry — a downstream
  recipient of only the tarball had no way to know it exists. Re-derived the dependency
  list from the real module graph rather than trusting a hand-transcribed one: `go list
  -deps ./cmd/attestward` across all five GOOS/GOARCH goreleaser builds (not just the
  host platform) turns up a ninth module the naive single-platform check misses —
  `github.com/inconshreveable/mousetrap` (Apache-2.0), pulled in by `cobra` only on
  windows/amd64 for its double-click-detection helper. New generated file
  `THIRD-PARTY-NOTICES.md` (`hack/gen-third-party-notices.sh`, committed and
  drift-guarded rather than produced only inside the release job — same
  generated/checked pairing as `checks-docs`/`checks-docs-check` and
  `examples`/`examples-check`): reads the resolved module graph plus each dependency's
  own LICENSE (and NOTICE, for `yaml.v3`'s dual MIT/Apache split) already extracted in
  the local module cache, no network call and no new tool (`google/go-licenses`/
  `Songmu/gocredits` both considered, a hermetic hack/ script preferred). New
  `make notices`/`make notices-check` pair and a `third-party-notices-drift` CI job,
  same shape as the existing drift guards. `archives.files` now lists `LICENSE`,
  `NOTICE`, `THIRD-PARTY-NOTICES.md`, `README.md`; verified by extracting a
  `goreleaser release --snapshot --clean --skip=sign` archive and confirming all four
  are present.
- **`tools/threatmodelguard` now also guards `docs/threat-model.md`'s "ten ADO
  collector packages" list** (#274, option 2 of that issue's four). Enumerates every
  package directly under `internal/collect/azuredevops` exposing a
  `Collect(ctx context.Context, ...)` method — determined by that method's presence,
  not by directory listing — and flags any not named in the doc's brace-expansion
  list; `adofixture`/`pipelinehistory` have no such method and stay correctly
  excluded. The go-github endpoint tables (#274's option 1) are deliberately left
  unguarded: their HTTP verbs are already asserted structurally at runtime by
  `provenanceTransport`, so the issue asks for a real cost/benefit call there rather
  than a reflex extension of this guard. Mutation-proved the same way as #260's own
  guard: removing a real collector name from the doc's list flags exactly that
  package; adding it back silences the flag.
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

- **GitHub `scahistory`'s `checkDependencyReview` no longer asserts `verified-fail` from
  a workflow it couldn't read** (#290, found by the independent review of #289 — a
  different variable than that fix's, in the same check function). `found` (whether a
  dependency-review-action-or-equivalent workflow matched) derives from
  `runhistory.MatchWorkflows`, which silently drops any workflow it couldn't fetch,
  decode, or parse into `skippedWorkflows` — and `checkDependencyReview` was the only
  check in the package that never received that list, unlike its siblings
  `checkToolConfigured` and `checkRanPerRelease` (#178/#202). Reproduced: a repo whose
  real `dependency-review-action` workflow (a required status check) 403s on content
  fetch — `C06.sca.tool-configured`/`C06.sca.ran-per-release` correctly went
  not-checkable over the same skip while `C06.sca.dependency-review` asserted
  verified-fail beside them, one signed pack certifying both "couldn't read this file"
  and "this control doesn't exist."

  `checkDependencyReview` now takes `skipped []runhistory.SkippedWorkflow` (threaded
  from `scahistory.go`'s one call site, which already computes it) and caps the
  `!found` branch at not-checkable — surfacing `skipped_workflows` in Facts — whenever
  the skip list is non-empty, mirroring `checkToolConfigured`'s existing shape rather
  than inventing a new one. The check's `checkRubrics` not-checkable entry gained the
  new cause. New test:
  `TestCollect_DependencyReview_OnlyWorkflowUnreadable_NotCheckableNotFail`, mirrored
  from #178/#202's identical regression tests; mutation-proved by disabling the new
  cap and confirming the test reddened with the exact pre-fix verified-fail/reason
  pair before restoring it.
- **`check_id` rendered raw inside an unescaped markdown code span at five
  sites — closed** (#239, a v1.0 flip blocker). `` `{{.CheckID}}` `` appeared
  in `report.md.tmpl`'s Gaps table, Self-Attested heading, and Not Checkable
  table; `poam.md.tmpl`'s Findings heading and Requires-Attention-Outside-
  This-Tool list. All five pull from `pack.Results` filtered only by
  `Status`, never by `check_id` validity, so a hostile `check_id` containing
  a backtick could close the span early and un-neutralize whatever markdown/
  HTML followed — the same class #222/#231 already fixed for Repo/
  Provenance/pack-header fields, left as a deliberately-documented,
  exploitable gap in `docs/threat-model.md` while the repo stays private
  (found during #231's own review, not folded into that fix since it
  reshaped rendering/formatting rather than adding an `esc` call). Escaping
  *inside* the span was never the fix (CommonMark doesn't process backslash
  escapes there — the exact trap #222 hit and had to undo): dropped the span
  at all five sites, `esc`'d as plain text instead, matching the established
  pattern.

  Two sites — `report.md.tmpl`'s Cluster Detail block and its Paired list —
  render `check_id` too but were **not** touched: both are keyed through a
  trusted-mapping lookup (`task.Checks`, `q.Pairing`) that only ever surfaces
  a `CheckResult` whose `CheckID` is byte-identical to the trusted mapping
  string it was looked up by — confirmed by tracing `resultsByCheck`'s
  construction directly, not assumed. `hostile-pack.json` gained three new
  hostile `check_id` markers (two new results, one existing result's
  `check_id` extended) covering all five vulnerable sites and both
  non-vulnerable ones by omission; confirmed each new marker fails against
  the pre-fix templates before fixing them, and re-confirmed via a second,
  single-site mutation per file after.

  `docs/threat-model.md`'s mitigations table had this gap's exploit recipe
  named explicitly (deliberately, per #231's own review — an honest claim
  beats a mitigation table that looks complete); carve-out removed now that
  it's closed. The table's sibling out-of-enum-`status` gap (also named
  there) is unrelated and still open, tracked as #240.
- **GitHub `sasthistory`'s `checkCadence` no longer asserts a confirmed value from a
  failed default-setup query — the last default-setup/enablement-derived instance of
  the #258 conflation class** (#268). `checkCadence`'s `low_confidence_match_only`
  derives from `!defaultSetupConfigured(ds)`, and `GetDefaultSetupConfiguration`
  returns a nil `ds` on ANY error — indistinguishable from a genuine "not configured"
  response, the identical conflation #258 fixed in the sibling `checkToolConfigured`.
  Not folded into
  #258 at the time: `checkCadence` never received `dsErr`/`dsResp` at all, and #258's
  review found closing that is two parameters plus one call site (not the signature
  rewrite originally estimated). Reachable in production the same way #258 already
  established: a token lacking `security_events` fails the default-setup query on every
  repo, and a low-confidence-only workflow match (name heuristic alone) reaches
  `checkCadence`'s Facts construction regardless. Concretely: before this fix,
  `C05.sast.tool-configured` correctly omitted `low_confidence_match_only` for this
  evidence shape while the adjacent `C05.sast.cadence` panel — same key name, same
  underlying failed query — still asserted `true`.

  Extracted the shared `unconfirmedDSFailure(dsResp, dsErr)` carve-out
  `checkToolConfigured` already had inline into its own package-level function, reused
  by both rather than writing a second copy — the same reasoning `matchConfidence`'s own
  doc comment already gives for being shared. `checkCadence` gained `dsResp`/`dsErr`
  parameters (threaded from `sasthistory.go`'s one call site, both already in scope one
  line above it) and gates `low_confidence_match_only`'s Facts inclusion behind
  `!unconfirmedDSFailure(dsResp, dsErr)`, omitting the key rather than emitting a
  defaulted value — matching #258's exact shape. Status/Reason computation is
  deliberately left unguarded, mirroring `checkToolConfigured`'s own precedent (only the
  Facts value gets the gate, not the status decision) — reusing `unconfirmedDSFailure`
  rather than writing a `dsErr == nil` shortcut also preserves the plan-gated exception:
  a plan-gated failure is a confirmed absence, not an unknown, so its key must stay
  present.

  `TestCollect_LowConfidenceMatchPlusDefaultSetupFails_FactsOmitDefaultSetupFields`
  (#258's own regression test) already used the exact fixture shape this bug needed —
  extended it to also assert `C05.sast.cadence`'s Facts, rather than writing a new test
  with a duplicate fixture. Mutation-proved: reverted `checkCadence`'s Facts gate,
  confirmed the extended assertion (and only it) reddens with the exact conflated
  `true` value the fix removes, restored.
- **`docs/threat-model.md`'s self-hosted-macOS job enumeration had five real defects,
  and nothing kept it current** (#260). The "Shared, persistent runner state"
  residual risk names every job sharing `spyros-mac-mini-ssdf`'s persistent Go
  caches, but the list was hand-maintained. Two job names were absent entirely:
  `runner-maintenance.yaml`'s `clean` job (the one job whose whole purpose is
  bounding this exact risk) and `self-scan.yaml`'s `attach-to-release`. Three more
  were attribution-level, not name-level: `multi-arch-build-sample.yaml`'s own
  `build` job (its darwin legs share the runner too, previously invisible behind
  ci.yaml's identically-named, unrelated `build`) landed unattributed on
  `spyros-mac-mini-ssdf`, and that same job's linux/arm64 and linux/amd64 legs land
  on `spyros-parallels-ssdf`/`spyros-ionos-ssdf` respectively — both named as
  machines exposed to this risk with no job attributed (ionos only partially, via
  `test-linux`). Found by re-auditing from scratch, not by trusting the one gap
  already reported. Guarded
  with a new `tools/threatmodelguard`, matching this repo's other three drift guards
  (`checks-docs-check` #30, `examples-check` #228, `rubricguard` #209): parses every
  workflow job's `runs-on` (resolving matrix indirection) and flags any
  self-hosted-macOS job not backtick-quoted in that one bullet. Coarse like its
  siblings — doesn't disambiguate which workflow a bare job name came from, so the
  two `build` jobs are indistinguishable to it. Wired into `ci.yaml` as
  `threat-model-drift`, which had to be added to the enumeration it now guards.

  Swept the rest of the document for the same shape per review: the go-github
  endpoint tables and the "ten ADO collector packages" list are currently accurate
  (verified, not assumed) but equally guardless — not fixed here, out of scope.
- **`tools/threatmodelguard`: fuller unit-test coverage for its individual functions**
  (#260, follow-up). No production code change — kept the initial PR's test suite to
  the issue's own explicit mutation-proof ask plus the one parsing-risk test to stay
  under the diff-size ceiling; adds the rest: a bare-scalar `runs-on`, a matrix leg
  with no `os:` key, case-insensitive label matching, a real-`.github/workflows`
  spot-check, and the doc-section-boundary edge cases (absent bullet, and that
  neighboring bullets' own job mentions don't leak in). Also adds the one case round 2
  review of #260 found missing: `missingFromDoc`'s backtick-delimited match is what
  stops `build-windows` from satisfying `build` as a substring collision — dropping the
  backticks left the whole package green before this test existed.
- **An out-of-enum `status` reaching an unescaped rendering fallback —
  closed** (#240, a v1.0 flip blocker, sibling gap to #239 above).
  `statusLabel`/`statusBadge`'s `default` branch returned an out-of-enum
  `Status` verbatim, unescaped — reachable because nothing on the report
  path ever called `Status.Valid()` or `EvidencePack.ValidateAgainstSchema`
  (only `scan.go`/`diff.go` do).

  Chose rejection over escaping: the schema already declares `status` a
  closed five-value enum (shared by `CheckResult`/`TaskRollup`/
  `ClusterRollup` via one `$defs/status`), and `attestward report` already
  refuses a pack whose `schema_version` it doesn't understand — an
  out-of-enum status is the same category of "this pack isn't what it
  claims to be," and `model.Status`'s own doc comment ("exactly these five
  values exist") makes that a structural invariant, not a soft convention,
  unlike `check_id` (an open string namespace by design — the "Unmapped"
  bucket already handles a `check_id` matching no known task, the reason
  #239 above chose escaping instead).

  `cmd/attestward/report.go`'s `runReport` now calls
  `pack.ValidateAgainstSchema()` — already-existing, already-tested
  infrastructure, reused rather than three hand-written `.Valid()` loops
  that could each go stale independently — right after the `schema_version`
  check, same hard-refusal treatment, no `--force` bypass (a schema
  violation is a shape problem, not the provenance question `--force`'s
  visible-banner escape hatch answers). Two new tests prove the guard
  catches an out-of-enum status on `CheckResult` and on `Rollup.Clusters`
  alike (all three Status-typed fields share the schema's one enum, not
  three independent ones — confirmed directly), plus a negative-baseline
  test confirming a valid pack still renders; mutation-proved by removing
  the new check and confirming exactly the two rejection tests redden while
  the baseline stays green.

  Round 2 review found the `Rollup.Clusters` test was vacuous as first
  written: it set `Clusters` but left `Tasks` nil, and `model.Rollup.Tasks`
  has no `omitempty` — a nil `Tasks` marshals as `"tasks": null` against a
  schema that requires an array, so the pack was rejected at
  `/rollup/tasks` regardless of what the Clusters status said. Proved
  directly: swapping in a genuinely valid status left the test green.
  Fixed by giving `Tasks` its own valid (empty) value, isolating the
  Clusters status as the only remaining schema violation, and tightening
  the assertion from a bare `"schema validation"` substring to
  `"clusters/0/status"` — the broad substring is exactly what let the
  vacuity hide. The `CheckResult` half was never vacuous: the
  negative-baseline test shares the same fixture pack and passes, proving
  it's otherwise schema-clean.

  `docs/threat-model.md`'s mitigations table gains `cmd/attestward/report.go`
  as a "Where" entry alongside the templates/`mdescape` already there;
  this gap's carve-out removed now that it's closed too — the table's
  injection-mitigation cell now has no remaining known-exploitable gap.

  Two more round 2 review fixes, no behavior change: `attestward report --help`
  only described `schema_version` as a hard-refusal reason, but
  `ValidateAgainstSchema()` validates the whole pack — a `null` where the
  schema wants an array (`scope.repos`, `results[].provenance`,
  `rollup.tasks`/`rollup.clusters`) is refused identically now, so `--help`
  says so. `report.md.tmpl`'s two sites #239 left untouched (Cluster Detail,
  the Paired list) and its `Integrity.SHA256` code span each gained an inline
  template comment naming exactly why the raw code span is safe there —
  that reasoning used to live only in a PR body, a threat-model paragraph,
  and a test comment, nowhere near the code a future site would be copied
  from.
- **`checkToolConfigured` Facts no longer assert a confirmed value from a query
  that merely failed, in the GitHub twins of C05/C06** (#258, follow-up to
  #266's identical Azure DevOps fix). `github/sasthistory`'s
  `checkToolConfigured` emitted `Facts["codeql_default_setup"]` from
  `setupConfigured := defaultSetupConfigured(ds)`, and
  `GetDefaultSetupConfiguration` returns a nil `ds` on ANY error —
  indistinguishable from a genuine, observed "not configured" response — the
  identical conflation #266 fixed on Azure DevOps, expressed here via a nil
  pointer rather than an explicit `err == nil &&` guard. `github/scahistory`'s
  `checkToolConfigured` had the same shape: `Facts["dependabot_configured"]`
  derived from `dependabotConfigured`, false whenever
  `fetchDependabotConfig` returns a real fetch error (confirmed by reading
  that function directly: it returns `exists=false` alongside any non-nil
  `err`, not just the normalized "absent at both `.yml`/`.yaml` paths"
  outcome). Both reachable whenever any workflow-based evidence already
  exists — each function's own not-checkable guard only fires when there's
  zero such evidence, so a low- or high-confidence match plus a failed
  default-setup/Dependabot query fell straight through to the misstatement.

  Fixed the same way as #266: omit the affected key entirely when the
  underlying query is unconfirmed, rather than emit a placeholder or third
  state. `github/sasthistory` needed one extra distinction #266's ADO fix
  didn't: a *plan-gated* default-setup failure (GHAS genuinely unavailable,
  e.g. unlicensed) is already treated elsewhere in this same function as a
  real, confirmed "not configured" fact, not an unknown — so the Facts gate
  reuses a new `unconfirmedDSFailure` var shared with the existing
  not-checkable guard (`dsErr != nil && (dsResp == nil ||
  !ghcollect.IsPlanGated(dsResp.StatusCode))`) rather than a bare
  `dsErr == nil` check, so a confirmed plan-gated absence still reports
  normally. Swept each package's own `low_confidence_match_only` (derived
  from the same `setupConfigured`/`dependabotConfigured`) too — four
  Facts-map entries across the two functions in total.

  `github/sasthistory`'s `checkRanPerRelease` and `github/scahistory`'s
  `checkRanPerRelease` were both checked directly, not assumed, and are
  clean — neither carries a Facts field derived from the respective
  error-defaulting variable. `github/sasthistory`'s `checkCadence` is a
  genuine exception, **found but not fixed here**: its own
  `low_confidence_match_only` derives from `defaultSetupConfigured(ds)` the
  same way `checkToolConfigured` did, but `checkCadence` never receives
  `dsErr`/`dsResp` at all — its one call site in `sasthistory.go` only
  passes `ds` — so fixing it needs threading two new parameters through the
  function signature and that call site, a real scope expansion left for a
  separate follow-up rather than folded in silently here.

  Same test shape as #266: each new test derives its "the query genuinely
  failed" fixture from a live HTTP 403/Forbidden response the collector
  actually parses (not a synthetic error value), using a low-confidence-only
  workflow match so the affected fields are actually reachable (every
  existing failed-query test in both packages registers zero workflow
  evidence, hitting the not-checkable guard instead — none of them exercised
  this Facts path before). Asserts the affected keys are *absent* from
  `Facts`, not merely not-`true`. Mutation-proved both fixes independently:
  reverted each `checkToolConfigured` to its pre-fix Facts construction in
  turn, confirmed the corresponding new test (and only that one) reddens
  with the exact conflated value the fix removes, restored.
- **`checkToolConfigured` Facts no longer assert a confirmed GHAzDO enablement
  value from a query that merely failed, in both Azure DevOps C05/C06
  collectors** (#258). `azuredevops/sasthistory`'s `checkToolConfigured`
  emitted `Facts["ghazdo_codeql_default_setup"]` from `setupConfigured :=
  enablementErr == nil && enablement.CodeQLEnabled` — a 403, 404, or any other
  GHAzDO repo-enablement query error collapsed identically to `false`,
  indistinguishable from a genuine, observed "off" response. Reachable in
  production whenever a pipeline match already exists (any confidence): the
  function's own not-checkable guard only fires when there's zero pipeline
  evidence at all, so a low- or high-confidence match plus a failed
  enablement query fell straight through to this misstatement — exactly the
  shape `vso.advsec` being outside the default PAT scope preset produces on
  every repo a scan-token can't see, the default experience for a large
  share of real PATs. Same defect as #246 (Reason strings) and #248 (rubric
  text), one layer down in Facts, where no rubric or status check looks — a
  consumer reading `evidence.json`'s Facts directly (a dashboard, the hosted
  tier) has no adjacent not-checkable status to reconcile it against, unlike
  a `report.md` reader.

  Fixed by omitting the affected key entirely rather than emitting a
  placeholder or third state (the issue's own top preference, confirmed
  safe: `internal/report/facts.go`'s `buildFactsView` iterates `range
  facts`, so an absent key already renders as nothing, and nothing else in
  this codebase — no schema field, no test, no rubric text — currently
  consumes this key by name, so there was no existing-consumer stability
  case for keeping the key and adding a sibling `_query_failed` marker
  instead). Swept every Facts entry in this package and its sibling
  `azuredevops/scahistory` for the same shape (a Fact whose value derives
  from a variable that silently defaults on error) and fixed both found:
  `sasthistory`'s own `low_confidence_match_only` (derived from the same
  `setupConfigured`); `scahistory`'s `checkToolConfigured` had the identical
  `setupConfigured`-derived field (`dependency_scanning_injection_enabled`)
  plus a second, independent one (`code_security_enabled`) and its own
  `low_confidence_match_only`. Five Facts-map entries across the two
  functions in total.

  `checkRanPerRelease` and `checkCadence` were checked, not assumed, per the
  issue's own explicit ask — both confirmed clean: `sasthistory`'s and
  `scahistory`'s `checkRanPerRelease` carry no Facts field derived from
  either package's enablement-error variable; `sasthistory`'s `checkCadence`
  *does* carry its own `low_confidence_match_only`, but by a deliberately
  different formula that already excludes `setupConfigured` entirely (its
  own doc comment explains why: GHAzDO default setup contributes zero
  observable builds to this collector's own run count, unlike GitHub's).
  `scahistory` has no `checkCadence` at all.

  The GitHub twins (`github/sasthistory`, `github/scahistory`) carry the
  identical defect shape and are swept/fixed separately (same issue,
  follow-up PR) to keep this one under the repo's diff-size ceiling.

  Every new test derives its "the query genuinely failed, not a normalized
  absence" fixture from a live HTTP 403/Forbidden response the collector
  actually parses, not a synthetic error value, and asserts the affected
  keys are *absent* from `Facts` (`_, ok := Facts[key]; ok` false) rather
  than merely not-`true` — the distinction the whole issue is about.
  Mutation-proved both fixes independently: reverted each
  `checkToolConfigured` to its pre-fix Facts construction in turn, confirmed
  the corresponding new test (and only that one) reddens with the exact
  conflated value the fix removes, restored.
- **`mapping_versions.scanner_signatures` is now populated on every scan** (#255).
  Declared on `model.MappingVersions`, in `docs/schema/evidence-pack.v1.schema.json`,
  and rendered by both `report.md.tmpl` and `report.html.tmpl` — but the scan path
  never assigned it, so every pack has omitted it since the field was introduced.
  `MappingVersions`' own doc comment claims it "records the version field of every
  `mappings/*.yaml` file consulted during a scan," which was false for this field the
  whole time: `scanner-signatures.yaml` moved 1.0.0 → 1.4.0 across five PRs (#59, #63,
  #165, #170, #234), gaining syft and SonarCloud's ADO tasks along the way, and no pack
  recorded which version classified its own SAST/SCA/provenance findings — a repo
  scanned before and after any of those could flip
  statuses with zero configuration change and no record of why. Fixed by loading the
  registry once more in `cmd/attestward/scan.go`'s own scan path (every collector
  already loads its own copy internally to actually match signatures; this is a second,
  cheap load purely to read `Version` for the pack header, not threaded into the
  collectors themselves). `self_attestation` does **not** have the same problem —
  checked rather than assumed, and it was already correctly populated from
  `saQuestions.Version`.

  New guard, `TestRunScan_MappingVersionsEveryFieldPopulated`: rather than hand-listing
  each `MappingVersions` field name (the same staleness risk any manually-maintained
  list carries — see `docs/threat-model.md`'s own persistent-runner-state paragraph,
  found stale for the identical reason during #257's review), walks every string field
  via reflection and asserts it's non-empty on a real scan-produced pack, so a future
  field added to the struct without also being wired into `runScan` fails automatically.

  Checked, not assumed, whether populating this field would break
  `hack/check-examples-drift.sh`'s mapping-version-currency guard: it wouldn't, because
  that check only ever compared `ssdf`/`cisa_form`/`self_attestation` — it has no
  `scanner_signatures` logic to trip, and `examples/demo-org-pack/evidence.json` is a
  frozen capture that doesn't gain the new field just because the scan code changed
  (confirmed: `examples-check` still passes clean). Extending that guard to cover
  `scanner_signatures` too is deliberately **not** done here: since the captured demo
  pack predates this fix, that field is absent from it and would never match the
  registry's current version, permanently failing the currency check until the demo org
  is genuinely re-scanned live — turning `make examples` into a re-scan requirement
  rather than a re-render. Left for a separate, deliberate decision. Also found while
  checking the render path: `internal/report/context.go`'s and `poam.go`'s own
  `MappingVersionMismatch` detection — a different mechanism from the currency
  guard above — only ever compares `ssdf`/`cisa_form`, despite `context.go`'s own doc
  comment naming "ssdf/cisa/questions"; `self_attestation` and `scanner_signatures` are
  both absent from that comparison in both files, identically. Pre-existing, unrelated
  to the scan-path bug this issue fixes, not touched here.
- **`rubricguard` no longer flags a status reference that's purely moved
  within an unchanged function** (#262). #261 restructured `checkRanPerRelease`
  with no behavior change, and the guard flagged it anyway — it compared raw
  hunk-overlapping line numbers, so a `model.StatusNotCheckable` reference
  moved 17 lines down read as "changed." (Not a required status check here
  — confirmed via the repo's ruleset — so it didn't block the merge, but
  it's the "red tick that doesn't mean the code is wrong" failure mode
  `ci.yaml`'s own coverage-upload comment already warns against.)

  Fixed per the issue's own preferred option: each function's *multiset* of
  referenced `model.Status*` names, old vs new (occurrence-count-sensitive,
  position-insensitive), replaces the hunk-overlap comparison (`scan.go`'s
  new `funcStatusRefs`). A deduplicated *set* (membership only) was tried
  first and also fixes #261, but replaying the fix against this repo's full
  commit history (153 commit-pairs, broader than #209's original 40-PR
  sample) surfaced a real gap it would reintroduce: commit 687e9f4 (#103,
  merged before this guard existed) added a genuinely new branch producing
  `StatusNotCheckable` for an undocumented case, reusing a name the function
  already referenced — a set never changes there; a multiset does (count
  1 -> 2). Final corpus result: 1/153 flags (#261) versus 2/153 under the
  original algorithm, zero new false positives. The #103 regression test
  follows in a separate, test-only PR.

  Cost, found in re-review by injecting into real production code
  (`github/secretshygiene/checks.go:130-133`): exchanging which of two
  *existing* `model.Status*` constants sits in which of two branches
  (condition untouched) leaves a function's multiset identical — invisible
  to this comparison. The old hunk-overlap algorithm caught that one
  specific spelling of the swap (by accident of which text moved); a
  condition-flip swap (e.g. `if enabled` -> `if !enabled`) around an
  unchanged pair of branches was already invisible before this fix, under
  both algorithms, since no status-constant line changes at all either
  way. Accepted deliberately — see `tools/rubricguard/main.go`'s own doc
  comment for the full accounting — as the direct cost of the corpus
  result above, not a free trade.
- **`rubricguard`: pinned the #103 corpus-verification finding above as its
  own dedicated regression test** (#262, follow-up). No production code
  change — the multiset comparison already handles this shape correctly, so
  the test alone closes the gap between "verified once during development"
  and "asserted permanently in CI."
- **C06.sca (Azure DevOps): `checkRanPerRelease` had the same two `dropped_tags`
  Facts-loss holdouts C05's identical function had, both fixed** (#256). #251
  ported C05 `sasthistory`'s pre-#252/#254 `checkRanPerRelease` shape into C06
  `scahistory` unchanged, carrying both holdouts across: the `injectionOnly`
  branch and the `buildsErr` branch each attached `Facts` only when
  `sameRepoSkips` was non-empty (or not at all, for `buildsErr`), so a repo with
  dependency scanning injection on — or a signature-matched pipeline whose
  build-history fetch failed — plus dropped-but-undateable release tags returned
  `not-checkable` with the dropped-tag record silently gone. Counted the holdouts
  explicitly rather than fixing only the one #256 named as filed: #254's own
  review found C05 had two, not the one originally claimed, so this PR checked
  for and confirmed the same shape here before writing the CHANGELOG line, not
  after. Both fixed identically to their C05 counterparts (`fix/246-248-252-
  sasthistory-claims`, post-#254): `dropped_tags` unconditional, `skipped_pipelines`
  still attached only where it already was (the `injectionOnly` branch) —
  confirmed unchanged and not inverted on every other return path in the
  function, none of which have ever carried `skipped_pipelines` (pre-existing,
  reachable only when `hasMatchedPipelines` is true).
- **`go.mod` is now tidy, a CI guard keeps it that way, and goreleaser no longer
  mutates it during release** (#249). Surfaced while verifying #247: `cmd/attestward/
  scan.go` imports `github.com/spf13/pflag` directly, but `go.mod` listed it
  `// indirect` — untidy on `main`, reproduced on a clean checkout (`go mod tidy`
  changes `go.mod`, leaves `go.sum` alone). Nothing checked this (unlike
  `checks-docs-check`/`examples-check`/`rubric-drift-check`, which all exist for
  exactly this shape of drift), and `.goreleaser.yaml`'s `before: hooks: - go mod
  tidy` ran it unchecked on every release — so the `go.mod` that produced published
  binaries was never provably the one at the tagged commit. Latent, not active
  today: the delta was one require-block promotion with `go.sum` unchanged, so the
  resolved dependency graph — and almost certainly the binaries — were identical
  either way. But for a tool whose whole premise is verifiable provenance (signed
  evidence packs, cosign-signed artifacts, #158's signed release tags), "check out
  the tag and rebuild" needs to be literally true, and a release step that can
  mutate the tree before building is exactly what shouldn't exist regardless.
  Three-part fix, in order of what actually matters: a new CI guard,
  `gomod-tidy-drift` (`make tidy-check`, a new `tidy`/`tidy-check` pair matching
  `checks-docs`/`checks-docs-check`'s and `examples`/`examples-check`'s existing
  shape) — this is the part that stops it recurring, without it the other two
  drift back the first time someone adds an import; the tidy result itself
  committed; and the goreleaser `before:` hook removed as redundant once the guard
  exists. Checked rather than assumed whether the guard needs network access:
  `go mod tidy` computes the full module graph, not just this build's own
  dependency closure, so it can need a network fetch for transitive test-only
  modules a plain `go build`/`go test` run never touches (confirmed directly —
  an isolated cache fully populated by `go build ./...` still needed four more
  modules under `GOPROXY=off`) — not fully hermetic, and this recurs on every
  module-graph change (a dependency bump), not just once ever: `lint`'s own
  `go install golangci-lint@v2.12.2` is pinned and genuinely one-time until the
  pin itself moves, but tidy's own closure is a strict superset of whatever the
  build/test jobs already fetched and moves with every `go.mod` change.

  Review found three more things worth fixing in the same PR: `make tidy-check`
  is the only `-check` target in this repo that mutates the working tree on a
  failing run (`checks-docs-check` passes `--check` and never writes;
  `examples-check` renders into a scratch directory and diffs there) — kept
  deliberately rather than restored on failure (harmless in CI, since
  `actions/checkout` resets the tree per job; often convenient locally, since
  the mutation is the fix `make tidy` itself would produce anyway), with the
  target's own comment corrected to say so rather than claiming a read-only
  contract it doesn't honor. The failure output was a bare diff hunk with no
  remediation instruction, unlike its two siblings — now emits an `::error::`
  annotation naming the fix (`run 'make tidy' and commit the result`), matching
  their house style. `docs/threat-model.md`'s own "shared, persistent runner
  state" paragraph — the exact property this guard's hermeticity argument
  leans on — didn't list this new job (or two other pre-existing omissions,
  `rubric-drift-check` and `semgrep.yaml`'s own job); added all three.
- **`MappingVersionMismatch` now compares all four mapping files, not two** (#264).
  `internal/report/context.go` and `poam.go` each independently compared only `ssdf`
  and `cisa_form` — `self_attestation` and `scanner_signatures` were absent from both,
  identically, despite `context.go`'s own doc comment naming "ssdf/cisa/questions"
  (i.e. including `self_attestation`) since before `scanner_signatures` even existed.
  This banner is the mechanism that stops a reader trusting a rendered report whose
  mapping data has moved since the scan — for two of four files it silently never
  fired. `self_attestation` was already populated on every pack, so this wasn't
  theoretical: a genuine drift produced no banner, and a reader could see
  self-attestation answers rendered against question text whose meaning had changed
  underneath them. `scanner_signatures` was a different story at the time this fix
  was written: #255/#263 (both open then) were what would populate
  `MappingVersions.ScannerSignatures` in the first place, so the `scanner_signatures`
  comparison shipped inert on every pack produced up to that point. #263 has since
  merged — scan.go now populates the field on every new scan, the same way it already
  did for the other three, so the comparison this PR added is live rather than
  waiting on a still-open dependency. A pack scanned before #263 still lacks the
  field, same as any older pack missing a field added after it was captured; the
  existing `pack.X != ""` guard already covers that case, not a new addition.

  Also generalized the banner text itself (`report.md.tmpl`, `report.html.tmpl`,
  `poam.md.tmpl`): it used to say mapping drift meant "SSDF task/CISA cluster titles
  ... may be missing or reflect a different revision", accurate when only
  `ssdf`/`cisa_form` drift could trigger it. It's reachable now by `self_attestation`/
  `scanner_signatures` drift too, and neither of those is an SSDF task or CISA cluster
  title, so the wording no longer names a specific cause — just "content below may be
  missing, reflect a different revision, or no longer match what the current mapping
  data would produce."

  Extracted the two files' duplicated comparison logic into one shared
  `mappingVersionMismatch` helper rather than extending both copies separately — the
  duplication is exactly why this drifted in the first place, and a future fifth
  mapping file now needs a comparison line added once, not twice. That de-duplication
  alone doesn't stop a fifth field from being silently missed the same way, though: a
  hand-listed table test of `mappingVersionMismatch`'s four known fields stays green
  forever if a fifth string field is added to `model.MappingVersions` with no matching
  comparison — not a compile error, not a test failure, still a silent miss (this PR's
  own review round caught exactly that in its first draft). What actually closes that
  gap, replacing the table test, is
  `TestMappingVersionMismatch_EveryFieldDriftsIndependently`: it reflects over
  `model.MappingVersions` itself — one struct, one uniform "does drifting this field
  alone flip the result" predicate, the same shape #263's own guard uses — so a future
  field is discovered and drifted automatically, with no test-file change required, and
  fails naming exactly which field has no comparison wired up for it. (An earlier draft
  of this PR considered and rejected reflecting over the four *loaded* mapping
  parameters instead — those are four different types, which would need a common
  interface or a name-keyed lookup to reflect over cleanly. That rejection was correct
  but beside the point: it argued against a design nobody had actually proposed.
  Reflecting over `model.MappingVersions`, the one uniform struct, needed none of that.)

  Threading the two previously-missing loaded mappings (`saQuestions`,
  `scannerSignatures`) through to both comparison sites required extending
  `RenderMarkdown`/`RenderHTML`/`RenderPOAM`'s own exported signatures (`RenderPOAM`
  gains both; the other two already took `saQuestions`, gaining only
  `scannerSignatures`) and their one caller, `cmd/attestward/report.go`, which now
  loads the scanner-signature registry too — `scan.go` doesn't load it yet (that's
  #255/#263, still open), so this load only benefits a pack some future or hand-built
  producer already populates `ScannerSignatures` on.

  Confirmed, not assumed, that the existing `pack.X != "" && loaded.Version != pack.X`
  guard shape degrades gracefully on a field an older pack never populated — a
  dedicated test loads the real, current `scannerSignatures` registry (via this
  package's existing `loadRealMappings` helper, not a hand-typed version string)
  against a pack whose own `ScannerSignatures` is empty and asserts no mismatch
  fires — since that's what makes it safe to ship this comparison before every pack
  carries the field (`examples/demo-org-pack`'s own frozen capture doesn't have it
  yet, for instance).

  The wiring itself — not just `mappingVersionMismatch` in isolation — is covered too:
  every existing fixture pack already mismatches on `ssdf`, which masked whether
  `buildContext`/`buildPOAMContext` actually pass `saQuestions`/`scannerSignatures`
  through (a mutation reverting both call sites to
  `mappingVersionMismatch(pack.MappingVersions, ssdf, cisa, nil, nil)` — a full revert
  of this issue's own fix — left every existing test green). Two new tests, one per
  `Render*` entry point, use a pack whose `ssdf`/`cisa_form`/`scanner_signatures` all
  match what's loaded but whose `self_attestation` alone drifts, and assert the banner
  appears in the rendered output; the same mutation now fails exactly those two tests
  and nothing else. (#271, below, later made the golden-file tests sensitive to the
  same mutation too, once the banner started naming specific files — see that entry.)
- **The mapping-version-mismatch banner now names which file(s) actually drifted**
  (#271, filed as a non-trivial follow-up from #264/#265's own review). The banner text
  used to list all four possible causes on every mismatch regardless of which one
  applied — harmless for `report.md`/`report.html`, which both also render a "Mapping
  versions:" line a reader can cross-reference by hand, but `poam.md` renders no
  mapping-version line at all, and two of the four triggers (`self_attestation`,
  `scanner_signatures`) affect nothing `poam.md` itself renders (`RenderPOAM`'s own doc
  comment). A pure `self_attestation` drift printed a "may be missing" warning on a
  POA&M with nothing on the page that could have drifted for that reason, and no way to
  find out which of the four causes actually applied.

  `mappingVersionMismatch` now returns `[]string` (the drifted `mappings/*.yaml` file
  paths, in a fixed ssdf/cisa/scanner-signatures/self-attestation order regardless of
  which combination actually drifted, so a pack with more than one drift renders
  identically every run) instead of `bool`. File paths, not the Go field name
  (`SelfAttestation`) or the JSON key (`self_attestation`): the file is what a
  compliance reader would actually go open. `renderContext.MappingVersionMismatch`/
  `poamContext.MappingVersionMismatch` are renamed to `DriftedMappingFiles []string` —
  `{{if .DriftedMappingFiles}}` is unchanged as "should the banner render" (empty slice
  is falsy in `text/template`/`html/template` same as `false` was) and doubles as
  "which file(s) to name," via the same comma-join `{{range}}` pattern
  `report.md.tmpl`'s Repos line already used. All three templates gained the drifted
  list; `report.html`'s own "Mapping versions" row shows the *pack's recorded* versions
  only, not which one no longer matches what's currently loaded, so it doesn't make the
  new list redundant there either — kept for consistency across all three documents.
  Banner wording changed too: "drifted: `X`, `Y`" became "the following mapping files
  no longer match: `X`, `Y`" — "drifted" is this project's own jargon (drift baseline,
  `attestward diff`), out of place in a document that went through non-engineer
  sign-off (#25). And the four-file order was picked to match the "Mapping versions:"
  header line both markdown documents already render (`report.md.tmpl:12`) — a reader
  cross-referencing the drift list against that line now sees the same order in both,
  not two different orderings of the same four names.

  `TestMappingVersionMismatch_EveryFieldDriftsIndependently` (#265's reflection test)
  now asserts the specific file name each field must produce, not just that some name
  comes back — a branch naming the *wrong* file (e.g. a copy-paste under the wrong
  case) fails it exactly as loudly as a branch naming none. Both `Render*` wiring
  tests, proven necessary by #265's own review (a `nil, nil` revert at either call site
  used to leave every test green), gained the same specificity: re-run the identical
  mutation here and it now fails on the missing file name, not just a missing
  substring — and, because the golden fixture's own drift list now names files by
  name rather than just tripping a bool, the two golden-file tests catch that same
  mutation too, without any change to them. Four tests redden where two did before.

  Round 2 review found the reflection test's own new assertion wasn't tight enough:
  `slices.Contains(got, wantFile)` passes if a branch appends an extra, undrifted
  file's name alongside the right one — proven by mutating the scanner-signatures
  branch to also append `cisa-ssda-form.yaml`, which left the whole suite green and
  lint clean, since no golden drifts `scanner_signatures` (`rich-pack.json` lacks the
  field entirely) and both wiring tests set it to *matching*. Each subtest drifts
  exactly one field from an all-matching baseline, so the correct answer is always a
  one-element slice; `slices.Contains` now reads `slices.Equal(got, []string{wantFile})`
  instead, mutation-proven to catch the same injected extra-append the naive check
  missed.
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
- **GitHub `sasthistory`/`scahistory` no longer assert `verified-fail` from a
  workflow-run-history query that never returned** (#287, found by the independent
  review of #284, which had claimed to close "the last known instance of the #258
  conflation class" — it didn't; #258's own class definition — "any Fact whose value
  is derived from a variable that silently defaults on error" — always covered this
  run-history variable too, a different variable than #267's sweep scoped to.
  #268's title overclaimed the same way and was corrected separately, not by this
  PR; #284's commit message made the identical overclaim and is immutable in git
  history — left as written rather than misdescribed as fixed here). `sasthistory.go`'s
  `collectRepo` looped `runhistory.FetchWorkflowRuns` once per matched SAST workflow
  and `continue`d past a failure with no record of it; `runs` silently defaulted to
  whatever the surviving workflows produced, and `checkCadence`/`checkRanPerRelease`
  both asserted confirmed values (Facts and Reason) from that incomplete pool.
  Reproduced: a real `codeql-action/analyze` workflow, one release, a good token, but
  the workflow-runs endpoint returning 403 (secondary rate limit) or 500 — everything
  else succeeds, and the pack emitted `C05.sast.cadence`/`C05.sast.ran-per-release`
  both `verified-fail`, asserting a confirmed absence from a query that failed.
  `scahistory.go`'s identical loop fed `checkRanPerRelease`'s `per_release` the same
  way.

  Both collectors now track the first per-workflow fetch error (`runsErr`) while
  still querying every remaining matched workflow (an unrelated workflow's runs are
  still worth gathering), then route to `not-checkable` rather than `verified-fail`
  when the merged runs pool is tainted by ANY workflow's failure — not just the
  failing workflow's own contribution: `checkCadence`'s run count and
  `checkRanPerRelease`'s per-release coverage both read the merged pool as a single
  unit, so a partial failure can silently undercount it exactly like a total one
  would (a release the failed workflow actually covered would still read
  "missing"). Mirrors `azuredevops/sasthistory`'s and `azuredevops/scahistory`'s
  identical `buildsErr` shape (checks.go:357/458/404) rather than inventing a new
  one — same early-return-before-either-Facts-map position, same unconditional
  `dropped_tags` inclusion on the ran-per-release path. Derived Facts keys
  (`run_count`, `runs_per_week`, `longest_gap_days`, `per_release`) are omitted
  entirely rather than reported as a defaulted zero, preserving #258's invariant
  that a `verified-fail` status is never paired with an omitted Facts key.

  Secondary finding also addressed: `scahistory/checks.go`'s `tool_names` added
  `"Dependabot"` from `dependabotConfigured` without an explicit `dependabotErr ==
  nil` gate, unlike the two Facts keys beside it. Investigated and confirmed
  behaviorally inert today — `fetchDependabotConfig` already normalizes every real
  fetch failure to `exists=false`, so `dependabotConfigured` is false whenever
  `dependabotErr != nil` regardless of the gate — but made explicit anyway so
  `tool_names`' correctness stops silently depending on that other function's
  contract, plus a regression test pinning the invariant (mutation-proved against a
  simulated contract regression, not against this no-op diff, since there is no
  live behavior for that specific gate to counterfactually prove).

  New tests: `TestCollect_WorkflowRunsFetch403_CadenceAndRanPerReleaseNotCheckable`
  and `TestCheckRanPerRelease_RunsErr_NotCheckableFactsOmitPerRelease` (sasthistory),
  `TestCollect_WorkflowRunsFetch403_RanPerReleaseNotCheckable` (scahistory) — neither
  package previously had any test exercising a failing `/runs` response. Fixing this
  also exposed a real pre-existing gap in
  `TestCollect_WorkflowBasedSCATool_AllChecksResolveCleanly`'s own fixture: it
  registered run history for only one of its two matched SCA workflows
  (dependency-review-action is itself SCA-category), silently relying on the very
  swallow this issue fixes to hide the other's unmocked 404 — the fixture now mocks
  both.
- **`tools/threatmodelguard`'s guarded enumeration was itself incomplete, and its
  section scoping leaked past two real Markdown boundaries** (#286, two compounding
  findings against #260/#272/#273, independently re-verified before merge). `wake-aorus`
  and `sleep-aorus` (`multi-arch-build-sample.yaml`'s AORUS wake/sleep pair) were named
  only in a separate "idle unless manually run" clause, not in the "every macOS-labeled
  job in this repo" list `docs/threat-model.md` itself claims is exhaustive — and
  `missingFromDoc` substring-searches the whole bullet, so that clause's backtick
  mention satisfied the guard anyway, silently. The clause also tried to map three job
  names to two machines with one "respectively," which can't express the real mapping.
  Fixed by moving both names into the exhaustive list (where every other guarded job
  already lives) and rewriting the idle-jobs clause without "respectively" —
  `docs/threat-model.md` now names all twenty of this repo's self-hosted-macOS jobs
  inside that one list, the doc-only fix #286 itself recommends.

  That fix is prose convention, not enforcement, and is not the structural half of
  finding 1 — deliberately left open, per the issue's own recommended option, so it
  isn't recorded as closed here. `missingFromDoc` is unchanged: it still accepts a
  name mentioned anywhere in the bullet, not just inside the list, so "in the list"
  and "mentioned in the bullet" only coincide today because every name happens to be
  written that way. Reviewer proved the gap survives: moving `sign-verify` out of the
  list into another clause of the same bullet still passes. A pre-existing instance
  of the same looseness was already there before this PR — `build` appears four times
  in the bullet, and removing its one list-anchored mention still passes the guard
  because it's also named three more times elsewhere in the same bullet (confirmed
  directly). Separately, `runnerStateSection`'s end-of-section scan only recognized
  `"\n  - **"` (a nested, two-space sibling bullet) and `"\n## "` as terminators —
  neither a 0-indent `"- **"` bullet (the level this document's own residual-risks
  list actually uses) nor a `"### "` subsection heading ended the scan, so a job name
  appended after either would have silently satisfied the guard against a stale
  enumeration. Added both markers; the doc comment above `runnerStateSection` also
  overclaimed "top-level bullet" for the existing two-space marker, corrected to say
  what it actually matches.

  New tests `TestRunnerStateSection_ScopesPastA0IndentBullet` and
  `TestRunnerStateSection_ScopesPastASubsectionHeading` cover the two new boundaries;
  mutation-proved by reverting the marker-list change and confirming both (and only
  both) redden, then restoring. `go run ./tools/threatmodelguard` stays green against
  the corrected doc — today's enumeration is genuinely complete, which is a fact about
  this edit, not a stronger guarantee the guard itself now enforces.

  Also corrected, found during review: this same bullet (and the sibling residual risk
  above it) named a single machine, `spyros-mac-mini-ssdf`, for every self-hosted-macOS
  job, but this repo has two identically-labeled self-hosted macOS runners
  (`spyros-mac-mini-ssdf` and `spyros-mac-studio-ssdf`) and every job selects by label
  (`runs-on: [self-hosted, macOS]`), never by machine name, so either can run any of
  them — confirmed against the live runners API, and `spyros-mac-studio-ssdf` has
  actually executed several of the jobs this section attributes solely to the other
  machine. Reworded both mentions to reflect label-based assignment across both
  machines; the fuller per-machine accounting and isolation implications are out of
  scope here and tracked in #301.

### Changed

- **`integration-scan.yaml` gains a path-filtered `push`-to-`main` trigger alongside its
  weekly schedule** (#278): the schedule alone only catches drift in GitHub's/Azure
  DevOps's own API surface, which doesn't track this repo's merge rate — a regression in
  this repo's own collector code now surfaces the moment a qualifying PR merges rather
  than waiting up to a week. Path-filtered to the trees that can move a
  `fixtures.yaml`/`fixtures-ado.yaml` entry or change how that comparison runs — the
  collector/mapping logic (`internal/collect/**`, `internal/mapping/**`, `mappings/**`),
  `runScan`'s orchestration (`cmd/attestward/scan.go`, `scanrepos.go`, `scanconfig.go`),
  the two integration tests and their fixture tables, and the workflow file itself. The
  workflow's own header comment records the full derivation, including what is
  deliberately excluded and why — not repeated here, since an enumerated list in two
  places is exactly the kind of claim that drifts. Both drift-tripwire issue bodies now
  name their actual trigger (push vs. schedule vs. manual dispatch) instead of assuming
  "scheduled", and both now name a third failure cause alongside a real regression and
  platform API drift: a deliberate, legitimate change to what the tool detects that just
  needs its fixtures file updated to match.
- **`C04.vars.secret-hygiene`'s sensitive-variable-name pattern widened to v2** (#181,
  from #180's own review). v1 (`(?i)(password|passwd|secret|token|api[_-]?key|
  connectionstring)`) was internally inconsistent — `api[_-]?key` tolerated a separator
  but `connectionstring` didn't, so `CONNECTION_STRING`/`connection-string`, the
  dominant real-world spelling, never matched; `pwd`, `credential(s)`, and `connstr`
  were missing outright too. v2 (`(?i)(password|passwd|pwd|secret|credentials?|token|
  api[_-]?key|connstr|connection[_-]?string)`) applies `[_-]?` separator tolerance
  uniformly to every multi-word stem and adds the three missing stems. This is a
  coverage improvement, not an honesty-bug fix:
  disclosure was already adequate (the rubric quotes the pattern verbatim, and nothing
  presents this as a content scan). The pattern is now exported as
  `SensitiveVariableNameRE` with a doc comment inviting reuse by a future GitHub
  variable-store analog, though no such collector exists yet and none is added here.
  The documented false-positive trade is unchanged and now pinned by its own test:
  `tokenizer_config`-shaped names still match (they contain "token") and are meant to,
  with the exact offending variable/group name always recorded in Facts for trivial
  triage. Reason strings, the `checkRubrics` entry, the remediation text, and
  `docs/checks-reference.md` (regenerated via `make checks-docs`) all quote the new
  pattern in lockstep with the code.
- **Harmonized `CheckMeta.Endpoints` host formatting across Azure DevOps collectors**
  (#179): C09 audit-logging and C10 vdp used a path-first style with the host named in
  a trailing parenthetical; every other ADO collector uses host-first
  (`GET <host>/{org}/...`). Both now match the majority convention. Strings and
  `docs/checks-reference.md` only — no behavior change. C10 vdp's `security-md` rubric
  now names its two candidate paths (`/SECURITY.md`, `/docs/SECURITY.md`) explicitly,
  restoring detail the old `Endpoints` parenthetical carried and the trim would
  otherwise have dropped from the published reference.
- **`CLAUDE.md`'s hand-maintained Progress tracker section removed, including its
  frozen Phase 0-6 history** (#276). Line 3's own instruction told every session to
  keep it current "in the same PR/commit that closes an issue" — followed reliably
  enough that the section still went stale repeatedly: the #34 Azure DevOps epic
  shown unchecked and "in progress" days after it had actually closed, the #36
  bullet's own two continuous-mode cross-references (#157, #158) still called open
  after both had been fixed, and a v1.0-milestone bullet naming six hosted-tier
  issues (#121-126) as this repo's open work after all six had closed (one
  delivered, five re-filed to `attestward-cloud`) — all found only by being asked to
  specifically audit the file, not by the "update it in the same PR" rule catching
  any of it on its own. A hand-typed mirror of GitHub issue state, updated by a rule
  nobody was structurally forced to follow, reliably drifts — the identical failure
  mode issue #260 independently found the same week in `docs/threat-model.md`'s own
  hand-maintained enumeration, one level down from process docs into code-adjacent
  claims.

  Considered and rejected: a CI guard comparing the tracker against live issue state
  (this repo's other four drift guards are all deliberately hermetic — no network
  calls in `go test ./...` — and a guard needing live GitHub API access is a
  materially heavier, differently-fragile category of tooling, one that also
  degrades on a fork's CI once #138 flips this repo public, with no credential to
  query issue state from); and regenerating it from the API the way
  `tools/progress/generate.py` already does for `tools/progress/index.html` (the
  tracker's only real value was its hand-written narrative — "18 collector-phase PRs
  each through independent session-level review", "found + fixed 5 real bugs across
  two review rounds" — texture no API call can reconstruct from issue titles and
  state alone, so a generator would only ever produce the checkbox skeleton and
  leave the prose to keep drifting anyway).

  The narrative was relocated, not deleted: `docs/archive/progress-narrative.md`
  carries it now, marked historical/not-maintained the same way
  `docs/archive/roadmap.md` already was — GitHub Issues stay canonical, this is
  context a future reader can't get from issue titles alone. `CLAUDE.md` itself now
  points at the [issue tracker](../../issues) and `tools/progress/generate.py`'s live
  dashboard directly, with no local mirror to drift. The Status paragraph's own
  hand-typed open-issue count ("11 open issues") was corrected too, by removing the
  number entirely rather than updating it to the now-current count — a fresh number
  written into prose is the identical bug, just reset to zero drift for one commit.
  `tools/progress/generate.py`'s own comment, previously instructing "update both
  places" (itself and this file) when phase scope changes, updated to reflect that
  there's only one place now.

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
