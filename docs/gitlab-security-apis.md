# GitLab's Ultimate-tier security APIs, as actually observed

Everything below was measured against live GitLab.com on **2026-08-13**, against
two real projects on two different tiers:

| Role | Project | ID | Tier |
|---|---|---|---|
| Entitled | `qloud-ltd-group/attestward-fixtures` | 85264548 | Ultimate **trial**, `trial_ends_on: 2026-09-08` |
| Free control | `sioakeim/attestward` | 85258212 | Free |

This document exists because C05 (`sast-history`) and C06 (`sca-history`) have no
GitLab collector yet, and the namespace that can answer these endpoints stops
being able to on **2026-09-08**. Write the collectors against what is recorded
here, not against docs.gitlab.com — several things below contradict the obvious
reading of the documentation.

Fixtures: `internal/collect/gitlab/gitlabfixture/testdata/`.

---

## 1. The headline finding: REST fails loudly, GraphQL fails silently

This is the single most important thing on this page, because Attestward's whole
design rests on telling *not entitled* apart from *verified clean*, and the two
APIs give opposite answers to that question.

**REST 403s.** Every security endpoint, on the Free project:

```
GET /projects/85258212/vulnerability_findings   → 403 {"message":"403 Forbidden"}
GET /projects/85258212/vulnerabilities          → 403 {"message":"403 Forbidden"}
GET /projects/85258212/dependencies             → 403 {"message":"403 Forbidden"}
```

**GraphQL returns empty collections, with no error at all.** Same project, same
token, same moment:

```json
{"data":{"project":{"securityScanners":{"enabled":[],"available":[],"pipelineRun":[]},
                    "vulnerabilities":{"nodes":[]}}}}
```

No `errors` key. No null. Just empty arrays that are structurally identical to
"this project is entitled, fully scanned, and clean."

> **A GraphQL-only C05/C06 collector cannot distinguish an unentitled project
> from a spotless one, and would silently report a Free project as passing.**
> Use REST for the entitlement decision.

**This contradicts GitLab's own documented null-vs-empty contract, which is
the sharper version of the finding.** GitLab's GraphQL docs say a field
returns `null` (with no `errors` entry) when the caller lacks permission or
the required tier — and separately, `{"nodes": []}` is the documented shape
for "permitted, but nothing there." An implementer who read only that and
wrote `if securityScanners == nil { unsupported }` would ship a guard that
never fires: the Free capture below shows `securityScanners` itself is a
**non-null object containing empty arrays**, not a null field. GitLab's own
stated contract does not flag this case at all — you have to check
`available` specifically (next).

### The one exception that makes GraphQL usable

`project.securityScanners.available` is the discriminator:

| Field | Free | Ultimate |
|---|---|---|
| `available` | `[]` | `["SAST","SAST_ADVANCED","SAST_IAC","DAST","DEPENDENCY_SCANNING","CONTAINER_SCANNING","SECRET_DETECTION","COVERAGE_FUZZING","API_FUZZING","CLUSTER_IMAGE_SCANNING"]` |
| `enabled` | `[]` | `["SAST","DEPENDENCY_SCANNING","SECRET_DETECTION"]` |
| `pipelineRun` | `[]` | `["SAST","DEPENDENCY_SCANNING","SECRET_DETECTION"]` |

⚠ **The "tier capability" reading of `available` is an inference from this
one two-project sample, not something GitLab's docs state.** GitLab documents
`available` only as "List of analyzers which are available for the project" —
nothing about licence/subscription/entitlement specifically. An empty
`available` on the Free project is *consistent* with "this tier can't run
these scanners", but the two-point sample here can't rule out a project- or
config-level cause instead of a tier-level one. Treat it as the best signal
observed, not a documented guarantee — and prefer REST for the actual
entitlement decision, per the boxed recommendation above.

`enabled` (configured in CI, → `C05.sast.tool-configured` /
`C06.sca.tool-configured`) and `available` map cleanly onto checks this repo
already has. **`pipelineRun` does not, and should not be used for
`ran-per-release` or `cadence`:** GitLab documents it as "List of analyzers
which ran successfully in the **latest pipeline**" — a single-pipeline
snapshot, not history. Both `ran-per-release` and `cadence` are explicitly
lookback-window checks (`internal/collect/gitlab/unsupported/unsupported.go`:
"SAST run cadence over the **lookback window**", "ran for **each release in
the lookback window**") — a signal describing only the latest pipeline cannot
answer either one. Build cadence/ran-per-release from per-pipeline iteration
(the jobs API's `finished_at`, already recommended in §4 for timing) instead;
`pipelineRun` is only useful as a fast "did the most recent pipeline scan at
all" check. Recorded as `graphql-security-scanners-{ultimate,free}.json`.

---

## 2. `security_report_summary` does not exist in REST

The brief that prompted this capture assumed
`GET /projects/:id/pipelines/:pipeline_id/security_report_summary`. It **404s on
every pipeline**, including ones with findings:

```
GET /projects/85264548/pipelines/2745885318/security_report_summary
  → 404 {"error":"404 Not Found"}
```

It is a **GraphQL field**, `Pipeline.securityReportSummary`, and there it works:

```graphql
project(fullPath: "…") { pipeline(iid: "3") { securityReportSummary {
  sast { vulnerabilitiesCount scannedResourcesCount }
  dependencyScanning { vulnerabilitiesCount }
  secretDetection { vulnerabilitiesCount }
  dast { vulnerabilitiesCount scannedResourcesCount }
  containerScanning { vulnerabilitiesCount }
  coverageFuzzing { vulnerabilitiesCount }
  apiFuzzing { vulnerabilitiesCount }
  clusterImageScanning { vulnerabilitiesCount }
} } }
```

→ `{"dependencyScanning":{"vulnerabilitiesCount":8},"sast":{"vulnerabilitiesCount":1,
"scannedResourcesCount":0},"secretDetection":{"vulnerabilitiesCount":1}}`, with
every scanner that did not run present as `null`. Recorded as
`graphql-security-report-summary.json`.

⚠ **Per-scanner `null` is ambiguous and must not be read as "did not run".** On
the Ultimate project, a pipeline whose scan jobs never produced reports returns
`{"sast":null,"dependencyScanning":null,"secretDetection":null}` — and the Free
project returns `securityReportSummary: null` wholesale. Absence here means
"no report", never "no vulnerabilities", and never "not entitled". Pair it with
`securityScanners.available` (§1) before drawing any conclusion.

Note `pipeline(iid:)` takes the **project-scoped iid**, not the global pipeline
id that REST uses. The findings pipeline is REST id `2745885318` = GraphQL
`iid: "3"`. If a collector only has the REST id, GraphQL also accepts it
directly as a global id — `project.pipeline(id: "gid://gitlab/Ci::Pipeline/2745885318")` —
so an iid lookup isn't required.

---

## 3. Raw scanner reports: one of them is not downloadable

This is the trap that cost the most time here, and it is invisible from the
jobs API.

`GET /projects/:id/jobs/:job_id` lists an `artifacts[]` array that includes the
report files with their real sizes:

```json
{"file_type":"dependency_scanning","filename":"gl-dependency-scanning-report.json","size":24701}
```

**That listing does not imply the file can be fetched.** Only files the job
declared under `artifacts:paths:` end up in the downloadable archive. Files
declared solely under `artifacts:reports:` are listed but not served:

| Report | In archive? | `GET /jobs/:id/artifacts/<filename>` |
|---|---|---|
| `gl-sast-report.json` | yes | **200** |
| `gl-secret-detection-report.json` | yes | **200** |
| `gl-dependency-scanning-report.json` | **no** | **404** |
| `gl-sbom.cdx.json.gz` | no (an unzipped per-package variant is) | **404** |

The SBOM asymmetry has a mechanism, not just an observation: the stock
template declares its CycloneDX outputs under `artifacts:paths:` as the glob
`**/gl-sbom-*.cdx.json` — which matches the per-package file
`gl-sbom-npm.cdx.json` but does not match `gl-sbom.cdx.json.gz` at all (wrong
extension). The gzipped combined SBOM was never going to be in the archive;
it isn't a case of "declared but not published" the way the dependency-
scanning report is.

Two dead ends, both tested, neither worth retrying:

- `GET /api/v4/projects/:id/jobs/:id/artifacts?file_type=dependency_scanning`
  — the parameter is **silently ignored**; you get the same archive zip back
  (200, identical 670 bytes). It does not error, so it looks like it worked.
- `GET /<path>/-/jobs/:id/artifacts/download?file_type=dependency_scanning`
  — the web route **403s for a PAT**. It needs a browser session cookie.

### How the dependency-scanning report was actually recovered

Re-declare it under `artifacts:paths:` and re-run. Appending this to the
fixture project's `.gitlab-ci.yml` was enough:

```yaml
gemnasium-dependency_scanning:
  artifacts:
    paths:
      - gl-dependency-scanning-report.json
```

The re-run produced a byte-identical **24701**-byte report (the lockfile had
not changed), and the job's archive grew 670 → 4802 bytes. The capture branch
was deleted afterwards; `main` on the fixtures project is untouched.

> **Consequence for the collector:** Attestward cannot rely on reading
> `gl-dependency-scanning-report.json` from a customer's pipeline, because
> customers run the stock template and the stock template does not publish it.
> Get SCA findings from `GET /projects/:id/dependencies` and
> `/vulnerability_findings` instead — both already recorded. The raw report is
> recorded here for its *schema*, not as a retrieval path.

---

## 4. Report shapes

All three reports share `{version, scan, vulnerabilities[]}`. `version` is the
GitLab security-report schema version (`15.2.2` for SAST/DS, `15.2.4` for
secret detection) — **not** the scanner version, which is `scan.scanner.version`.

`scan` carries `analyzer`, `scanner`, `type`, `start_time`, `end_time`,
`status`, `observability`. `start_time`/`end_time` are naive
`2026-08-10T00:44:31` strings with **no timezone** — do not parse them as
RFC3339. Cadence checks should prefer the job's own `finished_at` from the jobs
API, which is properly zoned.

Each vulnerability carries `id` (a content hash, stable across runs — usable for
dedupe), `category`, `name`, `description`, `severity`, `scanner{id,name}`,
`location`, and `identifiers[]`. `identifiers[]` is the useful part: it is a
mixed list where `type` varies by scanner. Across these three reports the
observed set is exactly `cve`, `cwe`, `gemnasium`, `ghsa`, `gitleaks_rule_id`,
`gosec_rule_id`, `owasp`, `semgrep_id` — and a single finding carries several
at once, in no guaranteed order. Match on `type`, never on list position —
and expect **more than one identifier of the same `type`** on a single
finding (the SAST finding here carries two separate `owasp` identifiers,
`A02:2021 - Cryptographic Failures` and `A3:2017 - Sensitive Data Exposure`);
a `map[type]identifier` reduction silently drops one.

⚠ **`severity` is capitalised (`"Critical"`, `"High"`, `"Medium"`) in the raw
reports, but SCREAMING_CASE (`"CRITICAL"`) in GraphQL and lowercase
(`"critical"`) in the REST `/vulnerabilities` response.** Three casings for one
concept across three surfaces of the same product. Normalise on ingest.

⚠ **`dependency_files` is absent entirely from the dependency-scanning
report** — not present as a key at all (measured: the report's top-level keys
are exactly `scan`, `version`, `vulnerabilities`), so a `len()` on a decoded-
but-missing field reads as 0 and hides the fact that it was never sent.
Gemnasium 6.6.1 emits a CycloneDX SBOM instead
(`gl-sbom-npm.cdx.json`, `bomFormat: CycloneDX`, `specVersion: 1.4`). Anything
wanting the dependency inventory should read the SBOM or
`GET /projects/:id/dependencies`, not this field.

⚠ **`scan.primary_identifiers` is enormous and irrelevant** — 592 entries,
72,682 of the SAST report's 104,094 bytes, listing every rule the analyzer
knows rather than anything it found. The committed fixture keeps 3 entries so
the shape stays visible; that trim is ours, not GitLab's.

---

## 5. What is recorded, and what it costs to re-record

Captured **2026-08-13** (§1–§3 probes, and the dependency-scanning report), and
**2026-08-10** (everything else, by an earlier session):

| Fixture | Source |
|---|---|
| `gl-sast-report.json` | SAST artifact, 1 finding (MD5/CWE-327), rules list trimmed |
| `gl-dependency-scanning-report.json` | DS artifact, 8 findings, full |
| `gl-secret-detection-report.json` | Secret Detection artifact, 1 finding |
| `gl-sbom-npm.cdx.json` | CycloneDX 1.4 SBOM, 2 components |
| `graphql-security-report-summary.json` | `Pipeline.securityReportSummary` |
| `graphql-security-scanners-{ultimate,free}.json` | The tier discriminator, both tiers |
| `vulnerability_findings.json`, `vulnerabilities-all-states.json`, `dependencies.json`, `403-not-entitled.json` | earlier session |

The counts corroborate each other, which is the reason to trust them: GraphQL
says 8 / 1 / 1, and the raw reports independently contain 8 / 1 / 1.

**Re-recording needs a paid namespace.** The trial ends 2026-09-08 and job
artifacts expire even sooner — the ones these came from expire **2026-09-09**.
The fixture project keeps `package.json` / `package-lock.json` pinning lodash
4.17.15 and minimist 1.2.0 precisely so Dependency Scanning still has something
to find if a refresh is needed before then; the scannable source file was
removed after capture, so SAST and Secret Detection now return zero findings
and would need it restored.

## 6. One correction owed to `unsupported.go` — PAID 2026-08-13

The C06 reason string used to say that on a free project "the API returns
nothing". Measured, REST returns **403**, and it is *GraphQL* that returns
nothing. The distinction is the whole point of the check.

Both C05 and C06 have since left `unsupported.go` entirely, for
`internal/collect/gitlab/{sasthistory,scahistory}`, and the correction landed
with them. Where the collectors ended up, and why:

| Check | Outcome |
|---|---|
| `C05.sast.tool-configured` | real, **Free tier** — merged CI configuration |
| `C05.sast.ran-per-release` | real, **Free tier** — releases + job history |
| `C05.sast.cadence` | real, **Free tier** — job history |
| `C05.sast.default-setup` | not-checkable: no GitLab analogue of a repo-level scanning toggle |
| `C06.sca.tool-configured` | real, **Free tier** |
| `C06.sca.ran-per-release` | real, **Free tier** |
| `C06.sca.alerts-triaged` | real, **Ultimate** — `/vulnerabilities`, 403 → not-checkable |
| `C06.sca.dependabot-config` | real, **Ultimate** — `/dependencies` vs the repo tree, retitled |
| `C06.sca.dependency-review` | not-checkable: GitLab has no required-status-check model |

Two things about §1 turned out to matter more than expected once the code was
written:

- **The tier question mostly evaporated.** Six of the nine checks are answered
  by `GET /ci/lint`, `GET /releases` and `GET /jobs`, none of which is gated —
  GitLab defines a scanner job by the `artifacts: reports:` type it publishes,
  and that declaration is readable on a free project. §1's trap is therefore
  not navigated by most of this work, it is *avoided*. Only C06's two
  entitled checks meet it, and they take REST.
- **§1's own hedge held.** `securityScanners.available` is never read. It is
  the best signal observed for the tier question, but it is a two-project
  inference rather than a documented guarantee, and a REST 403 needs no
  inference at all.

### A trap §1 does not cover, found while writing the collector

`GET /ci/lint`'s `merged_yaml` is not a safe thing to decode into a
`map[string]Job`. Its top level is not uniformly job-shaped — `stages:` is a
sequence, `variables:` a map of scalars — so a whole-document decode into a
struct-valued map fails outright on the first of them, and every real
project's configuration would have read as unparseable. Decode node by node.

And most entries in GitLab's own SAST template **declare
`artifacts: reports: sast:` and can never run**. Counted against the live
template on 2026-08-13:

| | SAST | Dependency Scanning |
|---|---|---|
| entries declaring the report type | 21 | 5 |
| hidden anchors (leading `.`) | 2 | 1 |
| pinned off with an unconditional `rules: [{when: never}]` | 11 | 1 |
| **actually runnable** | **8** | **3** |

The eleven disabled SAST entries are the `sast` configuration-only stub plus
ten retired analyzers (`bandit-sast`, `brakeman-sast`, `eslint-sast`,
`flawfinder-sast`, `gosec-sast`, `mobsf-android-sast`, `mobsf-ios-sast`,
`nodejs-scan-sast`, `phpcs-security-audit-sast`, `security-code-scan-sast`).
Counting the declaration alone credits every project that merely includes the
template with thirteen scanners it does not have — and, worse, lets a project
that deliberately disabled its only real analyzer still read as configured.
Recorded as `ci-lint-security-templates.json`.

## 7. Group-level protected environments (issue #13)

Captured **2026-08-13** on the same two namespaces, for a different reason: not a
tier question but an *address* question. `GET /projects/:id/protected_environments`
returns project-level entries only, and a project whose production environment is
protected at the **group** level has an empty project-level list — so C03's two
protection checks read a genuinely protected project as `verified-fail`.

Reproduced end to end on `qloud-ltd-group/attestward-fixtures`: with one
group-level entry live and no project-level entry, the project list was `[]`.

### The two models do not address environments the same way

| | Project level | Group level |
|---|---|---|
| Endpoint | `GET /projects/:id/protected_environments` | `GET /groups/:id/protected_environments` |
| Keyed by | environment **name** | deployment **tier** |
| Tier badge | Premium/Ultimate — but **works on Free** (verified 2026-08-11) | Premium/Ultimate; Free behaviour **unmeasured**, see below |

`name` on a group-level entry is a *deployment tier*: `production`, `staging`,
`testing`, `development` or `other`. GitLab's rationale is that "a group may
consist of many project environments that have unique names", so name-keying does
not scale across a group. The bodies are otherwise the same shape, which is why
one struct decodes both — and why mixing them up is easy. Recorded as
`group-protected-environments.json`:

```json
[{"name": "production",
  "deploy_access_levels": [{"access_level": 40, "access_level_description": "Maintainers", "…": "…"}],
  "required_approval_count": 0,
  "approval_rules": [{"access_level": 40, "required_approvals": 1, "…": "…"}]}]
```

The matching key on the other side is the environment's own `tier`, which
`GET /projects/:id/environments` already returns. GitLab derives it from the name
when it can but it is settable independently — both were created live to confirm:

```json
[{"id": 39113195, "name": "production", "tier": "production", "state": "available"},
 {"id": 39113196, "name": "gprd",       "tier": "production", "state": "available"}]
```

### The finding: inherited protection is NOT returned

**A parent group's protected environment governs projects in its subgroups —
GitLab's docs say a subgroup "cannot override it" — but the subgroup's own
endpoint does not report it.** Measured against a subgroup created under
`qloud-ltd-group` while the parent's `production` entry was live:

```
GET /groups/qloud-ltd-group/protected_environments                 → [{"name":"production",…}]
GET /groups/qloud-ltd-group%2Fpe-inherit-probe/protected_environments → []
```

So a collector that queries only the project's own namespace reproduces exactly
the false fail it set out to remove, one level down. `envseparation` walks the
namespace and every ancestor path instead. That walk needs no hierarchy
discovery call: `scope.Org` already IS the full namespace path, so the ancestors
are its path prefixes.

### What could not be measured, and what that forced

**The Free-tier behaviour of `GET /groups/:id/protected_environments` is
unknown.** There was no Free group to ask: the only accessible group is the
Ultimate-trial one, projects under `sioakeim` are in a *personal namespace*
(`/groups/sioakeim` → **404 Group Not Found**, so there is no group to query at
all), and creating a throwaway Free top-level group was refused —
`POST /groups` → **403**. Whether Free answers 403 like the REST security
endpoints in §1, or 200 `[]` like the project-level list that also carries a
Premium badge, is untested. Do not assume either.

That gap is the reason a failed group read does **not** become `not-checkable`,
which is otherwise this codebase's rule for tier-gated endpoints
(`ErrTierGated`). That rule protects a check whose *only* evidence is gated;
here it is not — project-level protected environments work on Free, so the fail
stays entitled and actionable. If Free does 403, treating that as
`not-checkable` would silently retire C03's two protection checks for the
majority audience. The blind spot is disclosed in the Reason instead.

**404 is NOT uniformly "no group exists."** GitLab is documented elsewhere in
this codebase (`internal/collect/gitlab/client.go`) as inconsistent about which
status code hides a group's existence from a token that can't see it — some
Premium endpoints 403, some 404. Whether that's true for THIS endpoint on Free
was never measured (see above). What's structurally provable, independent of
that gap: GitLab does not allow subgroups under a personal namespace, so if the
project's own namespace is nested (`a/b`), every ancestor path in the walk —
including the top-level one — is provably a real group, and a 404 anywhere in
that walk can only mean refused/hidden, never absent. The collector discloses
a 404 as a blind spot in that case, the same as a 403. Only for a project
directly in a single-segment namespace (the common personal-namespace case,
where there's exactly one path to check) does a 404 stay genuinely ambiguous
between "no group at all" and "a hidden top-level group" — and stays silent
there, rather than caveat the large majority of real fails on an unresolvable
distinction.

### Recreating this state

Everything below was deleted after capture; the group, the subgroup and the two
environments are gone. To rebuild it (needs Maintainer+ and a Premium/Ultimate
group — the trial ends **2026-09-08**):

```bash
curl -X POST -H "PRIVATE-TOKEN: $T" -H 'Content-Type: application/json' \
  "$API/groups/$GID/protected_environments" \
  -d '{"name":"production","deploy_access_levels":[{"access_level":40}],
       "approval_rules":[{"access_level":40,"required_approvals":1}]}'
curl -X POST -H "PRIVATE-TOKEN: $T" -H 'Content-Type: application/json' \
  "$API/projects/$PID/environments" -d '{"name":"gprd","tier":"production"}'
```

Teardown is `DELETE /groups/$GID/protected_environments/production` and, for an
environment, a `POST …/environments/:id/stop` before `DELETE …/environments/:id`.
