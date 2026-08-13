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

### The one exception that makes GraphQL usable

`project.securityScanners.available` is the discriminator, and it is a tier
signal rather than a scan-history signal — it lists what the tier *could* run,
independent of what any pipeline did run:

| Field | Free | Ultimate |
|---|---|---|
| `available` | `[]` | `["SAST","SAST_ADVANCED","SAST_IAC","DAST","DEPENDENCY_SCANNING","CONTAINER_SCANNING","SECRET_DETECTION","COVERAGE_FUZZING","API_FUZZING","CLUSTER_IMAGE_SCANNING"]` |
| `enabled` | `[]` | `["SAST","DEPENDENCY_SCANNING","SECRET_DETECTION"]` |
| `pipelineRun` | `[]` | `["SAST","DEPENDENCY_SCANNING","SECRET_DETECTION"]` |

That three-way split maps almost exactly onto the distinction the checks need:
`available` = tier capability (→ `unsupported` when empty), `enabled` =
configured in CI (→ `C05.sast.tool-configured` / `C06.sca.tool-configured`),
`pipelineRun` = actually executed (→ the `ran-per-release` and `cadence`
checks). Recorded as `graphql-security-scanners-{ultimate,free}.json`.

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
`iid: "3"`.

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
at once, in no guaranteed order. Match on `type`, never on list position.

⚠ **`severity` is capitalised (`"Critical"`, `"High"`, `"Medium"`) in the raw
reports, but SCREAMING_CASE (`"CRITICAL"`) in GraphQL and lowercase
(`"critical"`) in the REST `/vulnerabilities` response.** Three casings for one
concept across three surfaces of the same product. Normalise on ingest.

⚠ **`dependency_files` is absent entirely from the dependency-scanning report**
(the key is `null`, not an empty array — so a `len()` on it reads as 0 and hides
the fact that it was never sent). Gemnasium 6.6.1 emits a CycloneDX SBOM instead
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

## 6. One correction owed to `unsupported.go`

The C06 reason string currently says that on a free project "the API returns
nothing". Measured, REST returns **403**, and it is *GraphQL* that returns
nothing. The distinction is the whole point of the check, so the wording should
be tightened when the C06 collector lands. Left alone here deliberately: this
change is a fixture capture, and rewriting shared reason strings from a
capture branch is how two sessions collide.
