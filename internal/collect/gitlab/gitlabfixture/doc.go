// Package gitlabfixture holds recorded GitLab API responses for testing the
// GitLab collectors without live network calls (CONTRIBUTING.md: "no live
// network calls in go test ./...").
//
// # Why these were recorded, and why they cannot easily be re-recorded
//
// GitLab's security APIs — vulnerability_findings, dependencies, project
// audit_events — are Ultimate-tier features. On a Free project they answer
// 403, and on an entitled project with no scan history they answer 200 with an
// empty array. Neither is a usable fixture: an empty array cannot distinguish
// "parsed correctly" from "parsed nothing".
//
// The responses in testdata/ were captured on 2026-08-10 from a real Ultimate
// project running GitLab's stock Dependency-Scanning, SAST and Secret-Detection
// templates against deliberately outdated dependencies. They contain 10 real
// findings across all three scanners — 2 critical, 3 high, 5 medium — and two
// packages with genuine advisories.
//
// Re-recording requires an entitled namespace, so treat testdata/ as expensive
// to reproduce and do not casually regenerate it.
//
// # The raw scanner reports, added 2026-08-13
//
// gl-sast-report.json, gl-dependency-scanning-report.json,
// gl-secret-detection-report.json and gl-sbom-npm.cdx.json are the artifacts
// the scan jobs themselves wrote — the structured input a collector parses,
// as opposed to GitLab's post-processed view of it. Their counts corroborate
// the API recordings independently: 8 dependency-scanning, 1 SAST, 1 secret.
//
// gl-dependency-scanning-report.json took a detour worth knowing about. The
// jobs API lists it, with its real size, but the artifacts API will not serve
// it: GitLab's stock template declares it only under artifacts:reports:, and
// only artifacts:paths: files reach the downloadable archive. Asking for it
// returns 404, and the ?file_type= parameter that looks like the answer is
// silently ignored rather than rejected. It was recovered by re-declaring it
// under artifacts:paths: on a throwaway branch and re-running the pipeline.
// The practical consequence is in docs/gitlab-security-apis.md: a collector
// cannot expect to read this file from a customer's pipeline, so it is
// recorded for its schema, not as a retrieval path.
//
// # The CI-side recordings, added 2026-08-13
//
// ci-lint-security-templates.json, jobs-security-pipelines.json and
// repository-tree.json were captured for the C05/C06 collectors, from the same
// project, on the same day. Unlike everything above them they are NOT
// Ultimate-tier: GET /ci/lint, GET /jobs and GET /repository/tree all answer
// identically on a free project, which is exactly why three of those
// collectors' checks work on any tier.
//
// ci-lint-security-templates.json is the one worth reading before touching
// internal/collect/gitlab/cihistory. GitLab's stock SAST template declares
// `artifacts: reports: sast:` on twenty-one entries and only eight of them can
// ever run — the other thirteen are hidden anchors (".sast-analyzer",
// ".deprecated-16.8") or entries pinned off with `rules: [{when: never}]` (the
// `sast` configuration-only stub plus ten retired analyzers). A matcher that
// counted the declaration alone would credit every project including the
// template with thirteen scanners it does not have, which is the
// discrimination this fixture exists to pin. Its merged_yaml is TRIMMED, from 27,302 bytes to one entry of
// each kind, and re-serialised by the trimmer rather than kept byte-for-byte;
// the three `exists:` globs GitLab gates its dependency analyzers on are kept
// intact, because cihistory's dependency-manifest table is transcribed from
// them and its own test re-derives the table from this file.
//
// jobs-security-pipelines.json establishes what the run-history walk depends
// on: jobs come back newest-first, each with name/status/finished_at, its
// pipeline's commit SHA, and the artifact file_types it published. user,
// runner, runner_manager and project were dropped, and the commit object cut
// to id/short_id/created_at/title — the same hygiene the audit-event
// recordings got, not the API's shape.
//
// repository-tree.json is small but load-bearing for one specific claim: that
// project's tree holds go.mod AND package-lock.json, while dependencies.json
// reports package-lock.json only. go.mod is correctly not flagged as
// uncovered, because GitLab's own analyzer rule gates on go.sum. That pairing
// is the live cross-check behind C06's manifest-coverage check.
//
// The three GraphQL recordings answer the tier question that REST answers with
// a 403. graphql-security-scanners-free.json is the important one and the
// reason the pair exists: on a Free project GraphQL returns empty arrays and
// no error, structurally identical to an entitled, fully scanned, clean
// project. Only securityScanners.available separates them.
//
// # What was trimmed, and why
//
// The raw findings carry around forty keys each, most of them UI affordances —
// create_jira_issue_url, create_vulnerability_feedback_dismissal_path,
// merge_request_links. Those are kept out: they would bloat the repository and,
// worse, imply the collectors depend on fields they never read. What remains is
// the evidence a collector actually reasons about.
//
// 403-not-entitled.json is the other half of the contract: the tier-gated
// branch is the one that must never turn into a verified-fail.
//
// # What is executed, and what is only staged
//
// These were recorded ahead of the C04-C06 collectors, while an entitled
// namespace was available, because the window to capture them was narrower
// than the window to write the code. For a while nothing read them at all,
// which is worse than having no recordings: they cost real effort to capture,
// they look like coverage in a diff, and they answer no question.
//
// Executed today:
//
//   - vulnerabilities-all-states.json drives IsOpenVulnerability in the parent
//     package, which is where the decision that a dismissed or resolved finding
//     must never count as open is written down and tested.
//
//   - group-protected-environments.json is decoded by
//     internal/collect/gitlab/envseparation through that package's own
//     protectedEnvironment struct, which is the whole point of keeping it: it
//     pins the one thing about the group-level endpoint a reader is likely to
//     get wrong. The entry's "name" is a deployment TIER, not an environment
//     name, so the same struct that decodes the project-level list decodes
//     this one while meaning something different by the same field. Recorded
//     2026-08-13 from a live group-level protected environment created and
//     deleted on gitlab.com/qloud-ltd-group (Ultimate trial).
//
//   - every file here is parsed by TestEveryRecordedFixtureIsReadableAndParses,
//     so a truncated or corrupted capture fails at the commit that made it
//     rather than months later when its collector is finally written.
//
//   - dependencies.json, vulnerabilities-all-states.json,
//     ci-lint-security-templates.json, jobs-security-pipelines.json and
//     repository-tree.json are all driven end to end by
//     internal/collect/gitlab/{cihistory,sasthistory,scahistory} — the C05 and
//     C06 collectors, which landed 2026-08-13. dependencies.json and
//     vulnerabilities-all-states.json in particular are no longer staged:
//     they are the Ultimate-tier halves of C06's two entitled checks.
//
// Staged, not yet executed: vulnerability_findings.json, the four raw scanner
// reports, the three GraphQL recordings, and the two audit-event recordings.
//
// The GraphQL pair is a special case and will probably stay staged: C05 and
// C06 deliberately make no GraphQL call at all, precisely because
// graphql-security-scanners-free.json is what it is — an unentitled project
// answering with empty collections and no error. The recording earns its place
// as the evidence for a road NOT taken, which is why the collectors' own doc
// comments cite it.
//
// The tier-gated 403 path is covered by inline literals in the client and
// repoprotection tests and by internal/collect/gitlab/scahistory's own free-
// tier state, NOT by 403-not-entitled.json — that file is staged too.
//
// # Scrubbing
//
// The audit-event recordings have had author_name, author_email and ip_address
// removed and author_id flattened to 1. GitLab does return those fields; their
// absence here is our hygiene, not the API's shape. A collector author reading
// these should not conclude the fields are unavailable.
//
// gl-secret-detection-report.json has had location.commit.author removed for
// the same reason; its date, message and sha are untouched. The finding it
// carries is over AKIAIOSFODNN7EXAMPLE, which is Amazon's own published
// documentation value and authenticates nothing — it is in the fixture because
// a secret-detection recording with no detected secret evidences nothing.
//
// gl-sast-report.json has scan.primary_identifiers cut from 592 entries to 3.
// That field is the analyzer's catalogue of every rule it knows, not anything
// it found, and it was 72,682 of the report's 104,094 bytes. Three are kept so
// the element shape stays legible. This trim is ours; GitLab sends all 592.
package gitlabfixture
