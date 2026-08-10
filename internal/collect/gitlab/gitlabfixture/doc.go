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
// ⚠ Nothing reads these files yet. They were recorded ahead of the C04-C06
// collectors, while an entitled namespace was available, because the window to
// capture them was narrower than the window to write the code. Until those
// collectors land, the 403 path is covered by inline literals in the existing
// tests, not by 403-not-entitled.json.
package gitlabfixture
