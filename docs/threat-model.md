# Threat Model

Status: living document — seeded before implementation, finalized in Phase 6
(see the launch-readiness issue). This tool runs inside security-sensitive
organizations; its own security posture is a feature.

## What the tool is

A local, read-only CLI that queries source-control APIs with a user-supplied token and
writes evidence files to a user-chosen local directory. No server component, no database,
no telemetry, no network destinations other than the platform API (api.github.com in v0.1).

## Assets

| Asset | Sensitivity | Handling |
|---|---|---|
| GitHub token (`GITHUB_TOKEN`) | High — grants org read access | Read from env var only; never persisted, never logged, never included in evidence output |
| Raw API responses | Medium — may contain member lists, security-alert details | Only SHA-256 digests + minimal extracted facts are persisted |
| Evidence pack | Medium — reveals security posture and gaps | Written locally only; user decides distribution; pack hash enables tamper-evidence |
| Self-attestation answers | Medium | Treated as user-authored input, echoed into evidence clearly labeled `self-attested` |

## Trust boundaries

1. **User ↔ tool**: the user supplies the token and config; the tool must honor
   least-privilege guidance (fine-grained PAT, read-only scopes, documented precisely).
2. **Tool ↔ GitHub API**: TLS only; responses are untrusted input — parsed defensively,
   size-limited, never executed or templated into shell commands.
3. **Tool ↔ filesystem**: writes only under the user-specified `--out` directory.

## What the tool never does

- **No write operations** against any API — enforced by review and (where possible) by
  requesting read-only token scopes.
- **No network egress** besides the platform API. No telemetry, no update checks,
  no crash reporting.
- **No credential storage.** Tokens live in the environment for the life of the process.
- **No raw payload retention.** Evidence stores digests and extracted facts, not full
  API responses.

## Threats considered

| Threat | Mitigation |
|---|---|
| Token leakage via logs/output | Central scrubber redacts secret-shaped strings from all log/error paths before emit; evidence stores digests only |
| Malicious/compromised API responses (injection into reports) | HTML renderer escapes all API-derived strings; markdown renderer neutralizes link/script injection |
| Tampered evidence pack after generation | SHA-256 pack hash printed + embedded in report; optional cosign signature |
| Supply-chain attack on the tool itself | Pinned GitHub Actions (SHA), minimal dependency tree, signed releases via goreleaser+cosign, CodeQL on the repo |
| Dependency confusion / typosquatting on install | Official release artifacts with checksums; documented install paths only |
| Over-privileged tokens | README documents minimum fine-grained PAT permissions per collector; scan warns when the token has write scopes (best-effort detection) |

## Residual risks (documented, not hidden)

- The tool cannot verify controls GitHub does not expose via API (e.g., real MFA hardware
  type). Such checks are marked `partial` or `not-checkable`, never inferred.
- A user with a tampered binary defeats pack signing; users should verify release
  signatures/checksums on install.
