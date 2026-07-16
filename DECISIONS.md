# Open Decisions

Undecided questions requiring the owner's call. Once resolved: record the outcome here
(or as an ADR if architectural), and act on it. Resolved items move to the bottom table.

## Open

| # | Question | Notes | Blocking |
|---|---|---|---|
| D1 | **Final product name** | `attestor` is a placeholder. Check trademark, npm, Homebrew, GitHub org/repo availability before any public launch. Repo is private until named. | Phase 6 launch |
| D2 | **Logo / visual identity** | Needed for README/report header at launch, not before. | Phase 6 |
| D3 | **Launch channels** | HN/Show HN, r/netsec, compliance communities, direct outreach to small federal vendors? | Phase 6 |
| D4 | **Hosted-tier boundary** | What stays OSS forever vs. what the commercial hosted product adds (portfolio dashboard, retention, RSAA packaging, SSO). Must be written down before launch to avoid community trust issues. | Pre-launch |
| D7 | **Repo visibility timing** | Repo starts private; decide when to flip public (suggested: end of Phase 1, once mappings exist and history is presentable). The `.github/workflows/codeql.yaml` workflow was removed in Phase 2 (org's plan doesn't include GitHub Advanced Security, so it could never upload results on a private repo) — re-add it once the repo goes public or GHAS is purchased, whichever comes first. | Phase 1–2 |

## Resolved

| # | Decision | Outcome | Where |
|---|---|---|---|
| — | Language / distribution | Go, single static binary | [ADR-0002](docs/adr/0002-go-single-static-binary.md) |
| — | Mapping strategy | Data-driven YAML | [ADR-0003](docs/adr/0003-mappings-as-data.md) |
| — | Telemetry / write ops | None, ever | [ADR-0004](docs/adr/0004-read-only-local-first.md) |
| D6 | Release signing key management | Cosign **keyless** (Sigstore/Fulcio OIDC via GitHub Actions' ambient `id-token`) — no key material to manage or leak. Confirmed to fit the goreleaser pipeline (`signs:` block, `id-token: write` in release.yaml). | Issue #4, `.goreleaser.yaml`, SECURITY.md |
| D5 | Demo org name + fixture repo naming | Reused the owner's existing [Qloud-LTD](https://github.com/Qloud-LTD) org rather than creating a new one — already admin-accessible, Free plan (fine: demo repos are public, so secret scanning/push protection are free regardless of plan per GitHub's 2024+ policy). Repos: `demo-good` (all C01–C04 controls on), `demo-bad` (deliberately off/misconfigured). Only these two new repos were created; the org's 4 pre-existing unrelated public repos under the owner's personal account were explicitly left alone (not transferred). | Issue #15, `hack/demo-org-setup.sh` |
| D8 | Demo release signed-tag key management | A new, dedicated Ed25519 SSH key was generated specifically for signing `demo-good`'s C07 fixture release tags — not the owner's personal signing identity (none existed: no GPG/SSH signing key was configured for git on the owner's machine or registered with their GitHub account before this). The private key is stored in 1Password (`Clawdbot` vault, item "SSH Signing Key — ssdf demo-good release fixture"); the public key is registered as a GitHub `ssh_signing_key` on the owner's account, which is what lets GitHub report `v1.0.0`'s tag signature as verified. Scope is narrow and revocable independently of the owner's other credentials (GitHub Settings → SSH and GPG keys, or `DELETE /user/ssh_signing_keys/{id}`). This is separate from D6: D6 covers *artifact* signing (cosign, keyless); this covers *git tag* signing (SSH, key-based — annotated-tag signing has no keyless/OIDC equivalent in git itself). | Issue #19, `hack/demo-org-setup.sh`, `fixtures.yaml` |
| D9 | `docs/checks-reference.md` generation timestamp vs. determinism | The issue text asks for a "generation timestamp" in the generated file's header; the issue's own acceptance criteria separately require "regeneration is deterministic" so CI's drift check (`attestor checks docs --check`, a plain byte diff) can catch stale docs without false positives. A wall-clock timestamp would make every regeneration differ even with no real change, defeating that check. Resolved in favor of determinism: no wall-clock timestamp is rendered; the header instead cites each mapping's own `version` and `retrieved` fields (already present, source-derived, and only change when the mapping data itself changes) as the freshness signal. Revisit if the owner specifically wants a build-time stamp — that would need CI to exempt a single line from the drift diff, not a hard blocker, just not built speculatively. | Issue #30, `internal/checksref` |
