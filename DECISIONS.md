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
| D5 | **Demo org name + fixture repo naming** | A public GitHub org with one "good" and one "bad" repo is needed from Phase 2. Name should survive a product rename. | Phase 2 |
| D7 | **Repo visibility timing** | Repo starts private; decide when to flip public (suggested: end of Phase 1, once mappings exist and history is presentable). Note from #3: CodeQL code scanning doesn't actually run until this flips (or GHAS is enabled) — another reason not to push it too far past Phase 1. | Phase 1–2 |

## Resolved

| # | Decision | Outcome | Where |
|---|---|---|---|
| — | Language / distribution | Go, single static binary | [ADR-0002](docs/adr/0002-go-single-static-binary.md) |
| — | Mapping strategy | Data-driven YAML | [ADR-0003](docs/adr/0003-mappings-as-data.md) |
| — | Telemetry / write ops | None, ever | [ADR-0004](docs/adr/0004-read-only-local-first.md) |
| D6 | Release signing key management | Cosign **keyless** (Sigstore/Fulcio OIDC via GitHub Actions' ambient `id-token`) — no key material to manage or leak. Confirmed to fit the goreleaser pipeline (`signs:` block, `id-token: write` in release.yaml). | Issue #4, `.goreleaser.yaml`, SECURITY.md |
