# Open Decisions

Undecided questions requiring the owner's call. Once resolved: record the outcome here
(or as an ADR if architectural), and act on it. Resolved items move to the bottom table.

## Open

| # | Question | Notes | Blocking |
|---|---|---|---|
| D2 | **Logo / visual identity** | Needed for README/report header at launch, not before. | Phase 6 |
| D3 | **Launch channels** | HN/Show HN, r/netsec, compliance communities, direct outreach to small federal vendors? | Phase 6 |
| D7 | **Repo visibility timing** | Repo starts private; not yet decided when to flip public. CodeQL (`.github/workflows/codeql.yaml`) and `dependency-review-action` are both removed — GHAS-gated, unavailable on a private repo without it; re-add either once public or GHAS is purchased. `C06.sca.dependency-review` stays an accepted `verified-fail` gap on this repo's own self-scan until then. | Phase 1–2, #32 |

## Resolved

| # | Decision | Outcome | Where |
|---|---|---|---|
| — | Language / distribution | Go, single static binary | [ADR-0002](docs/adr/0002-go-single-static-binary.md) |
| — | Mapping strategy | Data-driven YAML | [ADR-0003](docs/adr/0003-mappings-as-data.md) |
| — | Telemetry / write ops | None, ever | [ADR-0004](docs/adr/0004-read-only-local-first.md) |
| D6 | Release signing key management | Cosign **keyless** (Sigstore/Fulcio OIDC via GitHub Actions' ambient `id-token`). | Issue #4, `.goreleaser.yaml`, SECURITY.md |
| D5 | Demo org name + fixture repo naming | [Qloud-LTD](https://github.com/Qloud-LTD) org. Repos: `demo-good` (C01–C04 controls on), `demo-bad` (deliberately misconfigured). | Issue #15, `hack/demo-org-setup.sh` |
| D8 | Demo release signed-tag key management | A dedicated Ed25519 SSH key (not the owner's personal identity) signs `demo-good`'s C07 fixture release tags. Stored in 1Password (`Clawdbot` vault); public key registered as a GitHub `ssh_signing_key`. Separate from D6: this is git-tag signing (SSH), not artifact signing (cosign). | Issue #19, `hack/demo-org-setup.sh`, `fixtures.yaml` |
| D9 | `docs/checks-reference.md` timestamp vs. determinism | No wall-clock timestamp in the generated header (would break CI's byte-diff drift check); freshness signal is each mapping's own `version`/`retrieved` fields instead. | Issue #30, `internal/checksref` |
| D10 | This repo's own default-branch review requirement vs. admin bypass | `required_approving_review_count` = 1 on the `main` ruleset; Admin-role "always" bypass actor deliberately kept (solo-maintainer repo, no second reviewer). `C02.branch.admin-enforced` stays `partial` as a result. | Issue #105 |
| D11 | This repo's own audit-log export fallback | No real export destination exists; `SA.audit-log-export-fallback` answered "no" in `self-attestation.yaml`. | Issue #106, `self-attestation.yaml` |
| D1 | Final product name | **Attestward.** Repo, Go module path, and CLI binary all renamed to match (`sioakim/attestward`, private per D7); domain `attestward.com` registered. A self-serve availability screen found no existing company/product/trademark using the name anywhere; formal USPTO/WIPO clearance is deliberately deferred until shortly before public launch, not done now. | Issue #33, `sioakim/ssdf-website`'s `CLAUDE.md` |
| D4 | Hosted-tier boundary | Anything a single local scan produces stays free/OSS forever; anything requiring a server, persistent storage, or multi-tenancy is the separate commercial hosted product (ADR-0004 rules those out of the free CLI). Free forever: all ten collectors, the full evidence pack, pack integrity, self-attestation, every mapping. Hosted (v1.0 milestone): #121–#126. | Issue #33, #121–#126 |
