# Open Decisions

Undecided questions requiring the owner's call. Once resolved: record the outcome here
(or as an ADR if architectural), and act on it. Resolved items move to the bottom table.

## Open

| # | Question | Notes | Blocking |
|---|---|---|---|
| D2 | **Logo / visual identity** | README logo landed (#132, #134 dark-mode variant); still needed for the report header template. | Phase 6 |
| D3 | **Launch channels** | HN/Show HN, r/netsec, compliance communities, direct outreach to small federal vendors? Announcement itself now lands with the v1.0 public flip (D7, #138). | #138 (v1.0) |

## Resolved

| # | Decision | Outcome | Where |
|---|---|---|---|
| — | Language / distribution | Go, single static binary | [ADR-0002](docs/adr/0002-go-single-static-binary.md) |
| — | Mapping strategy | Data-driven YAML | [ADR-0003](docs/adr/0003-mappings-as-data.md) |
| — | Telemetry / write ops | None, ever | [ADR-0004](docs/adr/0004-read-only-local-first.md) |
| D6 | Release signing key management | Cosign **keyless** (Sigstore/Fulcio OIDC via GitHub Actions' ambient `id-token`). | Issue #4, `.goreleaser.yaml`, SECURITY.md |
| D5 | Demo org name + fixture repo naming | [Qloud-LTD](https://github.com/Qloud-LTD) org. Repos: `demo-good` (C01–C04 controls on), `demo-bad` (deliberately misconfigured). | Issue #15, `hack/demo-org-setup.sh` |
| D8 | Demo release signed-tag key management | A dedicated Ed25519 SSH key (not the owner's personal identity) signs `demo-good`'s C07 fixture release tags. Stored in 1Password (`Clawdbot` vault); public key registered as a GitHub `ssh_signing_key`. Separate from D6: this is git-tag signing (SSH, since git has no keyless/OIDC equivalent for tag signing), not artifact signing (cosign, which does). | Issue #19, `hack/demo-org-setup.sh`, `fixtures.yaml` |
| D9 | `docs/checks-reference.md` timestamp vs. determinism | No wall-clock timestamp in the generated header (would break CI's byte-diff drift check); freshness signal is each mapping's own `version`/`retrieved` fields instead. | Issue #30, `internal/checksref` |
| D10 | This repo's own default-branch review requirement vs. admin bypass | `required_approving_review_count` = 1 on the `main` ruleset; Admin-role "always" bypass actor deliberately kept (solo-maintainer repo, no second reviewer). `C02.branch.admin-enforced` stays `partial` as a result. | Issue #105 |
| D11 | This repo's own audit-log export fallback | No real export destination exists — solo-maintainer repo, no SIEM/webhook target to send it to; `SA.audit-log-export-fallback` answered "no" in `self-attestation.yaml`, an accepted, deliberate gap rather than an oversight. | Issue #106, `self-attestation.yaml` |
| D1 | Final product name | **Attestward.** Repo, Go module path, and CLI binary all renamed to match (`sioakim/attestward`, private per D7); domain `attestward.com` registered. A web-search availability screen surfaced no company or product using the name (trademark registers not searched); formal USPTO/WIPO clearance is deliberately deferred until shortly before public launch. | Issue #33, `sioakim/ssdf-website`'s `CLAUDE.md` |
| D4 | Hosted-tier boundary | Anything a single local scan produces stays free/OSS forever; anything requiring a server, persistent storage, or multi-tenancy is the separate commercial hosted product (ADR-0004 rules those out of the free CLI). Free forever: all ten collectors, the full evidence pack, pack integrity, self-attestation, every mapping. Hosted (v1.0 milestone): #121–#126. | Issue #33, #121–#126 |
| D7 | Repo visibility timing | **v0.1.0 ships with the repo private; the public flip lands with v1.0** (owner decision 2026-07-21). The attestward.com website may link the repo before then — those links 404ing for outsiders is accepted. Everything gated on "before public" (runner-trust mitigations from #33/#31, CodeQL + `dependency-review-action` re-add, #29's cold-visitor and legal-sign-off gates, D1's trademark clearance) is collected in #138. Until the flip, `C06.sca.dependency-review` stays an accepted `verified-fail` gap on this repo's own self-scan. | Issue #33, #138 |
