# Roadmap

## v0.1 — GitHub-only evidence engine (current)

Full scope in the [product brief](product-brief.md) and tracked in
[GitHub Issues](../../../issues) (see the v0.1 epic). Highlights:

- Collectors C01–C10 against GitHub REST + GraphQL (read-only)
- SSDF SP 800-218 + CISA SSDA form mappings as versioned YAML
- `evidence.json`, `report.md`/`report.html`, `poam.md` outputs
- SHA-256 pack hashing, optional cosign signing
- Signed release binaries for linux/amd64+arm64, darwin/amd64+arm64, windows/amd64

## Post-v0.1 (design seams now, build later)

| Version | Theme |
|---|---|
| v0.2 | **Azure DevOps collector** — mirrors C01–C10 semantics; large enterprise + GovTech demand |
| v0.3 | **GitLab collector; SLSA level estimation; VEX awareness** |
| — | **Continuous mode** — GitHub Action that runs on release, commits/uploads the evidence pack, drift alerts |
| — | **Hosted tier** (separate product/repo, commercial) — portfolio dashboard, evidence retention, RSAA-ready packaging, org SSO |
| — | **Research artifact** — opt-in, aggregate-only annual "State of SSDF Readiness" report |

Nothing in this table is built during v0.1. The only v0.1 obligation is that the collector
interface and mapping schema do not preclude these.
