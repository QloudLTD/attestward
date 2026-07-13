# Project Brief: Open-Source SSDF Evidence Engine

> **Archived.** This was the seed document handed to the build agent; its content is now
> fully captured (with more detail) in [issue #1](../../../issues/1), the v0.1 epic, and
> the issues it links to. Kept for historical/narrative context only — the issues are
> canonical. Do not update this file; open or edit issues instead.

**Working name:** `attestor` (placeholder — final name TBD; check trademark/npm/GitHub availability before publishing)
**License:** Apache-2.0
**Owner:** Spyros / NEFIQ Ltd (US entity to be added later)
**Handoff target:** Claude Code agent (autonomous build with human review at phase gates)

---

## 1. Mission and one-liner

> **Everyone else helps you fill in the CISA attestation form. This tool proves what you're signing.**

Build an open-source CLI tool that connects to a software producer's source-control and CI/CD platform (GitHub first), **verifies** — rather than asks about — the technical controls behind the CISA Secure Software Development Attestation (SSDA) form, maps findings to NIST SSDF (SP 800-218) practices and the form's four practice clusters, and emits a signed, timestamped **evidence pack** (JSON + human-readable report) plus a **gap analysis** and **draft POA&M** for anything that fails.

### Why this exists (context the agent should internalize)

- Software producers selling to US federal agencies must sign the CISA SSDA form. An officer signs **under False Claims Act exposure**. DOJ's Civil Cyber-Fraud Initiative actively prosecutes inaccurate cybersecurity representations.
- The form's attestations map to NIST SSDF practices: secure build environments (separation, MFA, logging, credential encryption), supply-chain/provenance integrity, automated vulnerability checking (SAST/SCA cadence, pre-release checks), and vulnerability disclosure/remediation processes.
- Today's options for the long tail of small federal software vendors: sign-and-hope, or pay a 3PAO consulting firm for a manual assessment. Nothing self-serve verifies the actual pipeline.
- Every existing "compliance automation" competitor primarily *asks questions and stores documents*. This tool's differentiator is **harvested proof**: it reads the real configuration and run history and shows what is actually true.
- Strategic requirement (for the owner's purposes): the project must produce **credible public artifacts** — clean code, serious docs, an ADOPTERS.md, and named-adopter evidence. Quality and professionalism of the repo matter as much as features.

### Product principles (apply to every decision)

1. **Verify, don't ask.** If a control can be checked via API, check it. Questionnaire items are a last resort and must be clearly labeled `self-attested` in output.
2. **Read-only, local-first.** The tool runs on the user's machine or in their CI. It never transmits their data anywhere. Least-privilege tokens only.
3. **Evidence over score.** Primary output is evidence with provenance (what was checked, when, via which API, raw response digest), not a vanity score.
4. **Single static binary.** Zero-friction install: `brew install` / single download / `go install`. No server, no database required for core use.
5. **Mappings are data, not code.** SSDF/CISA-form mappings live in versioned YAML so the community can extend to other frameworks without touching Go.
6. **Boring, auditable code.** This tool will be run inside security-sensitive organizations. Minimal dependencies, no clever magic, everything reviewable.

---

## 2. Scope

### v0.1 (this build) — GitHub only

**Collectors (read-only, GitHub REST + GraphQL APIs):**

| ID | Collector | What it verifies | Maps to |
|----|-----------|------------------|---------|
| C01 | `org-security` | Org-level: 2FA/MFA enforcement, default repo permissions, members without 2FA (count only) | Secure environment / access control (SSDF PO.5, PS.1) |
| C02 | `repo-protection` | Branch protection / rulesets on default + release branches: required reviews, required status checks, force-push/deletion blocks, admin enforcement | Code integrity, separation of duties (PS.1, PW.4) |
| C03 | `env-separation` | GitHub Environments: existence of separated envs (e.g. `production`), protection rules, required reviewers, deployment branch policies | Environment separation (PO.5) |
| C04 | `secrets-hygiene` | Secret scanning + push protection enabled; Dependabot alerts enabled; (Advanced Security features detected where available) | Credential protection (PO.5, PW.4) |
| C05 | `sast-history` | Evidence that SAST runs per release: detect CodeQL / Semgrep / SonarQube / other SAST workflows; pull run history for last N releases; cadence stats | Automated vulnerability checking (PW.7, PW.8, RV.1) |
| C06 | `sca-history` | Evidence of SCA/dependency review: Dependabot config, dependency-review action, Snyk/Trivy/Grype/OSV-scanner workflow detection + run history | Third-party component checking (PW.4, RV.1) |
| C07 | `provenance` | Release artifact integrity: tags signed? releases have checksums/signatures? Sigstore/cosign or SLSA generator workflows present? commit→artifact linkage via workflow provenance | Supply chain / provenance (PS.1, PS.2, PS.3) |
| C08 | `actions-security` | Workflow security posture: actions pinned to SHA vs mutable tags, `GITHUB_TOKEN` default permissions, use of `pull_request_target`, OIDC vs long-lived cloud creds in deploy workflows | Secure build environment (PO.5) |
| C09 | `audit-logging` | Org audit-log availability (Enterprise) or documented fallback; repo webhook/event visibility | Logging/monitoring of trust relationships (PO.5) |
| C10 | `vdp` | Vulnerability disclosure: `SECURITY.md` present with intake channel; private vulnerability reporting enabled on repos | Vulnerability disclosure program (RV.1, RV.2, RV.3) |

**Deliberately self-attested in v0.1** (prompted via a small YAML questionnaire, clearly flagged in output): developer security training, threat modeling practice, documented triage SLAs, notification-of-agencies process. Do not fake verification where none is possible.

**Mapping engine:**
- `mappings/ssdf-800-218.yaml` — SSDF practices/tasks (PO, PS, PW, RV families) with IDs, titles, and which collectors/checks provide evidence.
- `mappings/cisa-ssda-form.yaml` — the form's four practice clusters, each referencing SSDF task IDs. Structure: cluster → SSDF tasks → checks → evidence requirements.
- Every check result rolls up: check → SSDF task → form cluster, with status `verified-pass | verified-fail | partial | self-attested | not-checkable`.

**Outputs:**
1. `evidence.json` — machine-readable full evidence pack: every check, raw evidence digests (hashes of API responses, not full payloads with sensitive content), timestamps, tool version, mapping versions.
2. `report.md` + `report.html` — human-readable: executive summary, per-cluster status, per-check detail with evidence citations, gap list.
3. `poam.md` — draft Plan of Action & Milestones for every `verified-fail`/`partial`: finding, affected SSDF task, suggested remediation, owner/date placeholders.
4. Integrity: the JSON pack is hashed (SHA-256) and the hash printed + embedded in the report; `--sign` flag signs the pack with a user-supplied key (use `sigstore/cosign` sign-blob if available; keep optional).

**CLI UX (cobra):**
```
attestor scan --org my-org [--repo my-repo ...] --out ./evidence/
attestor scan --config attestor.yaml          # repeatable, CI-friendly
attestor report ./evidence/evidence.json      # regenerate reports
attestor checks list                          # show all checks + mappings
attestor version
```
- Config file defines: org, repos in scope (a "product line"), release-tag pattern, lookback window (default: last 5 releases or 12 months), self-attestation answers file.
- Exit codes: 0 all verified-pass; 2 gaps found (for CI usage); 1 execution error.
- `GITHUB_TOKEN` env var; document minimum PAT scopes precisely in README (fine-grained PAT preferred; read-only).

### Explicitly OUT of scope for v0.1
- Azure DevOps, GitLab, Bitbucket collectors (v0.2+; design collector interface so these slot in cleanly).
- Any hosted service, web UI, database, telemetry.
- Auto-remediation or write operations of any kind.
- Filling/submitting the actual CISA form or RSAA integration.
- SBOM generation (integrate/detect existing SBOM workflows only; do not build an SBOM tool).
- Windows-specific build-server analysis, on-prem CI systems.

---

## 3. Architecture & stack

- **Language:** Go (single static binary, standard in security tooling). Go 1.22+.
- **Structure:**
```
/cmd/attestor/            # main
/internal/collect/        # collector interface + github/ implementation
/internal/model/          # evidence, check, finding types (versioned schema)
/internal/mapping/        # YAML loader, rollup logic
/internal/report/         # md/html/poam renderers (go templates)
/internal/integrity/      # hashing, optional cosign signing
/mappings/                # ssdf-800-218.yaml, cisa-ssda-form.yaml
/docs/                    # architecture.md, checks reference (generated), threat-model.md
/examples/                # sample config, sample output (from a public demo org)
/.github/workflows/       # ci.yaml (lint, test, build matrix), release.yaml (goreleaser), self-scan demo
```
- **Key deps (keep minimal):** `google/go-github` + `shurcooL/githubv4`, `spf13/cobra`, `spf13/viper` (or plain YAML via `gopkg.in/yaml.v3`), `goreleaser` for releases. Avoid heavyweight frameworks.
- **Collector interface:** `Collect(ctx, scope) ([]CheckResult, error)` per collector; results are pure data. Platform-specific code stays behind the interface — this is the seam for Azure DevOps/GitLab later.
- **Evidence provenance:** every CheckResult stores: API endpoint(s) called, timestamp, response content digest, and a minimal extracted fact set. Never store tokens; scrub anything secret-shaped defensively.
- **Rate limiting/backoff:** respect GitHub secondary rate limits; parallelize per-repo with a worker pool (default concurrency 4, flag-tunable).

---

## 4. Build phases with acceptance criteria

Work in this order. Each phase ends with passing CI, updated docs, and a tagged pre-release. Ask for human review at each gate.

**Phase 0 — Skeleton (½ day)**
Repo scaffold per structure above; CI (lint: golangci-lint; test; build for linux/mac/windows); goreleaser config; Apache-2.0 LICENSE; README stub with mission + safety posture; CONTRIBUTING.md; SECURITY.md (practice what we preach); ADOPTERS.md stub.
✅ `attestor version` builds and runs on all three platforms via CI artifacts.

**Phase 1 — Model + mappings (1 day)**
Implement evidence/check schema (versioned, JSON-schema published in /docs). Author `ssdf-800-218.yaml` covering the SSDF tasks relevant to the form's clusters (be accurate to SP 800-218 IDs — verify each ID against the official publication; do not invent). Author `cisa-ssda-form.yaml` with the four clusters referencing SSDF tasks. `attestor checks list` renders the full matrix.
✅ Mapping files validate against schema; matrix output reviewed by human for accuracy.

**Phase 2 — Collectors C01–C04 (2 days)**
Org security, branch protection/rulesets, environments, secrets hygiene. Integration tests against a purpose-built public demo org (create fixtures: one "good" repo, one "bad" repo). Unit tests with recorded API fixtures (go-vcr or hand-rolled JSON fixtures).
✅ Scan of demo org produces correct pass/fail on every check; fixtures committed.

**Phase 3 — Collectors C05–C07 (2–3 days, hardest)**
SAST/SCA detection heuristics (workflow file parsing + run history via API; detect the common tools by action name/step patterns; make the tool-signature list data-driven in YAML so new scanners are contributions, not code). Release/provenance checks incl. cosign/SLSA workflow detection and tag-signature verification.
✅ Correctly detects CodeQL and one third-party scanner on fixtures; correctly computes "SAST ran for each of last N releases: true/false"; provenance checks pass on a cosign-signed demo release.

**Phase 4 — Collectors C08–C10 + self-attestation input (1–2 days)**
Actions security posture, audit-log availability, VDP checks. Self-attestation YAML intake with explicit labeling.
✅ Full scan produces a complete evidence.json across all clusters.

**Phase 5 — Reports + POA&M + integrity (2 days)**
Renderers for report.md/html (clean, examiner/lawyer-readable: summary table per cluster, then per-check evidence detail), poam.md, SHA-256 pack hashing, optional cosign sign-blob. Golden-file tests for renderers.
✅ A non-engineer can read report.html and understand posture; POA&M lists every gap with SSDF citation; pack hash reproducible.

**Phase 6 — Polish & launch readiness (1–2 days)**
README rewrite (the sales pitch: problem → FCA stakes → what it verifies → 5-minute quickstart → sample report screenshot); docs/checks-reference generated from mappings; threat-model.md (what the tool accesses, what it never does); demo GIF; `attestor scan` self-scan workflow badge on the repo itself; issue templates ("new check proposal", "new scanner signature").
✅ A cold visitor can go from README to their first evidence pack in <10 minutes with a fine-grained PAT.

**Total estimate: ~10–12 working days of agent time with human review gates.**

---

## 5. Quality bar & working instructions for the agent

- **Accuracy discipline:** SSDF task IDs, form-cluster language, and any regulatory citation in docs must be verified against primary sources (NIST SP 800-218; CISA SSDA form instructions). Where the form's text is paraphrased, mark it as paraphrase. Never invent control IDs.
- **No dark patterns:** no telemetry, no phone-home, no "sign up to see results" in the OSS tool. (A hosted tier comes later, as a separate repo/service.)
- **Tests are not optional:** every collector has fixture-based unit tests; CI runs the demo-org integration scan on a schedule (cron) to catch GitHub API drift.
- **Security posture of the repo itself must be exemplary** — it will be scanned by its own tool publicly: branch protection, signed releases via goreleaser+cosign, pinned actions, CodeQL enabled. The repo is the first case study.
- **Docs style:** plain, precise, no marketing fluff in technical docs; the README may sell, the docs must inform.
- **Commit hygiene:** conventional commits; small PRs per phase; CHANGELOG.md maintained.
- When uncertain between two designs, prefer the one that is simpler to audit.

---

## 6. Post-v0.1 roadmap (do not build now; design seams for it)

1. **v0.2 — Azure DevOps collector** (mirrors C01–C10 semantics; large enterprise + GovTech demand; owner has deep ADO expertise for review).
2. **v0.3 — GitLab collector; SLSA level estimation; VEX awareness.**
3. **Continuous mode** — GitHub Action that runs on release and commits/uploads the evidence pack; drift alerts.
4. **Hosted tier (separate product):** multi-product portfolio dashboard, evidence retention, RSAA-ready packaging, org SSO. Commercial.
5. **Research artifact:** with opt-in from users (explicit consent, aggregate-only), publish "State of SSDF Readiness" findings annually.

---

## 7. Definition of done for the handoff

- Public GitHub repo, Apache-2.0, CI green, v0.1.0 release with signed binaries for linux/amd64+arm64, darwin/amd64+arm64, windows/amd64.
- Demo org with good/bad fixture repos and a linked sample evidence pack in /examples.
- README + checks reference + threat model published.
- Self-scan badge green on the repo.
- Open questions for the human logged in a `DECISIONS.md` (name, logo, launch channels, hosted-tier boundary).
