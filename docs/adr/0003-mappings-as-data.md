# ADR-0003: Compliance mappings are data, not code

**Status:** Accepted · **Date:** 2026-07-13

## Context

The value of the tool depends on accurate, reviewable mappings from technical checks to
NIST SSDF (SP 800-218) tasks and the CISA SSDA form's four practice clusters. Frameworks
evolve (SSDF revisions, form updates, future frameworks like EU CRA), and the set of
detectable scanner tools grows constantly. If these live in Go code, every framework or
scanner addition requires a code change, review by a Go developer, and a release.

## Decision

All mappings live as versioned YAML under `/mappings`:

- `ssdf-800-218.yaml` — SSDF practices/tasks (PO, PS, PW, RV) with IDs verified against
  the official NIST publication; never invented.
- `cisa-ssda-form.yaml` — the form's four clusters, each referencing SSDF task IDs.
- `scanner-signatures.yaml` — detection signatures for SAST/SCA tools (action names,
  step patterns), so supporting a new scanner is a YAML contribution.

Each file carries a `version:` field recorded in every evidence pack. The Go code loads,
validates (against a published schema), and rolls up — it contains no framework knowledge.

## Consequences

- Compliance experts can review and extend mappings without touching Go.
- Evidence packs are reproducible/attributable: pack says exactly which mapping versions
  produced it.
- Requires a schema + CI validation step so malformed community YAML fails fast.
- Slight runtime cost of YAML parsing at startup — negligible.
