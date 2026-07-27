# Progress narrative

> **Archived.** Relocated from `CLAUDE.md`'s own "Progress tracker" section when issue
> #276 cut that section: a hand-maintained mirror of GitHub issue state, updated
> checkbox-by-checkbox in the same PR/commit that closed each issue — the exact shape
> that reliably drifted (found first by issue #260's own audit of `docs/threat-model.md`,
> then again in the tracker itself, the day #276 was filed). Current status for any
> issue is the [issue tracker](../../../issues) or `python3 tools/progress/generate.py`'s
> live dashboard, never this file — both pull from GitHub directly and can't go stale
> the way a hand-typed checkbox can. Kept for historical/narrative context only: the
> texture below (review rounds, live-verification steps, bugs found and fixed along the
> way) isn't reconstructible from issue titles and state alone. Do not update this
> file; open or edit issues instead.

## v0.1 — GitHub-only evidence engine (2026-07-21)

Phases 0–6, tracked under the [v0.1 epic (#1)](../../../issues/1) — #2 through #33 all
closed. A few worth more than a bare checkbox: #25 (report.md/html renderers) closed
only once non-engineer sign-off was complete, not just when the code compiled; #31
(threat model finalization) added a runtime read-only guard, a claim-by-claim audit
against the actual codebase, and an external-reader sign-off, not just a document
pass; #32 (self-scan workflow + badge) was verified live — a clean run, then a
deliberate-red/revert test to prove the badge actually reacts to drift, not just that
the YAML parses; #33 (launch checklist) validated the release path itself via a
disposable `v0.1.0-rc.1` tag, deleted, before `v0.1.0` was tagged and cosign-verified
from an independent machine.

## v0.2 — Azure DevOps + continuous mode (2026-07-22 to -23)

**Continuous mode (#36).** `attestward diff` shipped in v0.2.0 (#143/#144/#145); the
action that consumes it lives in the separate
[attestward-action](https://github.com/sioakim/attestward-action) repo (ADR-0007's
write boundary), v1.0.0. Self-scan migrated as its first consumer (#147), with a drift
baseline attached to the v0.2.0 release. That first live run correctly caught two real
gaps: no SAST tool covered releases (#157), and release tags weren't signed (#158,
needing a signing-identity decision) — both since fixed.

**Azure DevOps epic (#34).** Stories S1–S9 all shipped (#148–#156): all ten collectors
live on both platforms, 94 registered checks, across 18 collector-phase PRs each
through independent session-level review. S9 (#155) delivered
`hack/demo-ado-setup.sh` proven live against dev.azure.com/seciq — found and fixed 5
real bugs across two review rounds — with the definitive 81-result fixture capture
landing in `fixtures-ado.yaml` and `TestIntegration_ADODemoOrgMatchesFixtures` passing
live against the real org. Of the epic's six review-spawned follow-ups, five closed
alongside it (#166, #176, #178, #179, #184); #181 (secret-hygiene regex v2) was left
open as ordinary low-priority backlog, not a gate on the epic itself.

## Hosted-tier placeholders, re-filed (2026-07-24 to -26)

This repo originally held six placeholder issues for the commercial hosted tier
(DECISIONS.md D4) — #121–#126. One, #121 (portfolio dashboard), was actually
delivered — live at attestward.com/app, built as `attestward-cloud`'s own story S4.
The other five were closed `NOT_PLANNED` and re-filed as their own stories under
`attestward-cloud`'s epic #11 instead of being built here: S8 export/retention (drift
tracking itself had already shipped separately, in cloud S5), S7 team
collaboration/POA&M, S10 RSAA-ready packaging (still research-first), S9 org SSO, S6
managed continuous mode. Hosted-tier status now lives entirely in `attestward-cloud`,
not here — nothing hosted-tier is open in this repo anymore.
