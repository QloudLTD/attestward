# ADR-0007: Continuous mode's writes live in workflow steps, never the CLI

**Status:** Accepted · **Date:** 2026-07-22

## Context

Continuous mode (issue #36; the `sioakim/attestward-action` composite action) turns
one-shot scans into ongoing assurance: scan per release, keep the evidence pack, alert
on posture drift. Unlike everything Attestward shipped before it, parts of that loop
are *writes* — uploading a pack as a release asset, opening or updating a drift issue.

[ADR-0004](0004-read-only-local-first.md) commits the tool to performing no write
operation against any platform API, ever, and the GitHub client's transport enforces
that at runtime by rejecting every non-GET/HEAD request. Continuous mode must not
erode that guarantee, in fact or in perception.

## Decision

- **The `attestward` binary stays read-only, forever.** No continuous-mode feature may
  be implemented inside the CLI if it requires a write. `attestward diff` (#143) fits
  this bar: it reads two packs and prints; its exit code is the only signal it emits.
- **Every write continuous mode needs happens in workflow/action steps** — plain,
  auditable `gh` calls in the composite action or the consumer's own workflow — under
  permissions the consumer grants explicitly in their `permissions:` block. The action
  performs exactly one write itself (release-asset upload, opt-in via
  `attach-to-release`, needs `contents: write`); drift-issue upsert is documented as a
  consumer-owned step, not baked into the action.
- **The action must hold the bar C08 checks for**: third-party actions pinned by
  commit SHA, the attestward binary pinned by version and verified (cosign keyless
  signature over `checksums.txt`, then archive hash) before anything executes.

## Consequences

- ADR-0004's grep-the-binary auditability claim survives continuous mode untouched;
  the writes are in YAML a consumer reads in one screen, not in compiled code.
- The action can never gain a convenience feature that quietly needs a write in the
  binary; anything like that lands as a workflow step or not at all.
- Self-scan (`.github/workflows/self-scan.yaml`) is the first consumer of the action
  and the live proof of the split: scan and diff via the read-only binary, asset
  upload via an explicit step with `contents: write`.
