# ADR-0004: Read-only, local-first, zero telemetry

**Status:** Accepted · **Date:** 2026-07-13

## Context

The tool handles an organization's security posture data and runs with a token that can
read the entire org. Target users work in security-sensitive environments where any
write capability, data egress, or phone-home behavior would block adoption outright —
and rightly so. Competing products are hosted services; being local is the trust wedge.

## Decision

- **Read-only:** the tool performs no write operation against any API, ever. Token
  guidance in the README specifies read-only fine-grained PAT permissions.
- **Local-first:** all output is written to a local directory chosen by the user. There
  is no server, no database, no account.
- **Zero telemetry:** no usage analytics, no update checks, no crash reporting, no
  network egress besides the platform API being scanned.

Any future hosted offering is a separate product in a separate repo; this tool never
gains a "sign up to see results" path.

## Consequences

- Auditable claim: reviewers can grep the binary/source for network destinations.
- We get no usage data — adoption is measured via ADOPTERS.md and community signals.
- Drift alerts / continuous monitoring must be implemented as user-controlled CI runs
  (post-v0.1 GitHub Action), not as a service.
