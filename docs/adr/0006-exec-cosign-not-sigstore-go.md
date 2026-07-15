# ADR-0006: Shell out to cosign, don't vendor sigstore-go

**Status:** Accepted · **Date:** 2026-07-15

## Context

Issue #27 needs `attestor scan --sign` to produce a Sigstore signature over `evidence.json`,
and `attestor verify` to check one. Two ways to get there:

1. Vendor `github.com/sigstore/sigstore-go` (or the lower-level `sigstore/cosign` packages)
   and call Sigstore's signing/verification APIs directly from Go.
2. Shell out to the `cosign` CLI (`cosign sign-blob` / `cosign verify-blob`), the way
   `.goreleaser.yaml` already signs release checksums (see that file's `signs:` block).

## Decision

Shell out to `cosign`. `internal/integrity.Signer` wraps `exec.Command("cosign", ...)`
behind a small interface (`SignBlob`/`VerifyBlob`), mockable in unit tests; the real
signing/verification round trip is exercised in CI against the actual binary, not mocked
there.

## Rationale

- **ADR-0002 (single static binary) stays clean.** `sigstore-go` pulls in a real dependency
  tree (Rekor/Fulcio clients, x509/OIDC handling, TUF root management for trust material) —
  vendoring it measurably grows the binary and its supply chain surface for a feature only
  `--sign`/`verify`-on-a-signed-pack users touch. Shelling out keeps that entire tree out of
  `go.sum` and out of every user's binary who never signs anything.
- **This project already has zero involvement in key management**, by design (see the
  issue: "never manage keys ourselves"). `cosign` is the actual key-management surface
  (key files, keyless OIDC, KMS backends, Fulcio/Rekor endpoints) — since attestor never
  touches key material directly either way, there's no correctness reason to reimplement
  cosign's own signing protocol in-process instead of just invoking the binary that already
  implements it correctly and is what every consumer already trusts to verify a `.bundle`.
- **One less thing to keep in sync.** `sigstore-go`'s API and the Sigstore ecosystem's trust
  root format both evolve; pinning a `cosign` binary version (as `.goreleaser.yaml` already
  does for release-checksum signing) is one version number to track, not a Go dependency
  tree plus the trust-root bundle format it expects.
- **Real-world precedent already exists in this repo.** `.goreleaser.yaml`'s `signs:` block
  already shells out to `cosign sign-blob --bundle=... --yes` for release checksums, and
  SECURITY.md documents the matching `cosign verify-blob --bundle ...` command for
  consumers. `attestor scan --sign`/`attestor verify` reuse that exact same invocation
  shape and `--bundle` output format (cosign v3 removed the legacy separate
  `--output-signature`/`--output-certificate` flags — confirmed against the installed
  v3.1.1 binary), rather than inventing a second, inconsistent signing convention within
  the same project.

## Consequences

- `attestor scan --sign` and `attestor verify` (for a signed pack) both require `cosign` on
  `PATH` at runtime — `attestor` itself never signs or verifies anything without it, and
  fails loudly with an install pointer rather than silently skipping signing (issue #27's
  own explicit requirement).
- Signing/verification args are passed through to `cosign` nearly verbatim
  (`--sign-args`/`--verify-args`) rather than exposed as attestor-specific flags — attestor
  doesn't attempt to model cosign's own (large, evolving) flag surface, matching "never
  manage keys ourselves."
- If a future need arises for signing to work with zero external binary dependencies (e.g.
  an air-gapped environment that can't install `cosign` but still needs in-process
  signing), that's a genuinely different feature, not a refactor of this one — revisit with
  its own ADR rather than retrofitting sigstore-go in here.
