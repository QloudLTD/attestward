# Security Policy

This tool is built for security-sensitive environments, and this repo intends to practice
what the tool preaches: branch protection, pinned actions, signed releases — and the repo
publicly scans itself with its own tool.

> ⚠ The self-scan and release pipelines described below were written for GitHub
> Actions and do not currently run on this host. The workflow definitions are kept
> in `.github/workflows/` as a record of intent; treat any claim below that depends
> on a pipeline having run as unverified until an equivalent exists here.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

- Preferred: [open a **confidential** issue](https://gitlab.com/sioakeim/attestward/-/issues/new) — tick
  **"This issue is confidential"** before submitting, so the report is visible only to
  project members. Do not submit without that box ticked; an untick is a public disclosure.
- You will receive an acknowledgment within **3 business days** and a triage decision
  within **10 business days**.

In scope: the CLI, its release pipeline, and anything that could cause the tool to leak
tokens, exfiltrate data, perform write operations, or emit misleading verification results
(a false `verified-pass` is a security issue for this tool — it induces a false attestation).

## Supported versions

Pre-1.0: only the latest release receives fixes.

## Verifying releases

Every release ships `checksums.txt` (SHA-256 over all archives) plus a keyless cosign
Sigstore bundle (`checksums.txt.bundle`) — no signing key for you to fetch or trust;
verification instead pins the exact GitHub Actions workflow identity and Sigstore's OIDC
issuer. (cosign v2 used separate `.sig`/`.pem` files via `--output-signature`/
`--output-certificate`; cosign v3 removed those flags in favor of one bundle file via
`--bundle` — this command is written for v3, which is what this repo's release pipeline
uses. Install cosign v3+.) Download both files from the release, then:

```bash
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp "^https://gitlab.com/sioakeim/attestward/\.github/workflows/release\.yaml@refs/tags/v.*$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt

# then confirm your downloaded archive's hash is listed:
#   Linux:            sha256sum --ignore-missing -c checksums.txt
#   macOS:             shasum -a 256 --ignore-missing -c checksums.txt
# (--ignore-missing skips the other 4 platforms' archives you didn't download —
# without it, a genuinely valid single-archive download still reports FAILURE.)
```

If `cosign verify-blob` fails, do not run the binary — treat it as untrusted.
