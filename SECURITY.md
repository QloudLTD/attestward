# Security Policy

This tool is built for security-sensitive environments, and this repo intends to practice
what the tool preaches: branch protection, pinned actions, CodeQL, signed releases — and
the repo publicly scans itself with its own tool.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

- Preferred: [GitHub private vulnerability reporting](../../security/advisories/new)
  ("Report a vulnerability" on the Security tab).
- You will receive an acknowledgment within **3 business days** and a triage decision
  within **10 business days**.

In scope: the CLI, its release pipeline, and anything that could cause the tool to leak
tokens, exfiltrate data, perform write operations, or emit misleading verification results
(a false `verified-pass` is a security issue for this tool — it induces a false attestation).

## Supported versions

Pre-1.0: only the latest release receives fixes.

## Verifying releases

Release binaries are checksummed and cosign-signed (from the first tagged release).
Verification instructions ship in each release's notes.
