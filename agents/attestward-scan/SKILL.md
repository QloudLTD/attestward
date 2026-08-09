---
name: attestward-scan
description: Build Attestward from source and run a first evidence scan against a GitHub org/repo or an Azure DevOps project. Use when someone wants to try Attestward, set it up from a clone, produce an evidence pack, or check the technical controls behind a CISA SSDA / NIST SSDF attestation. Handles prerequisites, cloning, building, gathering the platform and token details interactively, running the scan, and interpreting the results.
---

# Build Attestward and run a first scan

Take someone from nothing to a rendered evidence pack. Work through the phases in order —
each one's output is the next one's input — and **ask before assuming** anything you
cannot read off the machine.

## What this tool does, in one line

It queries a source-control platform's API read-only and reports what is *actually*
configured, rather than asking the user to self-certify it. Output is an evidence pack:
`evidence.json` plus rendered `report.md` / `report.html` and a draft POA&M.

---

## Phase 1 — Prerequisites

Check, don't assume. Report anything missing and stop rather than working around it.

```bash
go version    # need 1.25 or newer (go.mod pins go 1.25.0)
git --version
cosign version 2>/dev/null || echo "cosign not installed — optional, only needed for --sign and pack verification"
```

`cosign` is genuinely optional. Do not install it unprompted; only raise it if the user
asks to sign a pack or verify a signed one.

## Phase 2 — Get the source

If the working directory is already an Attestward checkout (there is a `go.mod` with
`module gitlab.com/sioakeim/attestward`), **use it** — do not clone a second copy. Say so.

Otherwise ask where to put it, then:

```bash
git clone https://gitlab.com/sioakeim/attestward.git
cd attestward
```

## Phase 3 — Build

```bash
make build          # or: go build ./cmd/attestward
./attestward version
```

If the build fails, show the real error. The most common cause is a Go version below
1.25 — check `go version` against `go.mod` before looking anywhere else.

There is also a released binary path for users who do not want to build:
`go install gitlab.com/sioakeim/attestward/cmd/attestward@latest`, or a signed archive from
the [releases page](https://gitlab.com/sioakeim/attestward/releases). Mention it if the
build is proving awkward; building from source is the point of this skill, though.

## Phase 4 — Ask what to scan

**This is the part that needs the user.** Ask these together rather than one at a time —
use a multiple-choice question where the options are genuinely closed.

1. **Platform** — `github` (default) or `azuredevops`. One scan covers exactly one
   platform; there is no mixed-platform pack.
2. **Target**
   - GitHub: the **org or personal account** name. A personal account works.
   - Azure DevOps: the **organization** *and* the **project** name (both required).
3. **Scope** — specific repositories, or all of them? Passing no repository scans every
   non-archived, non-fork repo in the account, which on a large org is slow and burns API
   quota. For a first run, **suggest one repository.**
4. **Output directory** — defaults to `./evidence/`. Anything written goes here and
   nowhere else.

### The token

Attestward reads the credential from an environment variable and nothing else. It never
takes a token as a flag, never reads it from a config file, and never writes it anywhere.

| Platform | Variable |
|---|---|
| GitHub | `GITHUB_TOKEN` |
| Azure DevOps | `AZURE_DEVOPS_EXT_PAT` |

**Never ask the user to paste a token into the conversation, and never echo one.** Ask
them to export it in their own shell:

```bash
export GITHUB_TOKEN=...        # in the user's terminal, not yours
```

In Claude Code specifically, they can prefix a command with `!` to run it in the session.

**Least privilege matters here.** A read-only fine-grained PAT is the recommendation, and
the tool prints a warning if the token carries write scopes. Point at the README's
"Required token permissions" table rather than reproducing it — it is long, per-collector,
and honest about which fine-grained categories are unverified.

The practical shape for GitHub: `read:org` for the org-level checks, read access to
repository administration, actions, contents and webhooks for the rest, and
`read:audit_log` (plus org-owner status) for C09. Checks the token cannot satisfy report
`not-checkable` — an honest degradation, **not** a failure, and they do not affect the
exit code.

## Phase 5 — Scan

```bash
# GitHub
./attestward scan --org <account> --repo <repo> --out ./evidence/

# Azure DevOps
./attestward scan --platform azuredevops --org <org> --project <project> --repo <repo> --out ./evidence/
```

Useful flags, all optional:

| Flag | Effect |
|---|---|
| `--repo` | Repeatable. Omit to scan every non-archived, non-fork repo. |
| `--check C01,C05` | Run only these check-ID prefixes. Good for a fast first look. |
| `--config <file>` | YAML config; see `examples/attestward.yaml`. Flags override it. |
| `--lookback-releases` / `--lookback-months` | Release window. Defaults: 5 releases / 12 months. |
| `--release-tag-pattern` | Glob (`filepath.Match`, **not** regex). Default `v*`. |
| `--self-attestation-file` | Answers for the questionnaire items — see `attestward attest init`. |
| `--sign` | Sign `evidence.json` with cosign. Needs cosign on PATH. |
| `--concurrency` | Collector concurrency, default 4. |

## Phase 6 — Read the result

```bash
ls ./evidence/                                    # evidence.json + rendered reports
./attestward report ./evidence/evidence.json      # re-render if needed
```

Open `report.md` (or `report.html`) and walk the user through it. **Explain the statuses
before the findings** — the distinction is the whole point of the tool:

- **verified-pass / verified-fail** — the tool observed this directly through the API.
- **not-checkable** — no API exposes it on this platform, or the token could not reach
  it. Structural on some platforms; never a failure.
- **self-attested** — the user answered it; the tool did not verify it. Always labelled.

Two honest framings worth giving the user unprompted:

- A `verified-fail` is **information, not a verdict**. The gap analysis and draft POA&M
  exist precisely because failures are the expected first-run outcome.
- Coverage is **not symmetric** between GitHub and Azure DevOps, and the gaps are
  structural rather than configurable. `docs/checks-reference.md` records exactly which
  API backs each check, and is generated from the collector registry, so it cannot drift
  from the code.

## Phase 7 — Offer, don't assume

Only if the user wants to go further:

```bash
./attestward attest init                                          # scaffold self-attestation answers
./attestward verify ./evidence/                                   # check pack integrity
./attestward diff <baseline>/evidence.json <current>/evidence.json  # posture drift; exit 2 = regressions
./attestward checks list                                          # every check and what backs it
```

`diff` exits **2** when it finds regressions, with the delta still on stdout — that is the
documented contract, so `set -e` scripts need to handle it deliberately.

---

## Rules

- **Read-only, forever** ([ADR-0004](../../docs/adr/0004-read-only-local-first.md)). The
  tool cannot perform a write against any platform API — a transport-level guard rejects
  any non-`GET`/`HEAD` request before it is sent. Never suggest a workflow that implies
  otherwise.
- **Never handle the user's token.** Do not read it, echo it, write it to a file, or put
  it in a command you run. It lives in their environment.
- **Nothing leaves the machine** except calls to the platform API being scanned (and
  `cosign`, only when explicitly invoked). Say so if the user asks where their data goes —
  there is no server, no database, no telemetry.
- **Do not invent check IDs, SSDF task IDs, or CISA form language.** Every one traces to
  NIST SP 800-218 or the CISA SSDA Common Form. If you need one, read it from
  `mappings/*.yaml` or `docs/checks-reference.md`.
