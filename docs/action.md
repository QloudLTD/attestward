# The Attestward GitHub Action

`action.yml` at the root of this repository is a composite GitHub Action that runs a
read-only Attestward scan in your own CI using a pinned, cosign-verified release binary.

> **Moved here in 2026-07.** It previously lived in a separate `sioakim/attestward-action`
> repository. That repo is gone; reference this one instead. The action is versioned with
> the tool it runs, which is what you want — the `version:` input pins the scanner
> release, and the `uses:` ref pins the action itself.

Runs [Attestward](https://gitlab.com/sioakeim/attestward) — the read-only CLI that
*verifies* (rather than asks about) the technical controls behind the CISA SSDA form —
inside your own CI, and turns one-shot scans into ongoing assurance:

- **Verified binary, always.** The action downloads the exact release version you pin,
  checks the cosign keyless signature over `checksums.txt` against the Attestward
  release workflow's identity, and checks the archive hash — before running anything.
  A failed verification fails the step; nothing unverified ever executes.
- **Evidence pack per run.** `evidence.json` (+ `report.md`, `report.html`, `poam.md`)
  written into your workspace for you to store however you like — artifact, release
  asset, or both. Everything runs in *your* CI with *your* storage; nothing leaves.
- **Drift detection.** Give it a baseline pack and it runs `attestward diff`: the step
  fails only when verified posture actually *regressed* — coverage changes (token or
  plan capability) and checker changes (new tool version) are reported separately,
  never conflated with drift.

## Quickstart: scan on every release

```yaml
name: Attestward
on:
  release:
    types: [published]

permissions:
  contents: write   # read for the scan; write only for attach-to-release

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: sioakim/attestward@<pinned-sha> # pin a SHA, not a tag
        with:
          version: "0.1.0"
          org: your-org
          repos: |
            your-repo
          attach-to-release: "true"
```

`attach-to-release` uploads `evidence.json` + `report.html` as assets of the
triggering release — the recommended durable baseline location (workflow artifacts
expire; release assets don't).

## Scheduled drift detection

```yaml
name: Attestward drift
on:
  schedule:
    - cron: "0 6 * * 1"

permissions:
  contents: read

jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - name: Fetch baseline from the latest release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release download --repo ${{ github.repository }} \
            --pattern evidence.json --dir baseline
      - uses: sioakim/attestward@<pinned-sha>
        id: attestward
        with:
          version: "0.2.0"          # drift mode needs >= 0.2.0 (attestward diff)
          org: your-org
          repos: |
            your-repo
          baseline: baseline/evidence.json
```

The step fails when (and only when) the diff finds regressions; the rendered delta
lands in the job's step summary and at `steps.attestward.outputs.drift-summary-path`.

To keep a single rolling drift issue instead of a red run, set
`fail-on-drift: "false"` and act on the outputs:

```yaml
      - name: Upsert drift issue
        if: steps.attestward.outputs.drift == 'true'
        env:
          GH_TOKEN: ${{ github.token }}   # needs issues: write
        run: |
          # Create the label once — gh issue create errors on a label
          # that doesn't exist yet (gh issue list on one is fine, empty).
          gh label create attestward-drift --repo ${{ github.repository }} \
            -c d93f0b -d "Attestward detected posture drift" 2>/dev/null || true
          existing=$(gh issue list --repo ${{ github.repository }} \
            --label attestward-drift --state open --json number --jq '.[0].number // empty')
          if [ -n "$existing" ]; then
            gh issue comment "$existing" --repo ${{ github.repository }} \
              --body-file "${{ steps.attestward.outputs.drift-summary-path }}"
          else
            gh issue create --repo ${{ github.repository }} \
              --title "Attestward: posture drift detected" --label attestward-drift \
              --body-file "${{ steps.attestward.outputs.drift-summary-path }}"
          fi
```

## Inputs

| Input | Default | Purpose |
|---|---|---|
| `version` | (required) | Attestward release to run, without the leading `v`. Deliberately pinned — bumping the scanner is a reviewed change. Drift mode needs >= 0.2.0. |
| `org` | (required) | Account to scan (org or personal user account). |
| `repos` | all visible | Repos to scan, one per line. |
| `token` | `github.token` | Token the scan reads with. The default gives honest-degradation coverage (checks its permissions can't reach report `not-checkable`, never a fake pass); see Attestward's README token table for deeper coverage via a fine-grained PAT. |
| `self-attestation-file` | — | Self-attestation answers YAML, if you keep one. |
| `out` | `evidence` | Output directory for the pack. |
| `baseline` | — | Baseline `evidence.json` to diff against; enables drift mode. |
| `fail-on-drift` | `true` | Fail on regressions against the baseline. |
| `fail-on-gaps` | `false` | Fail when the scan itself finds gaps (exit 2). Off by default: gaps are a result to publish; drift is the alarm. |
| `attach-to-release` | `false` | On release events, upload `evidence.json` + `report.html` to the triggering release (needs `contents: write`). |

## Outputs

| Output | Meaning |
|---|---|
| `pack-path` | Path to the written `evidence.json`. |
| `scan-exit-code` | `0` clean, `2` gaps found. |
| `drift` | `"true"` when drift mode ran and found regressions. |
| `drift-summary-path` | Rendered Markdown delta (empty when drift mode is off). |

## Trust model

- The Attestward **binary never writes** to any platform API — its HTTP transport
  rejects non-GET/HEAD methods outright
  ([ADR-0004](adr/0004-read-only-local-first.md)).
  The only writes continuous mode involves (release-asset upload, an optional drift
  issue) happen in workflow steps you can read above, under permissions you grant
  explicitly.
- Every third-party action this action `uses:` is pinned by commit SHA, and the
  attestward binary is pinned by version + signature + hash — the same bar Attestward's
  own C08 checks hold your workflows to.


## License

Apache-2.0. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
