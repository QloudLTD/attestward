# examples

| File | Purpose |
|---|---|
| `attestward.yaml` | Fully-commented `attestward scan --config` example |
| `demo-org-pack/` | Real `evidence.json`, `report.md`, `report.html`, and `poam.md` from a live `attestward scan` against the public [Qloud-ltd-com/demo-good](https://github.com/Qloud-ltd-com/demo-good) demo repo (see the root README's quickstart) — a genuine mixed pass/fail result, not a cherry-picked all-green run: `demo-good` was originally built as a C01-C04 fixture (issue #15), so several later checks (C05-C10) honestly report real gaps. `evidence.json.sha256` is the sidecar `attestward verify` checks against. `make examples-check` (issue #228) guards all three rendered files against drift from `evidence.json` — see that Makefile target's own comment before editing anything here by hand. |
| `scan-demo.cast` | An [asciinema](https://asciinema.org/) recording of a real `attestward scan` → `attestward verify` → `attestward report` run against the same demo repo — play locally with `asciinema play scan-demo.cast`, or paste it into [asciinema.org](https://asciinema.org/) or an `<asciinema-player>` embed to view in a browser. |

Regenerate the demo pack yourself against the real (public) demo org — a full re-scan,
needed whenever the demo repo's own state, `mappings/*.yaml`'s `version:`, or the set of
registered checks has moved since this pack was last captured:

```bash
export GITHUB_TOKEN=<a token with at least public read access>
attestward scan --org Qloud-ltd-com --repo demo-good --out examples/demo-org-pack/
attestward report examples/demo-org-pack/evidence.json
```

`attestward report` with no `--format` renders all three files (`report.md`,
`report.html`, `poam.md`) into `evidence.json`'s own directory by default — passing
`--format html` here, as an earlier version of this file did, regenerates only one of
the three files this pack guards and leaves the other two stale, which is exactly how
`report.html` itself went two releases out of date before issue #228 added a guard for
it. If `evidence.json` itself hasn't changed (a template/renderer change only, not a
live re-scan), use `make examples` from the repo root instead — it's the render-only
equivalent of the second command above, and `make examples-check` is what CI runs to
catch drift in either case.
