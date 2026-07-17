# examples

| File | Purpose |
|---|---|
| `attestor.yaml` | Fully-commented `attestor scan --config` example |
| `demo-org-pack/` | Real `evidence.json` + `report.html` from a live `attestor scan` against the public [Qloud-LTD/demo-good](https://github.com/Qloud-LTD/demo-good) demo repo (see the root README's quickstart) — a genuine mixed pass/fail result, not a cherry-picked all-green run: `demo-good` was originally built as a C01-C04 fixture (issue #15), so several later checks (C05-C10) honestly report real gaps. `evidence.json.sha256` is the sidecar `attestor verify` checks against. |
| `scan-demo.cast` | An [asciinema](https://asciinema.org/) recording of a real `attestor scan` → `attestor verify` → `attestor report` run against the same demo repo — play locally with `asciinema play scan-demo.cast`, or paste it into [asciinema.org](https://asciinema.org/) or an `<asciinema-player>` embed to view in a browser. |

Regenerate the demo pack yourself against the real (public) demo org:

```bash
export GITHUB_TOKEN=<a token with at least public read access>
attestor scan --org Qloud-LTD --repo demo-good --out examples/demo-org-pack/
attestor report examples/demo-org-pack/evidence.json --format html
```
