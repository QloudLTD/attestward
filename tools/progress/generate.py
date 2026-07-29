#!/usr/bin/env python3
"""Regenerate tools/progress/index.html from live GitHub issue state.

Local dev convenience only — not part of the shipped attestward product, not hosted.
Run with no arguments: `python3 tools/progress/generate.py` (or `make progress`).
Requires `gh` authenticated against sioakim/attestward.
"""
import html
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = "sioakim/attestward"

# Mirrors the phase breakdown in the v0.1 epic (issue #1) — the only place this
# exact grouping is still hand-maintained, since CLAUDE.md's own copy was cut in
# issue #276. Update here when issue scope changes.
PHASES = [
    ("Phase 0 — Skeleton", [2, 3, 4]),
    ("Phase 1 — Model + mappings", [5, 6, 7, 8]),
    ("Phase 2 — Foundation + collectors C01-C04", [9, 10, 11, 12, 13, 14, 15]),
    ("Phase 3 — Collectors C05-C07", [16, 17, 18, 19]),
    ("Phase 4 — Collectors C08-C10 + self-attestation", [20, 21, 22, 23]),
    ("Phase 5 — Outputs + integrity", [24, 25, 26, 27, 28]),
    ("Phase 6 — Polish & launch", [29, 30, 31, 32, 33]),
    ("Post-v0.1 (seams only, not built yet)", [34, 35, 36]),
    ("Meta / dev tooling", [1, 37]),
]

OUT_PATH = Path(__file__).parent / "index.html"


def fetch_issues():
    raw = subprocess.run(
        [
            "gh", "issue", "list", "--repo", REPO, "--state", "all", "--limit", "200",
            "--json", "number,title,state,labels,url",
        ],
        check=True, capture_output=True, text=True,
    ).stdout
    return {issue["number"]: issue for issue in json.loads(raw)}


def render_issue_row(issue_num, issues):
    issue = issues.get(issue_num)
    if issue is None:
        return f'<tr class="missing"><td>#{issue_num}</td><td colspan="3">not found</td></tr>'
    state = issue["state"]  # OPEN | CLOSED
    badge_class = "closed" if state == "CLOSED" else "open"
    labels = ", ".join(l["name"] for l in issue["labels"])
    title = html.escape(issue["title"])
    return (
        f'<tr>'
        f'<td class="num"><a href="{issue["url"]}">#{issue_num}</a></td>'
        f'<td class="title">{title}</td>'
        f'<td class="labels">{html.escape(labels)}</td>'
        f'<td><span class="badge {badge_class}">{state.lower()}</span></td>'
        f'</tr>'
    )


def render_phase(name, numbers, issues):
    done = sum(1 for n in numbers if issues.get(n, {}).get("state") == "CLOSED")
    total = len(numbers)
    rows = "\n".join(render_issue_row(n, issues) for n in numbers)
    return f"""
    <section class="phase">
      <h2>{html.escape(name)} <span class="count">{done}/{total}</span></h2>
      <table>
        <thead><tr><th>Issue</th><th>Title</th><th>Labels</th><th>Status</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"""


def render(issues):
    all_numbers = [n for _, nums in PHASES for n in nums]
    done = sum(1 for n in all_numbers if issues.get(n, {}).get("state") == "CLOSED")
    total = len(all_numbers)
    pct = round(100 * done / total) if total else 0
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    phases_html = "\n".join(render_phase(name, nums, issues) for name, nums in PHASES)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>attestward build progress</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; line-height: 1.4; }}
  h1 {{ margin-bottom: 0.25rem; }}
  .meta {{ color: #888; font-size: 0.85rem; margin-bottom: 1.5rem; }}
  .progress-bar {{ background: #ddd; border-radius: 6px; height: 20px; overflow: hidden; margin: 1rem 0 2rem; }}
  @media (prefers-color-scheme: dark) {{ .progress-bar {{ background: #333; }} }}
  .progress-fill {{ background: #2563eb; height: 100%; text-align: right; color: white; font-size: 0.75rem; line-height: 20px; padding-right: 6px; box-sizing: border-box; white-space: nowrap; }}
  .phase {{ margin-bottom: 2rem; }}
  .phase h2 {{ font-size: 1.05rem; border-bottom: 1px solid #ccc; padding-bottom: 0.3rem; }}
  .count {{ font-weight: normal; color: #888; font-size: 0.85rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  td, th {{ text-align: left; padding: 4px 8px; vertical-align: top; }}
  thead th {{ color: #888; font-weight: normal; font-size: 0.8rem; }}
  tbody tr:nth-child(odd) {{ background: rgba(128,128,128,0.06); }}
  .num a {{ text-decoration: none; }}
  .labels {{ color: #888; font-size: 0.8rem; }}
  .badge {{ padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; }}
  .badge.open {{ background: #fde68a; color: #713f12; }}
  .badge.closed {{ background: #bbf7d0; color: #14532d; }}
  .missing td {{ color: #b91c1c; font-style: italic; }}
</style>
</head>
<body>
  <h1>attestward build progress</h1>
  <div class="meta">Generated {generated_at} from live GitHub issue state (<code>tools/progress/generate.py</code>) — local view only, not hosted.</div>
  <div class="progress-bar"><div class="progress-fill" style="width:{pct}%">{done}/{total} ({pct}%)</div></div>
  {phases_html}
</body>
</html>
"""


def main():
    issues = fetch_issues()
    OUT_PATH.write_text(render(issues))
    all_numbers = [n for _, nums in PHASES for n in nums]
    done = sum(1 for n in all_numbers if issues.get(n, {}).get("state") == "CLOSED")
    print(f"Wrote {OUT_PATH} ({done}/{len(all_numbers)} issues closed)", file=sys.stderr)


if __name__ == "__main__":
    main()
