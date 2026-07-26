#!/usr/bin/env bash
# hack/check-examples-drift_test.sh — regression test for
# check-examples-drift.sh: proves it passes on a genuinely up-to-date pack
# and fails, loudly and with the right message, on each way a pack can go
# stale. Doesn't test whether `attestward report` renders correctly —
# that's report_test.go's job — only that this script's own checks work.
# Uses copies of the real examples/demo-org-pack/evidence.json as input
# rather than a hand-crafted fixture, so this test never needs its own
# schema-currency upkeep as the evidence-pack schema evolves.
#
# Wired into ci.yaml's `test` job, same as fetch-drift-baseline_test.sh —
# pure local rendering and diffing, no live network calls. Depends on
# `jq`, same as check-examples-drift.sh itself now does.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
target="$script_dir/check-examples-drift.sh"

cd "$repo_root"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# newFixture builds a fresh, genuinely-current fixture pack at $1 from the
# real example pack's evidence.json (plus its sidecar — every case below
# except "sidecar missing" itself needs it present, since that check now
# runs before anything else) and renders it once to get guaranteed-correct
# report.md/report.html/poam.md.
newFixture() {
  mkdir -p "$1"
  cp examples/demo-org-pack/evidence.json "$1/evidence.json"
  cp examples/demo-org-pack/evidence.json.sha256 "$1/evidence.json.sha256"
  go run ./cmd/attestward report "$1/evidence.json" --out "$1" >/dev/null
}

fail=0

# Case 1: a pack whose rendered files genuinely match its evidence.json
# must pass.
fixture1="$work/case1"
newFixture "$fixture1"
out1="$work/case1.out"
if ! "$target" "$fixture1" >"$out1" 2>&1; then
  echo "FAIL: up-to-date fixture reported as drifted:"
  cat "$out1"
  fail=1
fi

# Case 2: a pack whose rendered report.html no longer matches its
# evidence.json — the exact #200/#212 shape (template/renderer changed,
# the example wasn't regenerated) — must fail, loudly, and say so.
fixture2="$work/case2"
newFixture "$fixture2"
echo "<!-- drift -->" >>"$fixture2/report.html"
out2="$work/case2.out"
if "$target" "$fixture2" >"$out2" 2>&1; then
  echo "FAIL: stale fixture (report.html mutated) reported as up to date"
  fail=1
elif ! grep -q "stale" "$out2"; then
  echo "FAIL: stale fixture's error output doesn't say it's stale:"
  cat "$out2"
  fail=1
fi

# Case 3: a missing rendered file (e.g. poam.md never committed) must
# fail too, distinctly from a content mismatch — diff -r reports this as
# "Only in <dir>: poam.md" rather than a content hunk, so check for the
# filename rather than a specific "is missing" phrasing this script no
# longer produces itself (issue #230's N6: the render-diff moved from a
# hardcoded per-file loop to `diff -r -x`).
fixture3="$work/case3"
newFixture "$fixture3"
rm "$fixture3/poam.md"
out3="$work/case3.out"
if "$target" "$fixture3" >"$out3" 2>&1; then
  echo "FAIL: fixture with poam.md missing reported as up to date"
  fail=1
elif ! grep -q "poam.md" "$out3"; then
  echo "FAIL: missing-file output doesn't mention poam.md:"
  cat "$out3"
  fail=1
fi

# Case 4 (issue #230's N2): a pack whose recorded mapping_versions no
# longer match the current mappings/*.yaml must fail with a message
# telling the reader to re-scan — NOT the generic "run make examples"
# advice, which would bake a mapping-version-mismatch banner into all
# three files instead of fixing anything.
fixture4="$work/case4"
newFixture "$fixture4"
jq '.mapping_versions.ssdf = "99.0.0"' "$fixture4/evidence.json" >"$fixture4/evidence.json.new"
mv "$fixture4/evidence.json.new" "$fixture4/evidence.json"
out4="$work/case4.out"
if "$target" "$fixture4" >"$out4" 2>&1; then
  echo "FAIL: mapping-version-mismatched fixture reported as up to date"
  fail=1
elif ! grep -q "re-scan" "$out4"; then
  echo "FAIL: mapping-version-mismatch output doesn't say to re-scan:"
  cat "$out4"
  fail=1
fi

# Case 5 (issue #230's N3): a pack whose check_id set no longer matches
# the current registry (a check was added/removed since capture) must
# fail — this is the "add a check to the registry and the rendered
# output doesn't change" gap the render-diff alone can't catch, since
# buildContext only ever iterates results the pack already has.
fixture5="$work/case5"
newFixture "$fixture5"
jq '.results |= map(select(.check_id != "C01.org.2fa-required"))' "$fixture5/evidence.json" >"$fixture5/evidence.json.new"
mv "$fixture5/evidence.json.new" "$fixture5/evidence.json"
out5="$work/case5.out"
if "$target" "$fixture5" >"$out5" 2>&1; then
  echo "FAIL: check_id-mismatched fixture reported as up to date"
  fail=1
elif ! grep -q "check_id set" "$out5"; then
  echo "FAIL: check_id-mismatch output doesn't name the coverage gap:"
  cat "$out5"
  fail=1
fi

# Case 6 (issue #230's N6): a missing evidence.json.sha256 sidecar must
# fail rather than pass silently — examples/README.md documents it as
# what `attestward verify` checks against.
fixture6="$work/case6"
newFixture "$fixture6"
rm "$fixture6/evidence.json.sha256"
out6="$work/case6.out"
if "$target" "$fixture6" >"$out6" 2>&1; then
  echo "FAIL: fixture with a missing sidecar reported as up to date"
  fail=1
elif ! grep -q "evidence.json.sha256" "$out6"; then
  echo "FAIL: missing-sidecar output doesn't name the missing file:"
  cat "$out6"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "check-examples-drift.sh: all scenarios passed"
