#!/usr/bin/env bash
# hack/check-third-party-notices-drift_test.sh — regression test for
# check-third-party-notices-drift.sh: proves it passes on a genuinely
# up-to-date THIRD-PARTY-NOTICES.md and fails, loudly and with a message
# naming the drift, on a hand-edited one. Doesn't re-derive the module
# graph itself — that's gen-third-party-notices.sh's job, exercised here
# only indirectly — this only tests that the diff-and-report wiring
# around it works. Wired into ci.yaml's `test` job, same as
# fetch-drift-baseline_test.sh and check-examples-drift_test.sh — pure
# local generation and diffing, no live network calls.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
target="$script_dir/check-third-party-notices-drift.sh"

cd "$repo_root"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0

# Case 1: a copy of the real, currently up-to-date THIRD-PARTY-NOTICES.md
# must pass.
case1="$work/case1.md"
cp THIRD-PARTY-NOTICES.md "$case1"
out1="$work/case1.out"
if ! "$target" "$case1" >"$out1" 2>&1; then
  echo "FAIL: up-to-date THIRD-PARTY-NOTICES.md reported as drifted:"
  cat "$out1"
  fail=1
fi

# Case 2: a hand-edited copy — the exact failure mode this guard exists
# to catch (a dependency change that never regenerated the file) — must
# fail, and say so.
case2="$work/case2.md"
cp THIRD-PARTY-NOTICES.md "$case2"
echo "hand-edited, not regenerated" >>"$case2"
out2="$work/case2.out"
if "$target" "$case2" >"$out2" 2>&1; then
  echo "FAIL: hand-edited THIRD-PARTY-NOTICES.md reported as up to date"
  fail=1
elif ! grep -q "stale" "$out2"; then
  echo "FAIL: stale file's error output doesn't say it's stale:"
  cat "$out2"
  fail=1
fi

# Case 3: a missing file must fail distinctly, not just diff against
# nothing.
case3="$work/does-not-exist.md"
out3="$work/case3.out"
if "$target" "$case3" >"$out3" 2>&1; then
  echo "FAIL: a missing THIRD-PARTY-NOTICES.md reported as up to date"
  fail=1
elif ! grep -q "not found" "$out3"; then
  echo "FAIL: missing-file output doesn't say so:"
  cat "$out3"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "check-third-party-notices-drift.sh: all scenarios passed"
