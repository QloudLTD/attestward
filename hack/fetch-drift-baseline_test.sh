#!/usr/bin/env bash
# hack/fetch-drift-baseline_test.sh — regression test for
# fetch-drift-baseline.sh, run against a fake `gh` so every case is
# exercisable locally/in CI without a real GitHub release. Issue #211's
# whole point is that a broken baseline chain used to look identical to a
# genuine first run (both silently skipped) — this test's central
# assertion is that they're now distinguishable: scenario "broken chain"
# below must show the ::error:: annotation that scenarios "no releases at
# all" / "no release ever carried the asset" must NOT show.
#
# Review of the first version of this test (PR #213) found it could not
# see the failure class it exists to prevent: every scenario assumed `gh`
# itself succeeds, so a `gh` call failing (rate limit, transient 5xx) and
# a `gh` call succeeding-but-finding-nothing were indistinguishable to the
# fake — which is exactly how that gap reproduced #211's original defect
# inside the very script meant to fix it. Scenarios 6-10 below cover that:
# each simulates a `gh` failure at a different call site and asserts the
# script hard-fails rather than printing one of the benign skip messages.
#
# Wired into ci.yaml's `test` job. No live network calls, same rule the Go
# collector tests follow — the real `gh` binary is never invoked, only the
# fake below — but not "pure bash" either: `jq` runs for real against
# synthesised gh-shaped JSON (see N1 below), so this suite depends on `jq`
# being on the runner the same way `hack/fetch-drift-baseline.sh` and
# self-scan.yaml's "Evaluate gaps" step already do.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target="$script_dir/fetch-drift-baseline.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Fake `gh`, driven by:
#   FAKE_RELEASES — space-separated "tag:has_evidence" pairs, most-recent-
#     first (matching gh release list's own default order: newest first).
#   FAKE_GH_FAIL  — optional: "list-latest", "list-fallback", "view-latest",
#     "view-fallback", or "download-latest". Makes the matching `gh` call
#     exit 1 with nothing on stdout, simulating a transient `gh` failure
#     (rate limit, 502, token blip) rather than a genuine "not found" —
#     see B1/F2 in fetch-drift-baseline.sh's own header for why the two
#     must never look the same. "download-latest" fails the download of
#     whichever tag is first in FAKE_RELEASES (the "latest" one)
#     regardless of its own has_evidence flag — modeling a transient
#     failure on a release that genuinely does carry the asset, which is
#     the case a boolean `if gh ...; then` can't distinguish from "it's
#     just not there". "view-latest"/"view-fallback" separately fail the
#     pre-loop check on the latest release and a per-candidate check
#     inside the fallback loop — two independent call sites in the real
#     script (M2, review round 3): a single mode that fails every `gh
#     release view` call can't tell them apart, so removing either
#     handler in the real script alone still leaves a combined scenario
#     green (the other handler's coverage masks the gap).
#
# N1 (found in review round 2): a mock that hand-rolls its own output
# shape, instead of running the real script's own `--jq` argument through
# real `jq` against real gh-shaped JSON, cannot catch a `--jq` field-name
# typo — e.g. `.tag_name` instead of `.tagName`, an easy mistake since
# GitHub's REST and GraphQL APIs disagree on snake_case vs. camelCase.
# Confirmed: `echo '[{"tagName":"v0.3.0"}]' | jq -r '.[0].tag_name //
# empty'` prints nothing — the wrong field name resolves to `null // empty`
# silently, exactly the shape of #211's own defect, just introduced by a
# typo instead of workflow logic. So "release list"/"release view" below
# build real gh-shaped JSON — only the fields the real script's own
# `--json` argument actually requests (M1, review round 3: an earlier
# version also emitted `isLatest`, which the script never asks for and
# real `gh` never returns unrequested — see M1's own note further down
# for why a mock richer than reality is the unsafe direction) — and pipe
# it through `jq -r` using the *caller's own* `--jq` argument (extracted
# from "$@", not reimplemented) — a typo in fetch-drift-baseline.sh's
# `--jq` expression breaks this mock exactly like it would break against
# the real API. This costs the "pure bash" property a mock could
# otherwise have — accepted, since ci.yaml's `test` job already assumes
# `jq` on the runner (self-scan.yaml's "Evaluate gaps" step calls it
# directly, same runner class), so this isn't a new dependency, just a
# different call to an already-required tool.
#
# Handles exactly the six `gh` invocations fetch-drift-baseline.sh makes.
fakebin="$work/bin"
mkdir -p "$fakebin"
cat >"$fakebin/gh" <<'FAKE_GH'
#!/usr/bin/env bash
set -euo pipefail
read -r -a releases <<<"${FAKE_RELEASES:-}"
fail="${FAKE_GH_FAIL:-}"

# jq_arg extracts the value that followed --jq on the real command line,
# so the fake runs the exact expression fetch-drift-baseline.sh passes,
# not a hand-rolled equivalent (see N1 above). Only matches a separate
# `--jq EXPR` token pair — `--jq=EXPR` or `-q EXPR` would return empty,
# which `jq -r ""` then errors on loudly rather than silently accepting
# some other expression. fetch-drift-baseline.sh always uses the `--jq
# EXPR` form, so this is a real constraint but a safe-direction one: it
# breaks visibly if that ever changes, rather than masking a real query.
jq_arg() {
  local prev=""
  for a in "$@"; do
    [ "$prev" = "--jq" ] && printf '%s' "$a" && return
    prev="$a"
  done
}

# M3: bash 3.2 (macOS's stock /bin/bash — GPLv3 avoidance means no
# Homebrew-bash guarantee on every self-hosted runner) treats
# "${releases[@]}" on a never-populated array as an *unbound variable*
# under `set -u`, not an empty expansion — confirmed: `read -r -a arr
# <<<""` leaves `arr` genuinely unset in 3.2, and modern bash's fix for
# this (treating a declared-but-empty array as safe to expand) doesn't
# apply to a variable `read` never assigned at all. Every expansion of
# `releases` below uses the `${releases[@]+"${releases[@]}"}` idiom,
# verified under both /bin/bash 3.2.57 and Homebrew bash 5.x, for exactly
# this reason — a bare "${releases[@]}" reintroduces a real, live CI
# failure on any runner without Homebrew, not a hypothetical one.
case "$1 $2" in
"release list")
  if [[ "$*" == *"--limit 1 "* ]]; then
    [ "$fail" = "list-latest" ] && exit 1
  else
    [ "$fail" = "list-fallback" ] && exit 1
  fi
  # M1: only the field the real script actually requests (`tagName`) —
  # real `gh release list --json tagName` returns exactly that and
  # nothing else (verified live: no `isLatest` unless asked for). A mock
  # richer than reality is the unsafe direction: it would keep passing if
  # fetch-drift-baseline.sh ever reverted to an isLatest-based rule
  # without also updating its own --json field list, while production
  # silently resolved an empty tag and fell open exactly like #211.
  json="["
  first=1
  for r in "${releases[@]+"${releases[@]}"}"; do
    [ "$first" -eq 1 ] || json="$json,"
    json="$json{\"tagName\":\"${r%%:*}\"}"
    first=0
  done
  json="$json]"
  echo "$json" | jq -r "$(jq_arg "$@")"
  ;;
"release download")
  tag="$3"
  if [ "$fail" = "download-latest" ] && [ "${#releases[@]}" -gt 0 ] && [ "$tag" = "${releases[0]%%:*}" ]; then
    exit 1
  fi
  for r in "${releases[@]+"${releases[@]}"}"; do
    if [ "${r%%:*}" = "$tag" ]; then
      if [ "${r##*:}" = "yes" ]; then
        mkdir -p baseline
        echo '{"fake":"evidence"}' >baseline/evidence.json
        exit 0
      fi
      exit 1
    fi
  done
  exit 1
  ;;
"release view")
  # M2: "latest" and "fallback" are two independent call sites in the
  # real script (the pre-loop check on $latest_tag, and the per-candidate
  # check inside the fallback loop) — a single fail mode that always
  # fires makes them mask each other in coverage (removing either
  # handler alone still leaves the suite green, since the other handler
  # alone still trips the same "view" flag). is_latest_tag distinguishes
  # which call this is the same way the real script does: "is this the
  # first/newest entry".
  tag="$3"
  is_latest_tag=0
  if [ "${#releases[@]}" -gt 0 ] && [ "$tag" = "${releases[0]%%:*}" ]; then
    is_latest_tag=1
  fi
  [ "$is_latest_tag" -eq 1 ] && [ "$fail" = "view-latest" ] && exit 1
  [ "$is_latest_tag" -eq 0 ] && [ "$fail" = "view-fallback" ] && exit 1
  found=0
  has="no"
  for r in "${releases[@]+"${releases[@]}"}"; do
    if [ "${r%%:*}" = "$tag" ]; then
      found=1
      has="${r##*:}"
      break
    fi
  done
  [ "$found" -eq 1 ] || exit 1
  if [ "$has" = "yes" ]; then
    json='{"assets":[{"name":"evidence.json"}]}'
  else
    json='{"assets":[]}'
  fi
  echo "$json" | jq -r "$(jq_arg "$@")"
  ;;
*)
  echo "fake gh: unhandled invocation: $*" >&2
  exit 1
  ;;
esac
FAKE_GH
chmod +x "$fakebin/gh"

failures=0

# run_scenario NAME FAKE_RELEASES [TRIGGER_TAG] [FAKE_GH_FAIL]
# Runs the real script against the fake gh, capturing stdout, exit code,
# and the GITHUB_OUTPUT file it writes, into the scenario_* globals below.
#
# The subshell's own exit is captured via `|| exit_code=$?`, not a bare
# `$?` on the following line — this script runs under `set -e`, which (per
# review of the first version of this file) aborts on a failing *simple*
# command the instant it fails, before the next statement executes, even
# though that statement only reads $?. `|| exit_code=$?` makes the
# subshell's failure part of an OR-list instead, which `set -e` does not
# abort on — without this, no scenario asserting a nonzero exit could ever
# run (assert_exit_zero was unreachable dead code for exactly this
# reason), and scenarios 6-8 below (the ones this review round added)
# could not exist at all.
run_scenario() {
  local name="$1" releases="$2" trigger_tag="${3:-}" gh_fail="${4:-}"
  local scratch
  scratch=$(mktemp -d)
  local output_file="$scratch/github_output"
  : >"$output_file"

  local exit_code=0
  (
    cd "$scratch"
    PATH="$fakebin:$PATH" \
      GITHUB_REPOSITORY="sioakim/attestward" \
      GITHUB_OUTPUT="$output_file" \
      FAKE_RELEASES="$releases" \
      TRIGGER_TAG="$trigger_tag" \
      FAKE_GH_FAIL="$gh_fail" \
      "$target"
  ) >"$scratch/stdout" 2>&1 || exit_code=$?

  scenario_name="$name"
  scenario_scratch="$scratch"
  scenario_exit=$exit_code
  scenario_stdout=$(cat "$scratch/stdout")
  scenario_output=$(cat "$output_file")
}

# indent prints its argument with every line prefixed by two spaces.
indent() {
  local text="$1"
  echo "  ${text//$'\n'/$'\n  '}"
}

assert_contains() {
  local haystack="$1" needle="$2" msg="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "FAIL [$scenario_name]: $msg"
    echo "  expected to find: $needle"
    echo "  ---- stdout ----"
    indent "$scenario_stdout"
    echo "  ---- GITHUB_OUTPUT ----"
    indent "$scenario_output"
    failures=$((failures + 1))
  fi
}

assert_not_contains() {
  local haystack="$1" needle="$2" msg="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "FAIL [$scenario_name]: $msg"
    echo "  expected NOT to find: $needle"
    echo "  ---- stdout ----"
    indent "$scenario_stdout"
    failures=$((failures + 1))
  fi
}

assert_exit_zero() {
  if [ "$scenario_exit" -ne 0 ]; then
    echo "FAIL [$scenario_name]: expected exit 0, got $scenario_exit"
    indent "$scenario_stdout"
    failures=$((failures + 1))
  fi
}

assert_exit_nonzero() {
  if [ "$scenario_exit" -eq 0 ]; then
    echo "FAIL [$scenario_name]: expected a nonzero exit (a gh failure must hard-fail, not silently skip), got 0"
    indent "$scenario_stdout"
    failures=$((failures + 1))
  fi
}

# --- Scenario 1: no releases exist at all — genuine first run. ---
run_scenario "no releases at all" ""
assert_exit_zero
assert_contains "$scenario_stdout" "no releases exist yet — drift detection skipped this run" \
  "should report a clean first-run skip"
assert_contains "$scenario_output" "path=" "GITHUB_OUTPUT should still get a (empty) path= line"
assert_not_contains "$scenario_stdout" "::error::" "a genuine first run must not be flagged as broken"

# --- Scenario 2: latest release carries evidence.json — happy path. ---
run_scenario "latest has evidence.json" "v0.3.0:yes v0.2.0:yes v0.1.0:no"
assert_exit_zero
assert_contains "$scenario_stdout" "baseline: v0.3.0's evidence.json (latest release)" \
  "should use the latest release's own pack"
assert_contains "$scenario_output" "path=baseline/evidence.json" "GITHUB_OUTPUT should point at the downloaded file"
assert_not_contains "$scenario_stdout" "::error::" "the happy path must not be flagged"
if [ ! -f "$scenario_scratch/baseline/evidence.json" ]; then
  echo "FAIL [latest has evidence.json]: baseline/evidence.json was not written"
  failures=$((failures + 1))
fi

# --- Scenario 3: BROKEN CHAIN — latest is missing it, an older release
# has it, and this is NOT the release currently being processed (no
# TRIGGER_TAG match — e.g. a scheduled/dispatched run, or a stale gap
# left by a past broken run). This is issue #211's central regression
# case: before this fix, this scenario produced the exact same output as
# scenario 1/4 (silent skip) — indistinguishable from a genuine first
# run. ---
run_scenario "broken chain" "v0.3.0:no v0.2.0:yes v0.1.0:no"
assert_exit_zero
assert_contains "$scenario_stdout" "::error::" "a broken chain must be loudly annotated"
assert_contains "$scenario_stdout" "chain is broken" "the annotation should name the actual problem"
assert_contains "$scenario_stdout" "baseline: v0.2.0's evidence.json (fallback — v0.3.0 is missing it)" \
  "should fall back to the most recent release that does carry the asset"
assert_contains "$scenario_output" "path=baseline/evidence.json" "GITHUB_OUTPUT should point at the fallback pack, not skip"

# --- Scenario 4: genuine first run, but with release history — no
# release, old or new, has ever carried the asset. Must read the same as
# scenario 1 (clean skip, no ::error::), not like scenario 3. ---
run_scenario "no release ever carried the asset" "v0.3.0:no v0.2.0:no v0.1.0:no"
assert_exit_zero
assert_contains "$scenario_stdout" "no evidence.json on any release yet — drift detection skipped this run (first run)" \
  "should report a clean first-run skip, not an error"
assert_not_contains "$scenario_stdout" "::error::" "a chain that never started is not a broken chain"
assert_contains "$scenario_output" "path=" "GITHUB_OUTPUT should still get a (empty) path= line"

# --- Scenario 5 (F1): EXPECTED missing pack — a release-triggered run for
# the exact release that just published (TRIGGER_TAG == latest_tag). This
# is not a broken chain: attach-to-release (which runs after self-scan)
# is what will attach v0.3.0's own pack once this very run finishes, so it
# is *always* missing at the point this script runs, on every successful
# release, forever. Must fall back quietly — no ::error::, different
# wording from the broken-chain case. ---
run_scenario "expected — own release's pack not yet attached" \
  "v0.3.0:no v0.2.0:yes v0.1.0:no" "v0.3.0"
assert_exit_zero
assert_not_contains "$scenario_stdout" "::error::" "a release's own not-yet-attached pack is not a broken chain"
assert_not_contains "$scenario_stdout" "chain is broken" "must not use broken-chain wording for the expected case"
assert_contains "$scenario_stdout" "v0.3.0 has no evidence.json yet — expected, this run is what publishes it" \
  "should explain why v0.3.0 has no pack yet"
assert_contains "$scenario_stdout" "baseline: v0.2.0's evidence.json (fallback — v0.3.0 is missing it)" \
  "should still fall back to the most recent release that does carry the asset"
assert_contains "$scenario_output" "path=baseline/evidence.json" "GITHUB_OUTPUT should point at the fallback pack, not skip"

# --- Scenario 6 (F2): `gh release list --limit 1` (latest resolution)
# itself fails. Three releases exist and v0.2.0 carries the asset — the
# correct behavior is a hard failure, not the benign "no releases exist
# yet" message (which would be a lie: releases do exist, gh just
# couldn't be reached). ---
run_scenario "gh fails resolving latest" "v0.3.0:no v0.2.0:yes v0.1.0:no" "" "list-latest"
assert_exit_nonzero
assert_not_contains "$scenario_stdout" "no releases exist yet" \
  "a gh failure must not be reported as if no releases exist"
assert_not_contains "$scenario_output" "path=baseline" "must not claim a baseline was resolved"

# --- Scenario 7 (F2): the fallback `gh release list --limit 50` call
# fails, after the latest release was confirmed missing the asset. Same
# requirement: hard failure, not a silent "first run" skip. ---
run_scenario "gh fails listing fallback candidates" "v0.3.0:no v0.2.0:yes v0.1.0:no" "" "list-fallback"
assert_exit_nonzero
assert_not_contains "$scenario_stdout" "drift detection skipped this run" \
  "a gh failure must not be reported as a benign skip"

# --- Scenario 8 (B1/F2, split per M2): `gh release view` fails on the
# PRE-LOOP check for the latest release — the very first thing
# fetch-drift-baseline.sh does after resolving latest_tag, never reaching
# the fallback loop at all. Independent from scenario 9 below: a single
# "view" mode that failed every `gh release view` call (the pre-round-3
# version of this test) couldn't tell the two call sites apart, so
# removing either handler in the real script alone still left a combined
# scenario green. Must hard-fail with a message naming gh's failure, not
# silently read as absence. ---
run_scenario "gh fails viewing the latest release" "v0.3.0:no v0.2.0:yes v0.1.0:no" "" "view-latest"
assert_exit_nonzero
assert_contains "$scenario_stdout" "gh release view v0.3.0" "should name which gh call failed"
assert_contains "$scenario_stdout" "::error::" "a gh failure on the latest-release check must be loudly annotated"
assert_not_contains "$scenario_stdout" "drift detection skipped this run" \
  "a gh failure must not be reported as a benign skip"

# --- Scenario 9 (F2): `gh release view` fails partway through the
# fallback scan, AFTER the latest release's own view call has already
# succeeded (v0.3.0 genuinely has no evidence.json, so the script reaches
# the loop and starts checking v0.2.0). Before F2, piping straight into
# `grep -qx` made this indistinguishable from "this release has no
# evidence.json" — exactly #211's original defect, reproduced through the
# fix's own fallback loop. Must hard-fail with a message naming gh's
# failure, not silently `continue` past it. ---
run_scenario "gh fails viewing a fallback candidate" "v0.3.0:no v0.2.0:yes v0.1.0:no" "" "view-fallback"
assert_exit_nonzero
assert_contains "$scenario_stdout" "gh release view v0.2.0" "should name which gh call failed"
assert_contains "$scenario_stdout" "::error::" "a gh failure mid-scan must be loudly annotated"
assert_not_contains "$scenario_stdout" "drift detection skipped this run" \
  "a gh failure must not be reported as a benign skip"

# --- Scenario 10 (B1): `gh release download` for the LATEST release fails
# (transient 502) even though that release genuinely carries the asset.
# Review of the first fix found this exact case: a `gh` exit status
# consumed as a boolean (`if gh release download ...; then`) can't tell
# "the asset is absent" from "gh itself failed" — reproduced live against
# a real release (a nonexistent-pattern download and a genuine transient
# failure both exit 1) and, against this repo's actual release state
# (latest missing the asset, no older release carrying it either), gave
# the exact silent "no evidence.json on any release yet" skip — #211's
# defect, verbatim, through the fourth `gh` call site F2 didn't touch.
# Must hard-fail, matching every other `gh`-failure scenario above, not
# read as a benign first-run skip. ---
run_scenario "gh fails downloading the latest release" "v0.3.0:yes v0.2.0:no v0.1.0:no" "" "download-latest"
assert_exit_nonzero
assert_not_contains "$scenario_stdout" "drift detection skipped this run" \
  "a gh failure must not be reported as a benign skip"

if [ "$failures" -gt 0 ]; then
  echo "$failures assertion(s) failed"
  exit 1
fi
echo "all fetch-drift-baseline scenarios passed"
