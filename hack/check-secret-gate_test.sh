#!/usr/bin/env bash
# hack/check-secret-gate_test.sh — exercises the secret gate that stands
# between the self-scan and the publish in .gitlab-ci.yml's
# `self-scan-and-publish` job.
#
# The gate is the last thing between a scanned credential and a public
# branch, and every other check in this repo would stay green if it silently
# stopped working — so it gets a test of its own, in the same shape as the
# hack/*_test.sh siblings (a developer-run companion to a CI script, not
# itself wired into a pipeline).
#
# It EXTRACTS the gate from .gitlab-ci.yml rather than restating it. A test
# holding its own copy of the patterns would keep passing after the real gate
# was weakened, which is the failure this file exists to notice. Extraction is
# plain awk, deliberately, so this needs nothing the golang CI image lacks —
# no yaml parser, no jq.
#
# Two of the six cases below are regressions, not hypotheticals: an
# adversarial review of the original version found that `if grep ...` read
# "grep could not run" (exit 2) as "grep found nothing", and that -I let a
# NUL byte exempt a file from the scan entirely. Both are asserted here.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
cd "$repo_root"

CI_FILE="${1:-.gitlab-ci.yml}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Everything from the SECRET_RE assignment up to (not including) the first
# call site — i.e. the definitions, and nothing that would run a scan.
awk '
  /^ *SECRET_RE=/            { capture = 1 }
  /^ *for platform in gitlab/ { if (capture) exit }
  capture                    { sub(/^      /, ""); print }
' "$CI_FILE" > "$work/gate.sh"

if ! grep -q '^SECRET_RE=' "$work/gate.sh" || ! grep -q '^secret_gate()' "$work/gate.sh"; then
  echo "::error::could not extract the secret gate from $CI_FILE — the job's script was restructured. Re-anchor this test rather than deleting it." >&2
  exit 1
fi

# Everything below tests the gate's DEFINITION, which leaves the cheapest way
# to defeat it entirely invisible: delete the lines that call it. The
# definition would still extract, every case below would still pass, and no
# scan output would ever be screened. So the call sites are asserted here
# against the whole file, and so is their position — a gate that runs after
# the push is not a gate. (Found by an adversarial review of an earlier
# version of this file, which was green against a copy with both call sites
# removed.)
for expected in 'secret_gate "reports-out/$platform/evidence.json"' 'secret_gate reports-out'; do
  if ! grep -qF -- "$expected" "$CI_FILE"; then
    echo "::error::the gate is defined but never invoked as \`$expected\` in $CI_FILE — a gate nothing calls screens nothing." >&2
    exit 1
  fi
done

last_gate_line=$(grep -nF -- 'secret_gate reports-out' "$CI_FILE" | tail -1 | cut -d: -f1)
first_push_line=$(grep -n 'git -C pages-history push' "$CI_FILE" | head -1 | cut -d: -f1)
if [ -z "$last_gate_line" ] || [ -z "$first_push_line" ]; then
  echo "::error::could not locate the gate call and the push in $CI_FILE to compare their order. Re-anchor this check." >&2
  exit 1
fi
if [ "$last_gate_line" -ge "$first_push_line" ]; then
  echo "::error::the full-tree secret gate (line $last_gate_line) does not run before the push (line $first_push_line) — publishing would happen unscreened." >&2
  exit 1
fi
echo "ok: gate is invoked, and runs before the push (gate line $last_gate_line < push line $first_push_line)"

# The gate compares against the credentials the real job holds. Stand-ins
# here: no real secret is needed to prove the comparison fires, and a test
# that required live tokens would simply not be run.
export GITLAB_TOKEN="glpat-testtesttesttesttest"
export GITHUB_TOKEN="ghp_0000000000000000000000000000000000000000"
export GOGS_TOKEN="0123456789abcdef0123456789abcdef01234567"

fails=0

# run_case <expected-exit> <expected-message-substring> <description> <target>
#
# The message is asserted, not just the exit status, and that distinction is
# load-bearing: every failure mode here exits 1, so an exit-code-only
# assertion cannot tell "found a secret" from "could not run". Found by
# mutation — disabling the shape check entirely left an exit-code-only
# version of this test fully green, because the disabled check's own error
# branch fired instead and the gate still exited 1 for the wrong reason.
run_case() {
  want="$1"; want_msg="$2"; desc="$3"; target="$4"
  set +e
  output=$(bash -c "source '$work/gate.sh'; secret_gate '$target'" 2>&1)
  got=$?
  set -e
  if [ "$got" -ne "$want" ]; then
    echo "FAIL: $desc — gate exited $got, want $want" >&2
    echo "$output" | sed 's/^/    /' >&2
    fails=$((fails + 1))
  elif ! printf '%s' "$output" | grep -qF -- "$want_msg"; then
    echo "FAIL: $desc — exited $want as expected, but for the wrong reason (no \"$want_msg\" in output)" >&2
    echo "$output" | sed 's/^/    /' >&2
    fails=$((fails + 1))
  else
    echo "ok: $desc (exit $got)"
  fi
}

printf '{"reason":"ordinary text, no secrets here"}' > "$work/clean.json"
run_case 0 "secret gate clean" "ordinary content passes" "$work/clean.json"

printf '{"reason":"glpat-ABCDEFGHIJKLMNOPQRSTUV"}' > "$work/glpat.json"
run_case 1 "secret-shaped string found" "a GitLab token shape is caught (EvidencePack.Scrub has no glpat- pattern)" "$work/glpat.json"

printf '{"reason":"AKIAIOSFODNN7EXAMPLE"}' > "$work/akia.json"
run_case 1 "secret-shaped string found" "an AWS key shape is caught" "$work/akia.json"

# The Gogs token is 40 hex characters with no prefix, so no shape-based
# pattern can recognise one. Only the verbatim comparison can, which is the
# entire reason that second check exists.
printf '{"reason":"%s"}' "$GOGS_TOKEN" > "$work/verbatim.json"
run_case 1 "appears verbatim" "a prefix-less credential is caught verbatim" "$work/verbatim.json"

# Regression: grep exits >1 when it cannot run. That must fail the job, not
# read as clean.
run_case 1 "could not run" "a gate that cannot run fails closed" "$work/no-such-file.json"

# Regression: a NUL byte must not exempt a file from the scan.
printf 'x\000glpat-ABCDEFGHIJKLMNOPQRSTUV' > "$work/nul.json"
run_case 1 "secret-shaped string found" "a NUL byte does not smuggle a secret past the gate" "$work/nul.json"

if [ "$fails" -ne 0 ]; then
  echo "::error::$fails secret-gate case(s) failed" >&2
  exit 1
fi
echo "secret gate: all cases pass"
