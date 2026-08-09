#!/usr/bin/env bash
# hack/fetch-drift-baseline.sh — resolves self-scan.yaml's drift baseline:
# the evidence.json attached to the latest GitHub release for
# $GITHUB_REPOSITORY (durable, unlike expiring workflow artifacts — see
# self-scan.yaml's attach-to-release job, which maintains it).
#
# Issue #211: a missing baseline used to fail open silently in every case —
# a genuine first run (no release has ever carried the asset) and a broken
# chain (the latest release is missing it, but an older one has it — e.g.
# because a release-triggered run never fired) produced the identical
# "skipped this run" message. Review of the first version of this fix
# (PR #213) found further defects, all fixed here:
#
#   - F1: on a release-triggered run, self-scan (which calls this script)
#     always runs BEFORE attach-to-release attaches that same release's
#     own pack — so the just-published release can NEVER carry
#     evidence.json yet, on every single successful release, forever.
#     That is not a broken chain; it is this workflow's own normal
#     sequencing. TRIGGER_TAG (set by self-scan.yaml only on a
#     workflow_run event, to the release that triggered this run) lets
#     this script recognize that specific expected case and skip the loud
#     annotation for it, while still comparing against the next-most-
#     recent release that does carry the asset.
#   - F2/B1: `gh` itself can fail (rate limit, transient 5xx, token
#     issue). That must never look like "the asset is absent" — a fallback
#     loop that piped `gh release view` straight into `grep` (F2), and a
#     `gh release download` exit status consumed as a boolean via
#     `if gh ...; then` (B1, found in the second review round — F2's first
#     pass fixed three of what turned out to be four affected call sites,
#     missing this one), both let a `gh` failure silently reproduce #211's
#     exact original defect through this script instead of fixing it.
#     Confirmed live for B1: `gh release download --pattern
#     nonexistent-asset.json` against a real release and a genuine
#     transient failure both exit 1, indistinguishably.
#
#     Every `gh` call below now follows one of exactly two contracts: a
#     plain command substitution assigned directly to a variable and used
#     as a simple command, so `set -e` catches a failure on its own
#     (`latest_tag`, `tag_list`, and the two `gh release download` calls,
#     which are bare commands, never wrapped in an `if`/boolean context);
#     or a command substitution with its own exit status checked
#     explicitly via `||`, kept separate from whatever reads its output
#     (`latest_assets`, `assets`). No `gh` call is piped into anything, or
#     used as an `if`/`&&`/`||` condition, that would let its own exit
#     status get lost or reinterpreted by a downstream command.
#
# Three cases, deliberately distinguished:
#   1. No release exists at all yet — a genuine first run. Clean skip.
#   2. The latest release carries evidence.json — the common case.
#   3. The latest release does NOT carry it. Two sub-cases:
#      a. Expected (TRIGGER_TAG == latest release): this run's own pack
#         hasn't been attached yet. Falls back quietly, no annotation.
#      b. Otherwise: the chain is broken. Loudly annotated (::error::)
#         without failing the step outright — falling back to the most
#         recent release that does carry the asset means drift detection
#         still runs against a slightly stale baseline, which catches
#         real drift where skipping catches none.
#
# Extracted out of the workflow YAML so it's independently testable against
# a mocked `gh` without needing a real release — see
# fetch-drift-baseline_test.sh, wired into ci.yaml's test job.
#
# Reads GITHUB_REPOSITORY and GH_TOKEN from the environment (both ambient
# on a real Actions runner; the test script sets them explicitly).
# TRIGGER_TAG is optional — self-scan.yaml sets it only on a workflow_run
# event; empty/unset means "no specific release is expected to be missing
# its pack" (the schedule/workflow_dispatch case), so any missing latest is
# unconditionally treated as a broken chain. N2: if releases publish out of
# order (TRIGGER_TAG is v0.4.0 but v0.4.1 is already latest by the time
# this runs), TRIGGER_TAG won't match latest_tag and this reads as a false
# broken-chain alarm — loud and self-correcting (the next run past v0.4.1
# clears it), not silent, so left as-is rather than added complexity for
# an edge case this repo's release cadence doesn't hit in practice. Writes
# GitHub Actions' `path=...` output line to $GITHUB_OUTPUT, same contract
# as any other workflow step — just factored out of the YAML.
set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set}"
TRIGGER_TAG="${TRIGGER_TAG:-}"

# F3: the write side (self-scan.yaml's attach-to-release) attaches to the
# triggering run's head_branch — the literal tag, prerelease or not. The
# read side must resolve "latest" by the identical rule, or a prerelease
# (e.g. an `-rc.N` tag, which goreleaser auto-marks prerelease — this repo
# has cut one before, v0.1.0-rc.1) gets written under its own tag but never
# read back, since GitHub's "isLatest" excludes prereleases by definition.
# `gh release list`'s default order (newest first, prereleases included)
# gives both sides the same answer: the most recently published release,
# full stop. `--exclude-drafts` on every `release list` call below: a
# draft is never published (goreleaser creates none, so this is latent
# today), but a hand-made one would rank first, never carry a pack, and
# read exactly like a permanently broken chain no real release could
# clear — worth excluding on the read side even though nothing here
# writes one.
latest_tag=$(gh release list --repo "$GITHUB_REPOSITORY" --exclude-drafts \
  --limit 1 --json tagName --jq '.[0].tagName // empty')

if [ -z "$latest_tag" ]; then
  echo "path=" >>"$GITHUB_OUTPUT"
  echo "no releases exist yet — drift detection skipped this run"
  exit 0
fi

# B1 (see this file's header): view before download, exit status checked
# explicitly — was `if gh release download ...; then`, a `gh` exit status
# consumed as a boolean.
latest_assets=$(gh release view "$latest_tag" --repo "$GITHUB_REPOSITORY" \
  --json assets --jq '.assets[].name') || {
  echo "::error::gh release view $latest_tag failed — cannot determine whether the latest release carries evidence.json; treating the baseline chain as unverifiable rather than silently skipping"
  exit 1
}
if grep -qx evidence.json <<<"$latest_assets"; then
  gh release download "$latest_tag" --repo "$GITHUB_REPOSITORY" \
    --pattern evidence.json --dir baseline --clobber
  echo "path=baseline/evidence.json" >>"$GITHUB_OUTPUT"
  echo "baseline: $latest_tag's evidence.json (latest release)"
  exit 0
fi

# Latest release has no evidence.json.
if [ -n "$TRIGGER_TAG" ] && [ "$latest_tag" = "$TRIGGER_TAG" ]; then
  broken_chain=0
else
  broken_chain=1
fi

# Scan recent releases, newest first, for the most recent one that does
# carry the asset — bounded at 50 so this stays a handful of API calls;
# this repo has a single-digit release count today and 50 is generous
# headroom. Assigned to a variable first, not embedded directly inside the
# `for` word list, so `set -e` catches a `gh` failure here on its own
# (same contract as this file's header describes).
tag_list=$(gh release list --repo "$GITHUB_REPOSITORY" --exclude-drafts \
  --limit 50 --json tagName --jq '.[].tagName')

fallback_tag=""
for tag in $tag_list; do
  [ "$tag" = "$latest_tag" ] && continue
  # F2/B1 (see this file's header): exit status checked explicitly.
  assets=$(gh release view "$tag" --repo "$GITHUB_REPOSITORY" \
    --json assets --jq '.assets[].name') || {
    echo "::error::gh release view $tag failed — cannot determine whether it carries evidence.json; treating the baseline chain as unverifiable rather than silently skipping"
    exit 1
  }
  if grep -qx evidence.json <<<"$assets"; then
    fallback_tag="$tag"
    break
  fi
done

if [ -z "$fallback_tag" ]; then
  echo "path=" >>"$GITHUB_OUTPUT"
  echo "no evidence.json on any release yet — drift detection skipped this run (first run)"
  exit 0
fi

if [ "$broken_chain" -eq 1 ]; then
  echo "::error::latest release ($latest_tag) has no evidence.json, but an older one ($fallback_tag) does — the drift baseline chain is broken. Falling back to $fallback_tag's pack; this compares against a stale baseline until the chain is repaired."
else
  echo "$latest_tag has no evidence.json yet — expected, this run is what publishes it. Comparing against $fallback_tag's pack instead."
fi
gh release download "$fallback_tag" --repo "$GITHUB_REPOSITORY" \
  --pattern evidence.json --dir baseline --clobber
echo "path=baseline/evidence.json" >>"$GITHUB_OUTPUT"
echo "baseline: $fallback_tag's evidence.json (fallback — $latest_tag is missing it)"
