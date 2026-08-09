#!/usr/bin/env bash
# hack/check-examples-drift.sh — issue #228's drift guard for
# examples/demo-org-pack: re-renders report.md/report.html/poam.md from
# the pack's own committed evidence.json into a scratch directory and
# diffs against the committed copy, failing loudly if anything differs.
# Two further checks (added in review of #228, issue #230) run first,
# because a generic "run make examples" failure message is actively wrong
# for what they catch — see each section below for why.
#
# This is the guard #227's investigation found missing: report.html on
# main went two releases (#200, #212) without being regenerated, because
# nothing checked it — `rg 'demo-org-pack' Makefile .github/workflows/`
# returned nothing before this.
#
# Byte-stability confirmed empirically before writing this, not assumed:
# re-rendering the same evidence.json three independent times produced
# byte-identical SHA-256 sums for all three files. `attestward report`
# reads ScanStartedAt/ScanEndedAt from the pack itself rather than calling
# time.Now(), and its "Pack SHA-256" line hashes the deterministic input
# bytes — so a plain diff is sound here; no deterministic-render mode or
# partial comparison was needed.
#
# PACK_DIR (default examples/demo-org-pack, relative to the repo root)
# takes an optional override so check-examples-drift_test.sh can point
# this at a throwaway fixture directory instead of the real example pack.
# Must be run from the repo root (same assumption `make checks-docs-check`
# already makes via its own bare `go run ./cmd/attestward ...`), and
# depends on `jq`, same as hack/fetch-drift-baseline.sh already does.
set -euo pipefail

PACK_DIR="${1:-examples/demo-org-pack}"

if [ ! -f "$PACK_DIR/evidence.json" ]; then
  echo "::error::$PACK_DIR/evidence.json not found" >&2
  exit 1
fi

# --- Sidecar presence (found in review of #230) ---
#
# examples/README.md documents evidence.json.sha256 as what `attestward
# verify` checks a reader's copy against. A re-scan that regenerated
# evidence.json but forgot to copy its sidecar would leave this guard
# green (rendering doesn't need the sidecar) while silently breaking that
# documented walkthrough for the next person who follows it.
if [ ! -f "$PACK_DIR/evidence.json.sha256" ]; then
  echo "::error::$PACK_DIR/evidence.json.sha256 is missing — examples/README.md documents it as what 'attestward verify' checks against" >&2
  exit 1
fi

# --- Mapping-version currency (found in review of #230) ---
#
# evidence.json embeds the mapping versions live when it was captured
# (mapping_versions.ssdf/cisa_form/self_attestation). If mappings/*.yaml's
# own `version:` has moved since, re-rendering populates DriftedMappingFiles
# (internal/report/context.go), which bakes a "this pack's mapping
# versions do not match..." banner into the TOP of all three files (see
# report.html.tmpl:918, report.md.tmpl:2, poam.md.tmpl:2) — not a
# rendering defect `make examples` can fix, since the pack's own recorded
# mapping_versions is what's stale, and only a live re-scan of the demo
# org (hack/demo-org-setup.sh) can update it. Checked here, before any
# rendering, so this case gets its own message instead of being folded
# into the generic "run make examples" advice below — which would be
# telling someone to publish that banner on the exact artifact
# README.md points cold visitors at.
pack_ssdf=$(jq -r '.mapping_versions.ssdf' "$PACK_DIR/evidence.json")
pack_cisa=$(jq -r '.mapping_versions.cisa_form' "$PACK_DIR/evidence.json")
pack_sa=$(jq -r '.mapping_versions.self_attestation' "$PACK_DIR/evidence.json")
current_ssdf=$(sed -n 's/^version: *"\(.*\)"/\1/p' mappings/ssdf-800-218.yaml | head -1)
current_cisa=$(sed -n 's/^version: *"\(.*\)"/\1/p' mappings/cisa-ssda-form.yaml | head -1)
current_sa=$(sed -n 's/^version: *"\(.*\)"/\1/p' mappings/self-attestation-questions.yaml | head -1)

if [ "$pack_ssdf" != "$current_ssdf" ] || [ "$pack_cisa" != "$current_cisa" ] || [ "$pack_sa" != "$current_sa" ]; then
  echo "::error::$PACK_DIR/evidence.json's mapping_versions (ssdf=$pack_ssdf, cisa_form=$pack_cisa, self_attestation=$pack_sa) no longer match the current mappings/*.yaml (ssdf=$current_ssdf, cisa_form=$current_cisa, self_attestation=$current_sa) — this needs a live re-scan of the demo org, NOT 'make examples': re-rendering a version-mismatched pack bakes a mapping-version-mismatch banner into all three files instead of fixing anything" >&2
  exit 1
fi

# --- Check-ID coverage (found in review of #230) ---
#
# The render-diff below only catches drift in HOW an already-present
# result is rendered — a check ADDED to the registry doesn't change the
# rendered output at all if evidence.json never gained a result for it
# (buildContext only iterates pack.Results), so this guard would stay
# green while the showcase silently under-reports what attestward
# actually checks today. The pack's 52 check_ids happen to be set-equal
# to the current registry's 46 GitHub checks + 6 self-attestation
# questions as of writing, but that was a one-time manual confirmation in
# issue #228's own PR, not something anything enforced — enforced here.
current_ids=$(go run ./cmd/attestward checks list --format json | jq -r '[.[] | select(.platform == "github" or .platform == null) | .check_id] | unique | .[]')
pack_ids=$(jq -r '[.results[].check_id] | unique | .[]' "$PACK_DIR/evidence.json")
if [ "$current_ids" != "$pack_ids" ]; then
  echo "::error::$PACK_DIR/evidence.json's check_id set no longer matches the current GitHub + self-attestation registry — a check was added, removed, or renamed since this pack was captured; a live re-scan is needed, not a re-render. Diff (< current registry, > pack):" >&2
  diff <(echo "$current_ids") <(echo "$pack_ids") >&2 || true
  exit 1
fi

# --- Render drift ---
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

go run ./cmd/attestward report "$PACK_DIR/evidence.json" --out "$work" >/dev/null

# -x excludes evidence.json/evidence.json.sha256 (never rewritten by
# `attestward report`) rather than hardcoding report.md/report.html/
# poam.md by name — future-proof against a format `runReport` learns to
# emit that this list doesn't yet know about (found in review of #230:
# the old hardcoded loop would silently ignore a new format the same way
# report.html itself drifted for two releases before this guard existed).
if ! diff -r -x 'evidence.json*' "$PACK_DIR" "$work"; then
  echo "::error::$PACK_DIR's rendered examples are stale — run 'make examples' and commit the result" >&2
  exit 1
fi

echo "$PACK_DIR's rendered examples are up to date"
