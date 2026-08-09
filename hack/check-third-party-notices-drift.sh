#!/usr/bin/env bash
# hack/check-third-party-notices-drift.sh — issue #282's drift guard for
# THIRD-PARTY-NOTICES.md, same shape as hack/check-examples-drift.sh:
# regenerate into a scratch file and diff against the committed copy,
# rather than mutating the working tree on a failing run.
#
# FILE (default THIRD-PARTY-NOTICES.md, relative to the repo root) takes
# an optional override so check-third-party-notices-drift_test.sh can
# point this at a throwaway copy instead of the real committed file —
# same reasoning as check-examples-drift.sh's own PACK_DIR parameter.
# Must be run from the repo root, same assumption every sibling guard
# already makes.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
cd "$repo_root"

FILE="${1:-THIRD-PARTY-NOTICES.md}"

if [ ! -f "$FILE" ]; then
  echo "::error::$FILE not found" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$script_dir/gen-third-party-notices.sh" "$work/THIRD-PARTY-NOTICES.md" >/dev/null

if ! diff -u "$FILE" "$work/THIRD-PARTY-NOTICES.md"; then
  echo "::error::$FILE is stale — run 'make notices' and commit the result" >&2
  exit 1
fi

echo "$FILE is up to date"
