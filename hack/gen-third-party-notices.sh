#!/usr/bin/env bash
# hack/gen-third-party-notices.sh — issue #282's generator for
# THIRD-PARTY-NOTICES.md: the archive-level third-party attribution
# `.goreleaser.yaml`'s `archives.files` didn't carry before this issue.
#
# Reads only the resolved module graph (`go list -deps`) and each
# dependency's own license file as already extracted into the local
# module cache (`go list -m -f '{{.Dir}}'`) — no network call, no new
# tool, matching this repo's stated preference for a hermetic hack/
# script over pulling in google/go-licenses or Songmu/gocredits.
#
# Iterates every GOOS/GOARCH goreleaser actually ships — the same five
# targets ci.yaml's `build` job cross-compiles from, kept in sync with
# `.goreleaser.yaml`'s builds.goos/goarch/ignore by hand, the same way
# that job's own cross-compile loop already duplicates the list rather
# than parsing the yaml. Nothing guards this duplication against drift —
# adding a target to `.goreleaser.yaml` (e.g. windows/arm64) would leave
# `targets` below silently unchanged until someone updates it by hand,
# same as ci.yaml's own copy. This matters because the linked module set is
# NOT platform-independent: github.com/spf13/cobra pulls in
# github.com/inconshreveable/mousetrap only on windows (its
# double-click-detection helper) — `go list -deps` on darwin/linux never
# sees it, so a single-platform listing would silently omit a module that
# IS statically linked into the windows archive. The same
# THIRD-PARTY-NOTICES.md ships in every archive regardless of OS (see
# `.goreleaser.yaml`'s `archives.files`), so the union across all targets
# is the correct set for all of them: extra attribution on a platform
# that doesn't actually link a given module is harmless, missing
# attribution on one that does is the exact gap this closes.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
cd "$repo_root"

OUT="${1:-THIRD-PARTY-NOTICES.md}"

targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"

modules=""
for target in $targets; do
  goos="${target%/*}"
  goarch="${target#*/}"
  found=$(GOOS="$goos" GOARCH="$goarch" go list -deps -f '{{if .Module}}{{if not .Module.Main}}{{.Module.Path}} {{.Module.Version}}{{end}}{{end}}' ./cmd/attestward)
  modules="$modules
$found"
done
modules=$(echo "$modules" | sed '/^$/d' | sort -u)

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

{
  cat <<'HEADER'
# Third-Party Notices

`attestward` statically links the third-party Go modules listed below into
its released binaries. This file is **generated** by
`hack/gen-third-party-notices.sh` from the resolved module graph
(`go list -deps ./cmd/attestward`, across every OS/arch this project ships)
and each module's own license file as vendored in the local module
cache — never hand-edit it. Regenerate with `make notices`; CI verifies it
hasn't drifted from the actual dependency set via `make notices-check`
(the `third-party-notices-drift` job). It ships alongside `LICENSE` and
`NOTICE` in every release archive — see `.goreleaser.yaml`'s
`archives.files`.
HEADER
  echo

  while read -r path version; do
    [ -z "$path" ] && continue
    dir=$(go list -m -f '{{.Dir}}' "$path")

    license_file=""
    for name in LICENSE LICENSE.txt LICENSE.md COPYING COPYING.md; do
      if [ -f "$dir/$name" ]; then
        license_file="$dir/$name"
        break
      fi
    done
    if [ -z "$license_file" ]; then
      echo "::error::no LICENSE-like file found for $path@$version in $dir" >&2
      exit 1
    fi

    notice_file=""
    for name in NOTICE NOTICE.txt NOTICE.md; do
      if [ -f "$dir/$name" ]; then
        notice_file="$dir/$name"
        break
      fi
    done

    echo "## $path"
    echo
    echo "Version: \`$version\`"
    echo
    echo '```'
    cat "$license_file"
    # A license file with no trailing newline (e.g. jsonschema/v5's) would
    # otherwise weld the closing fence onto its last line, so CommonMark
    # stops treating it as a fence at all — inverts code-block parity for
    # the rest of the document. A plain `echo` after `cat` always adds a
    # newline regardless, so this must be conditional on there already
    # being one, not unconditional.
    if [ -n "$(tail -c 1 "$license_file")" ]; then echo; fi
    echo '```'
    echo

    if [ -n "$notice_file" ]; then
      echo "### $path's own NOTICE"
      echo
      echo '```'
      cat "$notice_file"
      if [ -n "$(tail -c 1 "$notice_file")" ]; then echo; fi
      echo '```'
      echo
    fi
  done <<<"$modules"
} >"$tmp"

mv "$tmp" "$OUT"
echo "wrote $OUT"
