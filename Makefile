BINARY  := attestward
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build test lint tidy tidy-check checks-docs checks-docs-check examples examples-check notices notices-check

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/attestward

test:
	go test ./...

lint:
	golangci-lint run

tidy:
	go mod tidy

# Issue #249: the checks-docs/examples pair below both have a plain form
# and a `-check` counterpart that fails on drift instead of fixing it —
# tidy gets the same pairing, with one real difference from both (found
# in review, second round): checks-docs-check passes --check and never
# writes, and examples-check renders into a scratch `mktemp -d` and diffs
# there — both leave the working tree untouched on a failing run. This
# target does NOT: `go mod tidy` always rewrites go.mod/go.sum in place,
# so a failing run here leaves them tidied rather than reverted, unlike
# either sibling. Deliberately kept this way rather than restored on
# failure: harmless in CI (actions/checkout resets the tree per job) and
# often convenient locally, since the mutation IS the fix `make tidy`
# itself would otherwise be run for. A contributor relying on this as a
# read-only sanity check on a go.mod they've hand-edited to something
# other than what `go mod tidy` itself would produce should know that
# edit won't survive a failing run here.
tidy-check:
	go mod tidy
	@git diff --exit-code go.mod go.sum || { echo "::error::go.mod/go.sum are not tidy — run 'make tidy' and commit the result" >&2; exit 1; }

checks-docs:
	go run ./cmd/attestward checks docs

checks-docs-check:
	go run ./cmd/attestward checks docs --check

examples:
	go run ./cmd/attestward report examples/demo-org-pack/evidence.json --out examples/demo-org-pack

examples-check:
	./hack/check-examples-drift.sh

# Issue #282: THIRD-PARTY-NOTICES.md is generated from the resolved
# module graph + each dependency's own LICENSE file in the module
# cache — same generated/checked pairing as checks-docs/examples above.
notices:
	./hack/gen-third-party-notices.sh

notices-check:
	./hack/check-third-party-notices-drift.sh
