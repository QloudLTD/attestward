BINARY  := attestward
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build test lint tidy checks-docs checks-docs-check

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/attestward

test:
	go test ./...

lint:
	golangci-lint run

tidy:
	go mod tidy

checks-docs:
	go run ./cmd/attestward checks docs

checks-docs-check:
	go run ./cmd/attestward checks docs --check
