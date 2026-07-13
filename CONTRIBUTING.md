# Contributing

Thanks for your interest. This project is built issue-first: **GitHub Issues are the task
board** — every piece of work (feature, bug, doc, mapping change) has an issue, and the
issue thread is the record of what was decided and why.

## Ground rules

- **Read-only forever.** No PR that adds a write operation against any platform API will
  be accepted. See [ADR-0004](docs/adr/0004-read-only-local-first.md).
- **Accuracy discipline.** SSDF task IDs, CISA form language, and regulatory citations
  must be verified against primary sources (NIST SP 800-218, CISA SSDA form instructions).
  Paraphrases are marked as paraphrases. Never invent control IDs.
- **Boring, auditable code.** New dependencies need explicit justification in the PR.
  When in doubt between two designs, pick the one that is simpler to audit.
- **Tests are not optional.** Every collector change ships with fixture-based unit tests.

## Workflow

1. Find or create an issue. Comment your approach before writing code.
2. Branch from `main`: `<type>/<issue-number>-<short-description>`
   (e.g. `feature/12-repo-protection-collector`; types: `feature|fix|hotfix|chore|docs`).
3. Small PRs — target under 200 changed lines, hard ceiling 400. Split bigger work.
4. Conventional commits: `feat(collect): add repo-protection ruleset checks`
   (types: `feat|fix|chore|docs|refactor|test|style|perf`; imperative mood; reference the
   issue in the footer: `Fixes #12`).
5. CI must be green (`lint` and `test` are required status checks on `main`; the `build`
   matrix runs and uploads artifacts but does not gate merge). Squash merge only; the PR
   title becomes the commit on `main`.
6. Delete the branch after merge.

`main` is protected by a repository ruleset (PR required, linear history, no force-push,
no deletion). Repo admins can bypass it — documented here rather than left implicit, so a
solo maintainer isn't deadlocked by their own rules — but bypass is for emergencies only;
default to the PR workflow above even as the sole maintainer.

## Development setup

```bash
go version         # see the `go` directive in go.mod for the current floor (dependency-driven, not arbitrary)
make build         # or: go build ./cmd/attestor
make test          # go test ./...
make lint          # golangci-lint run
make tidy          # go mod tidy
```

## Testing conventions

- **Unit tests:** recorded API fixtures (JSON under `testdata/`), no live network calls.
- **GitHub API fixtures:** `internal/collect/github/ghfixture` provides a fixture-backed
  `http.RoundTripper` for collector tests — no live network, no VCR-style cassette
  dependency. `ghfixture.New().Set("GET", "/orgs/my-org", ghfixture.Response{Status: 200,
  Body: ...})` registers a canned response keyed by method+path (query strings aren't
  matched — provenance recording deliberately drops them too, see
  `internal/collect/github/transport.go`); `SetSequence(...)` registers an ordered sequence
  consumed one at a time, for testing retry behavior (e.g. a rate-limited response followed
  by success). Wire it into a real `Client` the same way
  `internal/collect/github/client_test.go`'s `newTestClient` helper does, so collector
  tests exercise the real auth/provenance/rate-limit transport chain, not a bypass of it.
- **Integration tests:** run against the public demo org (see the demo-org issue);
  gated behind a build tag so `go test ./...` stays offline-safe.
- **Renderer tests:** golden files under `testdata/golden/`.

## Contributing mappings and scanner signatures

The most valuable non-Go contributions:

- **New verification check** → use the "New check proposal" issue template. A check needs:
  what API evidence proves it, which SSDF task(s) it maps to, and its failure semantics.
- **New scanner signature** (SAST/SCA tool detection) → use the "New scanner signature"
  issue template, then PR the YAML addition to `mappings/scanner-signatures.yaml` with a
  fixture workflow file that exercises it.

Mapping changes bump the mapping file's `version:` field in the same PR.

## Docs

- Behavior or architecture changes update `docs/` in the same PR.
- Significant design choices get an ADR (`docs/adr/`).
- `CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com); add your entry
  under `Unreleased`.

## License

By contributing you agree that your contributions are licensed under Apache-2.0.
