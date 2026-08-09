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
   issue in the footer: `Refs #12`). Never `Fixes`/`Closes #N` — squash-merge auto-closes
   the issue, losing the close comment that records the evidence. Confirm with
   `gh pr view <N> --json closingIssuesReferences` → `[]`.
5. CI must be green (`lint` and `test` are required status checks on `main`; the `build`
   job runs but does not gate merge). Squash merge only; the PR title becomes the
   commit on `main`.
6. Delete the branch after merge.

`main` is protected by a repository ruleset (PR required, linear history, no force-push,
no deletion). Repo admins can bypass it — documented here rather than left implicit, so a
solo maintainer isn't deadlocked by their own rules — but bypass is for emergencies only;
default to the PR workflow above even as the sole maintainer.

## Development setup

```bash
go version         # see the `go` directive in go.mod for the current floor (dependency-driven, not arbitrary)
make build         # or: go build ./cmd/attestward
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
- **Integration tests:** run against the public demo org (`Qloud-LTD` — see
  `hack/demo-org-setup.sh` and `fixtures.yaml`), gated
  behind `//go:build integration` so `go test ./...` stays offline-safe. Run
  locally with a `GITHUB_TOKEN` in the environment:
  ```
  GITHUB_TOKEN=<token> go test -tags integration ./cmd/attestward/... -run TestIntegration_DemoOrgMatchesFixtures -v
  ```
  Without `-tags integration`, this test file isn't even compiled in; with the tag
  but no `GITHUB_TOKEN`, it skips cleanly rather than failing.

  **PAT provisioning for CI** (`.github/workflows/integration-scan.yaml`'s
  scheduled run): needs a `DEMO_ORG_PAT` repository secret — a fine-grained,
  read-only PAT scoped to the `Qloud-LTD` org (or at minimum its `demo-good`/
  `demo-bad` repos) with the same read permissions documented in the README's
  token table (`read:org` equivalent, `Administration: read-only`,
  `Actions: read-only`, plus admin-level repo read for `security_and_analysis`/
  vulnerability-alerts — see C04's collector doc comment on that last one).
  GitHub has no API to create a PAT (fine-grained token creation is a web-UI-only,
  human-authorized action by design), so this can't be automated — a repo admin
  must create it at github.com/settings/tokens and set it manually:
  ```
  gh secret set DEMO_ORG_PAT --repo sioakim/attestward
  ```
  GitHub also auto-disables a repo's scheduled (`cron`) workflows after 60 days
  of repository inactivity — if `integration-scan.yaml` ever appears to have
  stopped running on schedule, check Settings → Actions for a disabled-workflow
  notice before assuming the drift tripwire itself is broken; `workflow_dispatch`
  still works either way and re-enables it.
- **Renderer tests:** golden files under `testdata/golden/`.

## Contributing mappings and scanner signatures

The most valuable non-Go contributions:

- **New verification check** → use the "New check proposal" issue template. A check needs:
  what API evidence proves it, which SSDF task(s) it maps to, and its failure semantics.
- **New scanner signature** (SAST/SCA/container/secrets/SBOM/provenance tool detection) →
  use the "New scanner signature" issue template, then PR the YAML addition below.

Mapping changes bump the mapping file's `version:` field in the same PR.

### Adding a scanner signature

`mappings/scanner-signatures.yaml` entries have this shape (see
`docs/schema/mapping-scanner-signatures.schema.json` for the enforced schema, and
`internal/mapping/scannersig.go`'s `decodeScannerSignatures` for the extra checks the
schema alone can't express — duplicate IDs, unrecognized categories, malformed regexes):

```yaml
- id: my-tool                      # unique, lowercase-hyphenated
  name: "My Tool"                  # human-readable
  category: sast                   # sast | sca | container | secrets | sbom | provenance
  detect:
    actions:                       # `uses:` slugs (before the `@ref`), high confidence
      - slug: someorg/my-tool-action
        # version: "v2"            # optional, EXACT STRING match against the ref after
        #                          # `@` — "v2" does not match "v2.1.0" or a SHA pin (this
        #                          # repo's own workflows SHA-pin everything); omit unless
        #                          # you specifically need to distinguish one exact ref
    run_patterns:                  # regexes over `run:` step text, medium confidence
      - "my-tool (scan|test)"
    workflow_name_patterns:        # regexes over the workflow's own `name:`, low confidence — last resort
      - "(?i)\\bmy-tool\\b"
  run_evidence: >-
    How a run of this tool surfaces (workflow run name, check-run name, job name
    pattern) — used by C05/C06 to compute per-release scan cadence.
```

At least one of `actions`/`run_patterns`/`workflow_name_patterns` should be non-empty —
an empty `detect` block never matches anything (the one deliberate exception is
`dependabot`, whose real detection is a config file's presence, not workflow content;
see that entry's own comment). Prefer `actions` over `run_patterns` where the tool has
one canonical action slug: it's a much stronger signal than a CLI-invocation regex, which
could in principle appear in an unrelated comment or string.

**Fixture requirement**: add a minimal, realistic workflow file under
`internal/mapping/testdata/workflows/<id>.yaml` containing the step(s) your signature is
meant to detect, and add an entry to `internal/mapping/scannermatch_test.go`'s
`fixtureExpectations` table. `TestMatchWorkflow_CrossMatrix` then proves two things at
once: your new signature actually matches its own fixture at the confidence you claimed,
and it does *not* also fire on every other signature's fixture (no accidental overlap in
an action slug or regex).

## Docs

- Behavior or architecture changes update `docs/` in the same PR.
- Significant design choices get an ADR (`docs/adr/`).
- `CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com); add your entry
  under `Unreleased`.
- **State current status, not history.** `README.md`, `CONTRIBUTING.md`, and
  other docs describe *what is true now*, not the sequence of PRs/issues that got there
  — readers don't care how a decision was reached, only what it is; git history and
  issue threads are where the "how we got here" story already lives, and duplicating it
  in prose just goes stale. This means cutting the *event sequence* ("we first tried X,
  then switched to Y"), not the *rationale* — keep whatever constraint or tradeoff makes
  a decision what it is, since that's the part a reader
  actually needs to judge or revisit it later. Exception: a genuinely major change worth
  calling out explicitly (e.g. a regulatory shift the tool's own claims depend on) — use
  judgment, but default to terse and current.

## License

By contributing you agree that your contributions are licensed under Apache-2.0.
