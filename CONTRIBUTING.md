# Contributing

Thanks for your interest. The canonical repo is **[gitlab.com/sioakeim/attestward](https://gitlab.com/sioakeim/attestward)**
— that's where issues, merge requests, CI, and releases all live. This project is built
issue-first: **GitLab Issues are the task board** — every piece of work (feature, bug,
doc, mapping change) has an issue, and the issue thread is the record of what was decided
and why.

The code is also mirrored, read-only, to [github.com/QloudLTD/attestward](https://github.com/QloudLTD/attestward)
(Issues and Actions disabled there) and [gogs.ioakeim.com/sioakim/attestward](https://gogs.ioakeim.com/sioakim/attestward)
for visibility — neither mirror is monitored for issues or pull requests. Open issues and
merge requests on GitLab; anything filed against a mirror won't be seen.

## Ground rules

- **Read-only forever.** No MR that adds a write operation against any platform API will
  be accepted. See [ADR-0004](docs/adr/0004-read-only-local-first.md).
- **Accuracy discipline.** SSDF task IDs, CISA form language, and regulatory citations
  must be verified against primary sources (NIST SP 800-218, CISA SSDA form instructions).
  Paraphrases are marked as paraphrases. Never invent control IDs.
- **Boring, auditable code.** New dependencies need explicit justification in the MR.
  When in doubt between two designs, pick the one that is simpler to audit.
- **Tests are not optional.** Every collector change ships with fixture-based unit tests.

## Workflow

1. Find or create a GitLab issue. Comment your approach before writing code.
2. Branch from `main`: `<type>/<issue-number>-<short-description>`
   (e.g. `feature/12-repo-protection-collector`; types: `feature|fix|hotfix|chore|docs`).
3. Small MRs (merge requests) — target under 200 changed lines, hard ceiling 400. Split
   bigger work.
4. Conventional commits: `feat(collect): add repo-protection ruleset checks`
   (types: `feat|fix|chore|docs|refactor|test|style|perf`; imperative mood). Put a closing
   keyword in the MR description (`Closes #12`) so merging to `main` auto-closes the
   issue — GitLab records the close event AND every comment/note independently, so nothing
   is lost the way it would be under a squash that discards commit-level history. Leave a
   note on the issue itself summarizing what changed and why before (or as part of)
   merging, since that note is the durable record, not the commit message.
5. CI must be green — the project has `only_allow_merge_if_pipeline_succeeds` enabled, so
   GitLab itself blocks the merge button until the whole pipeline (`lint`, `test`, the
   drift-check jobs, `build`) passes. Merges are real merge commits, not squashed
   (`merge_method: merge`, `squash_option: default_off`) — commit-level history survives
   on `main`.
6. The source branch is auto-deleted on merge (`remove_source_branch_after_merge`).

`main` is a protected branch: only Maintainers can push or merge to it directly, and
force-push is disallowed (`allow_force_push: false`). Maintainers can still push directly
in an emergency — documented here rather than left implicit, so a solo maintainer isn't
deadlocked by their own rules — but default to the MR workflow above even as the sole
maintainer.

## Maintainers: keeping the mirrors in sync

After any merge to `main` or new tag on GitLab (the canonical repo), push the same `main`
and tags to both read-only mirrors so all three stay byte-identical:

```bash
git push github main:main && git push github --tags
git push gogs main:main    && git push gogs --tags
```

This is a maintainer operation, not part of the contributor workflow above — contributors
never need `github`/`gogs` remotes configured locally. Before ever force-pushing to either
mirror, check whether its branch has diverged (`git fetch <remote> && git rev-list
<remote>/main --not main`) — a mirror's history should only ever move forward from
GitLab's; if it hasn't, something was pushed there directly and needs investigating before
being overwritten, not silently discarded.

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
- **Integration tests:** run against the public demo org (`Qloud-ltd-com` — see
  `hack/demo-org-setup.sh` and `fixtures.yaml`), gated
  behind `//go:build integration` so `go test ./...` stays offline-safe. Run
  locally with a `GITHUB_TOKEN` in the environment:
  ```
  GITHUB_TOKEN=<token> go test -tags integration ./cmd/attestward/... -run TestIntegration_DemoOrgMatchesFixtures -v
  ```
  Without `-tags integration`, this test file isn't even compiled in; with the tag
  but no `GITHUB_TOKEN`, it skips cleanly rather than failing. The `azuredevops` twin
  (`TestIntegration_ADODemoOrgMatchesFixtures`, `integration_ado_test.go`) works the
  same way against `AZURE_DEVOPS_EXT_PAT`.

  These are currently run manually, not on a CI schedule — `.gitlab-ci.yml`'s stages
  (`verify`, `build`, `release`) don't include a scheduled integration job. The
  `.github/workflows/integration-scan.yaml` file describes what a scheduled GitHub
  Actions run of this test would look like (including how to provision the
  `DEMO_ORG_PAT` secret it would need), but GitHub Actions is disabled on the GitHub
  mirror, so that workflow does not run — treat it as a reference for wiring up a
  scheduled run on GitLab CI, not as live infrastructure.
- **Renderer tests:** golden files under `testdata/golden/`.

## Contributing mappings and scanner signatures

The most valuable non-Go contributions:

- **New verification check** → open a GitLab issue and pick the **"New Check Proposal"**
  description template (`.gitlab/issue_templates/`) from the template dropdown. A check
  needs: what API evidence proves it, which SSDF task(s) it maps to, and its failure
  semantics.
- **New scanner signature** (SAST/SCA/container/secrets/SBOM/provenance tool detection) →
  open a GitLab issue with the **"New Scanner Signature"** template, then MR the YAML
  addition below.

Mapping changes bump the mapping file's `version:` field in the same MR.

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

- Behavior or architecture changes update `docs/` in the same MR.
- Significant design choices get an ADR (`docs/adr/`).
- `CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com); add your entry
  under `Unreleased`.
- **State current status, not history.** `README.md`, `CONTRIBUTING.md`, and
  other docs describe *what is true now*, not the sequence of MRs/issues that got there
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
