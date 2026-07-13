# ADR-0001: Record architecture decisions

**Status:** Accepted · **Date:** 2026-07-13

## Context

This tool will be audited by security teams before they run it inside their organizations.
The *reasoning* behind design choices is part of the audit surface: a reviewer who can see
why a dependency exists or why data is handled a certain way can clear the tool faster.
Team memory alone does not survive contributor turnover on an open-source project.

## Decision

Record every significant architectural decision as a numbered ADR in `docs/adr/`, using
the Nygard format (Context → Decision → Consequences). ADRs are immutable once accepted;
a change of course produces a new ADR that supersedes the old one.

## Consequences

- Reviewers and new contributors get the "why" without archaeology through issues.
- Small writing overhead per significant decision.
- Open (undecided) questions live in `DECISIONS.md` at the repo root, not here.
