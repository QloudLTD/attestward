# agents/

Agent skills for working with Attestward.

A **skill** is a set of instructions an AI coding agent (Claude Code, or anything else
that reads this format) loads when it needs to perform a specific task. Each lives in its
own directory as `SKILL.md`, with YAML frontmatter declaring a `name` and a `description`
— the description is what the agent matches against to decide the skill is relevant.

| Skill | What it does |
|---|---|
| [`attestward-scan/`](attestward-scan/SKILL.md) | Build Attestward from source and run a first scan: checks prerequisites, clones and builds, gathers the platform/org/token details interactively, runs the scan, and walks through the resulting evidence pack. |

## Using one

With Claude Code, the skills here are picked up when this repository is the working
directory. Invoke by name (`/attestward-scan`) or just describe the task — *"scan my org
with attestward"* — and the agent matches the description.

With any other agent, point it at the `SKILL.md` file directly; they are plain Markdown
and readable on their own.

## The one rule these inherit

Attestward is **read-only, forever** ([ADR-0004](../docs/adr/0004-read-only-local-first.md)).
No skill here may instruct an agent to perform a write operation against any platform API.
Every command a skill runs must be a read, a local build, or a local file write under a
directory the user chose.
