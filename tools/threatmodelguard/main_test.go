package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const fixtureWorkflow = `on: push
jobs:
  documented-job:
    runs-on: [self-hosted, macOS]
    steps: []
  undocumented-job:
    runs-on: [self-hosted, macOS]
    steps: []
  linux-job:
    runs-on: [self-hosted, Linux, X64]
    steps: []
`

// TestRun_MutationProof is issue #260's own mutation-proof requirement:
// a self-hosted macOS job the doc doesn't mention must be flagged by
// name, and adding it to the doc must silence the flag.
func TestRun_MutationProof(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "workflows", "ci.yaml"), fixtureWorkflow)

	t.Run("flags an undocumented job", func(t *testing.T) {
		writeFile(t, filepath.Join(dir, "threat-model.md"), "## Residual risks\n\n"+
			"  - **Shared, persistent runner state is not wiped.** (every macOS-labeled job "+
			"in this repo: `documented-job`).\n\n"+
			"## See also\n")
		missing, err := run(filepath.Join(dir, "workflows"), filepath.Join(dir, "threat-model.md"))
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if len(missing) != 1 || missing[0] != "undocumented-job" {
			t.Errorf("missing = %v, want exactly [undocumented-job]", missing)
		}
	})

	t.Run("silent once every macOS job is named", func(t *testing.T) {
		writeFile(t, filepath.Join(dir, "threat-model.md"), "## Residual risks\n\n"+
			"  - **Shared, persistent runner state is not wiped.** (every macOS-labeled job "+
			"in this repo: `documented-job`, `undocumented-job`).\n\n"+
			"## See also\n")
		missing, err := run(filepath.Join(dir, "workflows"), filepath.Join(dir, "threat-model.md"))
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if len(missing) != 0 {
			t.Errorf("expected no findings once every macOS job is named, got %v", missing)
		}
	})

	// Round 2 review of #260: a forward cross-reference to the bare phrase
	// — "(see the Shared, persistent runner state residual risk below)", a
	// style this document and ci.yaml's own comments already use — used to
	// become "the section" under strings.Index's first-match behavior,
	// since it appears earlier in the document than the real bullet. Every
	// real job then read as undocumented against a completely correct
	// doc — reviewer proved this exact shape produces missing=[alpha] on a
	// doc that names alpha. bulletStartRe's line-anchored "  - **" prefix
	// can't match a parenthetical mention, only the real bullet.
	t.Run("a forward cross-reference to the bare phrase doesn't fool the section scan", func(t *testing.T) {
		writeFile(t, filepath.Join(dir, "threat-model.md"), "## Overview\n\n"+
			"Some other risk (see the Shared, persistent runner state residual risk "+
			"below for the full list of affected jobs).\n\n"+
			"## Residual risks\n\n"+
			"  - **Shared, persistent runner state is not wiped.** (every macOS-labeled job "+
			"in this repo: `documented-job`, `undocumented-job`).\n\n"+
			"## See also\n")
		missing, err := run(filepath.Join(dir, "workflows"), filepath.Join(dir, "threat-model.md"))
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if len(missing) != 0 {
			t.Errorf("a forward cross-reference before the real bullet caused false positives; missing = %v, want none", missing)
		}
	})
}

// TestRun_YmlExtensionWorkflowsAreScanned is round 2 review of #260: a
// self-hosted-macOS job living in a .yml-suffixed workflow (GitHub Actions
// accepts either extension; this repo already uses .yml elsewhere —
// dependabot.yml, every ISSUE_TEMPLATE/*.yml) used to be invisible to a
// .yaml-only glob, silently missing from the scan rather than flagged.
func TestRun_YmlExtensionWorkflowsAreScanned(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "workflows", "new.yml"), fixtureWorkflow)
	writeFile(t, filepath.Join(dir, "threat-model.md"), "## Residual risks\n\n"+
		"  - **Shared, persistent runner state is not wiped.** (every macOS-labeled job "+
		"in this repo: `documented-job`).\n\n"+
		"## See also\n")

	missing, err := run(filepath.Join(dir, "workflows"), filepath.Join(dir, "threat-model.md"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(missing) != 1 || missing[0] != "undocumented-job" {
		t.Errorf(".yml workflow's undocumented job not detected; missing = %v, want exactly [undocumented-job]", missing)
	}
}

// TestRun_ReusableWorkflowCallJobIsSkippedNotError is round 2 review of
// #260: a job-level `uses:` (a reusable-workflow call) has no `runs-on` at
// all, decoding to RunsOn's zero Kind — jobLabelSets' old default branch
// hard-errored on any unrecognized shape, so one reusable call anywhere in
// the workflow tree aborted the whole guard and reported nothing, even for
// an otherwise-undocumented macOS job in a *different* file. Worse than
// missing that one job: it silenced every real finding too.
func TestRun_ReusableWorkflowCallJobIsSkippedNotError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "workflows", "reusable-caller.yaml"), `on: push
jobs:
  call-shared:
    uses: ./.github/workflows/shared.yaml
`)
	writeFile(t, filepath.Join(dir, "workflows", "ci.yaml"), fixtureWorkflow)
	writeFile(t, filepath.Join(dir, "threat-model.md"), "## Residual risks\n\n"+
		"  - **Shared, persistent runner state is not wiped.** (every macOS-labeled job "+
		"in this repo: `documented-job`).\n\n"+
		"## See also\n")

	missing, err := run(filepath.Join(dir, "workflows"), filepath.Join(dir, "threat-model.md"))
	if err != nil {
		t.Fatalf("run: %v (a reusable-workflow-call job must be skipped, not abort the scan)", err)
	}
	if len(missing) != 1 || missing[0] != "undocumented-job" {
		t.Errorf("reusable-call job present alongside a real undocumented job; missing = %v, want exactly [undocumented-job]", missing)
	}
}

// TestRun_MentionOutsideTheListDoesNotSatisfyMembership is issue #286's
// own reproduction in miniature: moving a name out of the exhaustive list
// into another machine's clause of the same bullet used to still pass.
func TestRun_MentionOutsideTheListDoesNotSatisfyMembership(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "workflows", "ci.yaml"), fixtureWorkflow)
	writeFile(t, filepath.Join(dir, "threat-model.md"), "## Residual risks\n\n"+
		"  - **Shared, persistent runner state is not wiped.** (every macOS-labeled job "+
		"in this repo: `documented-job`), `spyros-ionos-ssdf` (`undocumented-job`, "+
		"`test-linux`).\n\n"+
		"## See also\n")

	missing, err := run(filepath.Join(dir, "workflows"), filepath.Join(dir, "threat-model.md"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(missing) != 1 || missing[0] != "undocumented-job" {
		t.Errorf("missing = %v, want exactly [undocumented-job] — a mention in another machine's "+
			"clause of the same bullet must not satisfy the macOS list's own claim", missing)
	}
}

// TestRun_MentionsOutsideListDoNotAccumulateIntoMembership is the `build`
// shape issue #286 found: absent from the list, but mentioned three
// separate times elsewhere in the same bullet, used to still pass.
func TestRun_MentionsOutsideListDoNotAccumulateIntoMembership(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "workflows", "ci.yaml"), fixtureWorkflow)
	writeFile(t, filepath.Join(dir, "threat-model.md"), "## Residual risks\n\n"+
		"  - **Shared, persistent runner state is not wiped.** (every macOS-labeled job "+
		"in this repo: `undocumented-job`). Elsewhere in this very bullet, `documented-job` "+
		"comes up three separate times: once here, `documented-job` again right here, and a "+
		"third time, `documented-job`, here too — none of those three mentions are inside "+
		"the list that claims exhaustiveness.\n\n"+
		"## See also\n")

	missing, err := run(filepath.Join(dir, "workflows"), filepath.Join(dir, "threat-model.md"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(missing) != 1 || missing[0] != "documented-job" {
		t.Errorf("missing = %v, want exactly [documented-job] — three mentions outside the list "+
			"must not substitute for membership in it", missing)
	}
}

// TestRun_SilentOnRealRepo runs the actual guard against this repo's own
// .github/workflows and docs/threat-model.md — the property issue #260
// exists to guarantee: today's enumeration is current.
func TestRun_SilentOnRealRepo(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "..", "..")
	missing, err := run(filepath.Join(root, ".github", "workflows"), filepath.Join(root, "docs", "threat-model.md"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(missing) != 0 {
		t.Errorf("expected the real threat-model.md to name every self-hosted macOS job, got missing: %v", missing)
	}
}
