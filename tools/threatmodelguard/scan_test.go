package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func mustParseJob(t *testing.T, src string) job {
	t.Helper()
	var wf workflowFile
	if err := yaml.Unmarshal([]byte(src), &wf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	j, ok := wf.Jobs["x"]
	if !ok {
		t.Fatalf("fixture must define a job named x: %s", src)
	}
	return j
}

func TestJobLabelSets_PlainList(t *testing.T) {
	j := mustParseJob(t, "jobs:\n  x:\n    runs-on: [self-hosted, macOS]\n")
	sets, err := jobLabelSets(j)
	if err != nil {
		t.Fatalf("jobLabelSets: %v", err)
	}
	if len(sets) != 1 || !isMacOSSelfHosted(sets[0]) {
		t.Errorf("sets = %v, want one self-hosted-macOS set", sets)
	}
}

func TestJobLabelSets_BareScalar(t *testing.T) {
	j := mustParseJob(t, "jobs:\n  x:\n    runs-on: ubuntu-latest\n")
	sets, err := jobLabelSets(j)
	if err != nil {
		t.Fatalf("jobLabelSets: %v", err)
	}
	if len(sets) != 1 || isMacOSSelfHosted(sets[0]) {
		t.Errorf("sets = %v, want one non-macOS set", sets)
	}
}

// TestJobLabelSets_MatrixIndirection is multi-arch-build-sample.yaml's own
// `build` job shape: runs-on indirects through `${{ matrix.os }}`, and
// each strategy.matrix.include entry supplies its own os: list — the
// parsing risk to get right.
func TestJobLabelSets_MatrixIndirection(t *testing.T) {
	src := `jobs:
  x:
    strategy:
      matrix:
        include:
          - goos: linux
            os: [self-hosted, Linux, X64]
          - goos: darwin
            os: [self-hosted, macOS]
    runs-on: ${{ matrix.os }}
`
	j := mustParseJob(t, src)
	sets, err := jobLabelSets(j)
	if err != nil {
		t.Fatalf("jobLabelSets: %v", err)
	}
	if len(sets) != 2 {
		t.Fatalf("got %d label sets, want 2 (one per matrix leg): %v", len(sets), sets)
	}
	sawMacOS := false
	for _, s := range sets {
		if isMacOSSelfHosted(s) {
			sawMacOS = true
		}
	}
	if !sawMacOS {
		t.Errorf("no leg resolved to self-hosted macOS, want the darwin leg to: %v", sets)
	}
}

// TestJobLabelSets_MatrixLegWithoutOS confirms an include entry that
// doesn't vary the runner (no os: key) is skipped, not an error — a
// matrix can legitimately vary other fields while every leg shares one
// runner.
func TestJobLabelSets_MatrixLegWithoutOS(t *testing.T) {
	src := `jobs:
  x:
    strategy:
      matrix:
        include:
          - goarch: amd64
          - goarch: arm64
    runs-on: ${{ matrix.os }}
`
	j := mustParseJob(t, src)
	sets, err := jobLabelSets(j)
	if err != nil {
		t.Fatalf("jobLabelSets: %v", err)
	}
	if len(sets) != 0 {
		t.Errorf("sets = %v, want none — neither matrix leg defines os:", sets)
	}
}

func TestIsMacOSSelfHosted(t *testing.T) {
	cases := []struct {
		labels []string
		want   bool
	}{
		{[]string{"self-hosted", "macOS"}, true},
		{[]string{"self-hosted", "Linux", "X64"}, false},
		{[]string{"macOS"}, false}, // hosted macos-latest-style, not self-hosted
		{[]string{"ubuntu-latest"}, false},
		{[]string{"self-hosted", "MACOS"}, true}, // case-insensitive hedge
	}
	for _, c := range cases {
		if got := isMacOSSelfHosted(c.labels); got != c.want {
			t.Errorf("isMacOSSelfHosted(%v) = %v, want %v", c.labels, got, c.want)
		}
	}
}

// TestSelfHostedMacOSJobs_RealWorkflows runs the scanner against this
// repo's own .github/workflows — the same fixture main_test.go's
// TestRun_SilentOnRealRepo uses for the doc-comparison half — and checks
// for a few jobs known (by direct inspection, not assumed) to be
// self-hosted macOS today, plus one known not to be, rather than
// asserting an exhaustive list that would itself need maintaining.
func TestSelfHostedMacOSJobs_RealWorkflows(t *testing.T) {
	names, err := selfHostedMacOSJobs(repoWorkflowsDir(t))
	if err != nil {
		t.Fatalf("selfHostedMacOSJobs: %v", err)
	}
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	for _, want := range []string{"lint", "clean", "attach-to-release", "build"} {
		if !set[want] {
			t.Errorf("expected %q among self-hosted macOS jobs, got %v", want, names)
		}
	}
	if set["test-linux"] {
		t.Errorf("test-linux runs on Linux, not macOS — got it anyway in %v", names)
	}
}

func TestRunnerStateSection_ScopesToTheOneBullet(t *testing.T) {
	doc := []byte(`## Residual risks

  - **Some other risk.** Mentions ` + "`build`" + ` here, which must not count.
  - **Shared, persistent runner state is not wiped.** Mentions ` + "`lint`" + ` and ` + "`test`" + ` here.
  - **A later risk.** Mentions ` + "`clean`" + ` here, which must not count either.

## See also
`)
	section, err := runnerStateSection(doc)
	if err != nil {
		t.Fatalf("runnerStateSection: %v", err)
	}
	for _, want := range []string{"`lint`", "`test`"} {
		if !strings.Contains(section, want) {
			t.Errorf("section missing %s: %q", want, section)
		}
	}
	for _, mustNotContain := range []string{"`build`", "`clean`"} {
		if strings.Contains(section, mustNotContain) {
			t.Errorf("section leaked content from a neighboring bullet (%s): %q", mustNotContain, section)
		}
	}
}

// TestRunnerStateSection_ScopesPastA0IndentBullet is issue #286's finding 2:
// the residual-risks list's own bullets are 0-indent ("- **"), the level a
// sibling risk actually gets appended at — the old marker set
// ("\n  - **", "\n## ") had no 0-indent terminator at all, so a job name
// mentioned in the very next real-world edit (a new top-level residual
// risk) would have silently satisfied this guard.
func TestRunnerStateSection_ScopesPastA0IndentBullet(t *testing.T) {
	doc := []byte(`## Residual risks

  - **Shared, persistent runner state is not wiped.** Mentions ` + "`lint`" + ` here.
- **A sibling top-level risk.** Mentions ` + "`test`" + ` here, which must not count.

## See also
`)
	section, err := runnerStateSection(doc)
	if err != nil {
		t.Fatalf("runnerStateSection: %v", err)
	}
	if !strings.Contains(section, "`lint`") {
		t.Errorf("section missing `lint`: %q", section)
	}
	if strings.Contains(section, "`test`") {
		t.Errorf("section leaked past a 0-indent sibling bullet: %q", section)
	}
}

// TestRunnerStateSection_ScopesPastASubsectionHeading is issue #286's
// finding 2: a "### " subsection heading didn't terminate the section
// either, so content under one — e.g. a "## See also"-style cross-
// reference list one level down — could leak a job name in without it
// counting as documented in the bullet itself.
func TestRunnerStateSection_ScopesPastASubsectionHeading(t *testing.T) {
	doc := []byte(`## Residual risks

  - **Shared, persistent runner state is not wiped.** Mentions ` + "`lint`" + ` here.

### Some subsection

Mentions ` + "`test`" + ` here, which must not count.

## See also
`)
	section, err := runnerStateSection(doc)
	if err != nil {
		t.Fatalf("runnerStateSection: %v", err)
	}
	if !strings.Contains(section, "`lint`") {
		t.Errorf("section missing `lint`: %q", section)
	}
	if strings.Contains(section, "`test`") {
		t.Errorf("section leaked past a ### subsection heading: %q", section)
	}
}

func TestRunnerStateSection_Absent(t *testing.T) {
	if _, err := runnerStateSection([]byte("# nothing relevant here\n")); err == nil {
		t.Error("expected an error when the bullet doesn't exist, got nil")
	}
}

func TestMissingFromDoc(t *testing.T) {
	section := "mentions `lint` and `test` but not the third one"
	got := missingFromDoc([]string{"lint", "test", "clean"}, section)
	if len(got) != 1 || got[0] != "clean" {
		t.Errorf("missingFromDoc = %v, want [clean]", got)
	}
}

// TestMissingFromDoc_SubstringCollisionDoesNotSatisfy pins the reason
// missingFromDoc backtick-delimits its match ("`"+name+"`", not a bare
// strings.Contains(section, name)) rather than just checking the name
// appears somewhere: `build` is a genuine substring of `build-windows`, so a
// bare substring check would wrongly read a section naming only
// `build-windows` as also documenting `build`. Round 2 review of #260
// found this specific mutation (drop the backticks) left the whole package
// green — no test pinned it. Mutation-proved: reverted to a bare
// strings.Contains match, confirmed this test (and only this test) fails,
// restored.
func TestMissingFromDoc_SubstringCollisionDoesNotSatisfy(t *testing.T) {
	got := missingFromDoc([]string{"build"}, "mentions only `build-windows`")
	if len(got) != 1 || got[0] != "build" {
		t.Errorf("missingFromDoc([]string{\"build\"}, ...) = %v, want [build] — `build-windows` must not satisfy `build`", got)
	}
}

// repoWorkflowsDir locates .github/workflows relative to this test file's
// own module root, independent of `go test`'s working directory (always
// the package directory, tools/threatmodelguard here).
func repoWorkflowsDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "..", "..", ".github", "workflows")
}
