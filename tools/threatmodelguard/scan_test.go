package main

import (
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
