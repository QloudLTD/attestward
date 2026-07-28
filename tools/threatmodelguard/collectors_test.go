package main

import (
	"os"
	"path/filepath"
	"testing"
)

const realCollectorSrc = `package example

import "context"

type Collector struct{}

func (c *Collector) Collect(ctx context.Context, scope int) ([]int, error) {
	return nil, nil
}
`

// sharedHelperSrc is the adofixture/pipelinehistory shape: a package that
// lives alongside real collectors but exposes no Collect method at all.
const sharedHelperSrc = `package example

type Helper struct{}

func (h *Helper) DoSomething() error {
	return nil
}
`

func writeGoFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestAdoCollectorPackages_ExcludesSharedHelpers is the unit test issue
// #274 asks for directly: the enumeration finds real collector packages
// and excludes a package with no Collect(ctx...) method — the
// adofixture/pipelinehistory shape — based on the method's absence, not
// its name.
func TestAdoCollectorPackages_ExcludesSharedHelpers(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, filepath.Join(dir, "orgsecurity", "orgsecurity.go"), realCollectorSrc)
	writeGoFile(t, filepath.Join(dir, "vdp", "vdp.go"), realCollectorSrc)
	writeGoFile(t, filepath.Join(dir, "adofixture", "adofixture.go"), sharedHelperSrc)
	writeGoFile(t, filepath.Join(dir, "pipelinehistory", "pipelinehistory.go"), sharedHelperSrc)

	got, err := adoCollectorPackages(dir)
	if err != nil {
		t.Fatalf("adoCollectorPackages: %v", err)
	}
	want := []string{"orgsecurity", "vdp"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("adoCollectorPackages = %v, want %v — adofixture/pipelinehistory must be excluded", got, want)
	}
}

// TestAdoCollectorListFromDoc_MentionElsewhereDoesNotCount pins the
// scoping requirement #274 calls out directly (and #286 found missing in
// a sibling guard): a package name backtick-quoted somewhere else in the
// document must not satisfy the claim unless it's actually inside the
// "ADO collector packages" brace list itself.
func TestAdoCollectorListFromDoc_MentionElsewhereDoesNotCount(t *testing.T) {
	doc := []byte("Some other section mentions `newcollector` in passing, unrelated to the list.\n\n" +
		"none of the ADO collector packages (`internal/collect/azuredevops/{orgsecurity, vdp}/`) " +
		"is exhaustively enumerated here\n")
	got, err := adoCollectorListFromDoc(doc)
	if err != nil {
		t.Fatalf("adoCollectorListFromDoc: %v", err)
	}
	if got["newcollector"] {
		t.Errorf("a bare backtick mention outside the brace list must not count as listed, got %v", got)
	}
	if !got["orgsecurity"] || !got["vdp"] {
		t.Errorf("expected the real brace-list entries to be listed, got %v", got)
	}
}

func TestAdoCollectorListFromDoc_Absent(t *testing.T) {
	if _, err := adoCollectorListFromDoc([]byte("nothing relevant here\n")); err == nil {
		t.Error("expected an error when the brace-list doesn't exist, got nil")
	}
}

// TestAdoCollectorListFromDoc_MultipleConstructsErrors is issue #302's gap
// 2: FindSubmatch used to bind to whichever construct came first in the
// document, so a second complete (or even partial) brace-expansion
// elsewhere shadowed or was shadowed by the real one with no signal either
// way. FindAllSubmatch plus an explicit count check turns that into a
// loud error instead of a silent pick — proven here for a decoy before the
// real list, a decoy after it, and a decoy with a different (partial)
// membership, since all three are "more than one construct" regardless of
// position or content.
func TestAdoCollectorListFromDoc_MultipleConstructsErrors(t *testing.T) {
	realList := "none of the ADO collector packages (`internal/collect/azuredevops/{orgsecurity, vdp}/`) " +
		"is exhaustively enumerated here\n"
	completeDecoy := "Test decoy: `internal/collect/azuredevops/{orgsecurity, vdp}/` appears here.\n\n"
	partialDecoy := "Test decoy: `internal/collect/azuredevops/{orgsecurity}/` appears here.\n\n"

	cases := map[string]string{
		"complete decoy before the real list": completeDecoy + realList,
		"complete decoy after the real list":  realList + "\n" + completeDecoy,
		"partial decoy before the real list":  partialDecoy + realList,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := adoCollectorListFromDoc([]byte(doc))
			if err == nil {
				t.Fatal("expected an error when more than one brace-list construct is present, got nil")
			}
		})
	}
}

func TestMissingADOCollectors(t *testing.T) {
	listed := map[string]bool{"orgsecurity": true, "vdp": true}
	got := missingADOCollectors([]string{"orgsecurity", "vdp", "newcollector"}, listed)
	if len(got) != 1 || got[0] != "newcollector" {
		t.Errorf("missingADOCollectors = %v, want [newcollector]", got)
	}
}

// TestExtraADOCollectors is issue #302's gap 3, the reverse direction:
// a name left in the doc's list with no matching real package — deleted,
// renamed, or a ghostpackage that never existed — must be flagged.
func TestExtraADOCollectors(t *testing.T) {
	listed := map[string]bool{"orgsecurity": true, "vdp": true, "ghostpackage": true}
	got := extraADOCollectors([]string{"orgsecurity", "vdp"}, listed)
	if len(got) != 1 || got[0] != "ghostpackage" {
		t.Errorf("extraADOCollectors = %v, want [ghostpackage]", got)
	}
}

// TestRunADOCollectors_MutationProof is issue #274's own mutation-proof
// requirement, the same shape as #260's TestRun_MutationProof: a real
// collector package the doc doesn't name must be flagged by name, and
// adding it to the doc must silence the flag.
func TestRunADOCollectors_MutationProof(t *testing.T) {
	dir := t.TempDir()
	collectDir := filepath.Join(dir, "azuredevops")
	writeGoFile(t, filepath.Join(collectDir, "orgsecurity", "orgsecurity.go"), realCollectorSrc)
	writeGoFile(t, filepath.Join(collectDir, "vdp", "vdp.go"), realCollectorSrc)
	writeGoFile(t, filepath.Join(collectDir, "adofixture", "adofixture.go"), sharedHelperSrc)
	docPath := filepath.Join(dir, "threat-model.md")

	t.Run("flags an undocumented collector package", func(t *testing.T) {
		writeGoFile(t, docPath, "none of the ADO collector packages "+
			"(`internal/collect/azuredevops/{orgsecurity}/`) is exhaustively enumerated here\n")
		missing, extra, err := runADOCollectors(collectDir, docPath)
		if err != nil {
			t.Fatalf("runADOCollectors: %v", err)
		}
		if len(missing) != 1 || missing[0] != "vdp" {
			t.Errorf("missing = %v, want exactly [vdp]", missing)
		}
		if len(extra) != 0 {
			t.Errorf("extra = %v, want none", extra)
		}
	})

	t.Run("silent once every collector package is named", func(t *testing.T) {
		writeGoFile(t, docPath, "none of the ADO collector packages "+
			"(`internal/collect/azuredevops/{orgsecurity, vdp}/`) is exhaustively enumerated here\n")
		missing, extra, err := runADOCollectors(collectDir, docPath)
		if err != nil {
			t.Fatalf("runADOCollectors: %v", err)
		}
		if len(missing) != 0 {
			t.Errorf("expected no findings once every collector package is named, got %v", missing)
		}
		if len(extra) != 0 {
			t.Errorf("extra = %v, want none", extra)
		}
	})

	t.Run("flags a listed package with no matching real package", func(t *testing.T) {
		writeGoFile(t, docPath, "none of the ADO collector packages "+
			"(`internal/collect/azuredevops/{orgsecurity, vdp, ghostpackage}/`) is exhaustively enumerated here\n")
		missing, extra, err := runADOCollectors(collectDir, docPath)
		if err != nil {
			t.Fatalf("runADOCollectors: %v", err)
		}
		if len(missing) != 0 {
			t.Errorf("missing = %v, want none", missing)
		}
		if len(extra) != 1 || extra[0] != "ghostpackage" {
			t.Errorf("extra = %v, want exactly [ghostpackage]", extra)
		}
	})
}

// TestRunADOCollectors_SilentOnRealRepo runs the actual guard against
// this repo's own internal/collect/azuredevops and docs/threat-model.md
// — the property issue #274 exists to guarantee: today's "ADO collector
// packages" list is current.
func TestRunADOCollectors_SilentOnRealRepo(t *testing.T) {
	missing, extra, err := runADOCollectors(repoADOCollectDir(t), repoThreatModelPath(t))
	if err != nil {
		t.Fatalf("runADOCollectors: %v", err)
	}
	if len(missing) != 0 {
		t.Errorf("expected the real threat-model.md to name every ADO collector package, got missing: %v", missing)
	}
	if len(extra) != 0 {
		t.Errorf("expected the real threat-model.md to name only real ADO collector packages, got extra: %v", extra)
	}
}

// repoADOCollectDir locates internal/collect/azuredevops relative to this
// test file's own module root, independent of `go test`'s working
// directory — mirrors scan_test.go's repoWorkflowsDir.
func repoADOCollectDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "..", "..", "internal", "collect", "azuredevops")
}

func repoThreatModelPath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "..", "..", "docs", "threat-model.md")
}
