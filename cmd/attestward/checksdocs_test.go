package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRunChecksDocsGen_WritesFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "checks-reference.md")

	var stdout bytes.Buffer
	if err := runChecksDocsGen(&stdout, out, false); err != nil {
		t.Fatalf("runChecksDocsGen: %v", err)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read %s: %v", out, err)
	}
	if !bytes.HasPrefix(got, []byte("# Checks Reference")) {
		t.Errorf("expected output to start with '# Checks Reference', got: %.80s", got)
	}
	if !bytes.Contains(got, []byte("## C01.org-security")) {
		t.Error("expected the real registry's C01.org-security collector group to appear")
	}
}

func TestRunChecksDocsGen_CreatesMissingOutputDir(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "nested", "checks-reference.md")

	var stdout bytes.Buffer
	if err := runChecksDocsGen(&stdout, out, false); err != nil {
		t.Fatalf("runChecksDocsGen: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("expected %s to exist: %v", out, err)
	}
}

func TestRunChecksDocsGen_CheckPassesWhenUpToDate(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "checks-reference.md")

	var stdout bytes.Buffer
	if err := runChecksDocsGen(&stdout, out, false); err != nil {
		t.Fatalf("runChecksDocsGen (write): %v", err)
	}
	if err := runChecksDocsGen(&stdout, out, true); err != nil {
		t.Errorf("runChecksDocsGen (--check) on freshly-written file: %v", err)
	}
}

func TestRunChecksDocsGen_CheckFailsWhenStale(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "checks-reference.md")
	if err := os.WriteFile(out, []byte("stale content\n"), 0o644); err != nil {
		t.Fatalf("write stale fixture: %v", err)
	}

	var stdout bytes.Buffer
	err := runChecksDocsGen(&stdout, out, true)
	if err == nil {
		t.Fatal("runChecksDocsGen (--check) against stale content: got nil error, want a drift failure")
	}
}

func TestRunChecksDocsGen_CheckFailsWhenMissing(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "checks-reference.md")

	var stdout bytes.Buffer
	err := runChecksDocsGen(&stdout, out, true)
	if err == nil {
		t.Fatal("runChecksDocsGen (--check) against a missing file: got nil error, want an error")
	}
}

func TestRunChecksDocsGen_Deterministic(t *testing.T) {
	dir := t.TempDir()
	out1 := filepath.Join(dir, "a.md")
	out2 := filepath.Join(dir, "b.md")

	var stdout bytes.Buffer
	if err := runChecksDocsGen(&stdout, out1, false); err != nil {
		t.Fatalf("runChecksDocsGen (1): %v", err)
	}
	if err := runChecksDocsGen(&stdout, out2, false); err != nil {
		t.Fatalf("runChecksDocsGen (2): %v", err)
	}

	a, err := os.ReadFile(out1)
	if err != nil {
		t.Fatalf("read %s: %v", out1, err)
	}
	b, err := os.ReadFile(out2)
	if err != nil {
		t.Fatalf("read %s: %v", out2, err)
	}
	if !bytes.Equal(a, b) {
		t.Error("two independent runs against the same (unchanged) registry produced different bytes")
	}
}
