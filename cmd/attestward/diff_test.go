package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sioakim/attestward/internal/integrity"
	"github.com/sioakim/attestward/internal/model"
	"github.com/sioakim/attestward/internal/packdiff"
)

// writeDiffFixture writes pack as <dir>/<name>/evidence.json (plus its
// .sha256 sidecar when withSidecar) and returns the evidence.json path.
func writeDiffFixture(t *testing.T, dir, name string, pack model.EvidencePack, withSidecar bool) string {
	t.Helper()
	sub := filepath.Join(dir, name)
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	hash, err := writeEvidencePack(pack, sub)
	if err != nil {
		t.Fatalf("writeEvidencePack: %v", err)
	}
	path := filepath.Join(sub, "evidence.json")
	if withSidecar {
		if err := integrity.WriteSidecar(path, hash); err != nil {
			t.Fatalf("WriteSidecar: %v", err)
		}
	}
	return path
}

func diffFixturePack(status model.Status) model.EvidencePack {
	return model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "test",
		Scope:         model.ScanScope{Org: "attestward-demo", Repos: []string{"good-repo"}},
		Results: []model.CheckResult{
			{
				CheckID:    "C02.branch.required-reviews",
				Title:      "Branch protection requires reviews",
				Status:     status,
				Reason:     "fixture",
				Scope:      model.ScopeRef{Org: "attestward-demo", Repo: "good-repo"},
				Provenance: []model.Provenance{},
			},
		},
	}
}

func TestRunDiff_RegressionDetectedAcrossFormats(t *testing.T) {
	dir := t.TempDir()
	base := writeDiffFixture(t, dir, "base", diffFixturePack(model.StatusVerifiedPass), true)
	cur := writeDiffFixture(t, dir, "cur", diffFixturePack(model.StatusVerifiedFail), true)

	var out bytes.Buffer
	delta, err := runDiff(&out, base, cur, "text")
	if err != nil {
		t.Fatalf("runDiff: %v", err)
	}
	if !delta.HasRegressions() {
		t.Fatal("pass -> fail fixture must report a regression")
	}
	if !strings.Contains(out.String(), "REGRESSIONS") || !strings.Contains(out.String(), "C02.branch.required-reviews") {
		t.Errorf("text output missing regression detail:\n%s", out.String())
	}

	out.Reset()
	if _, err := runDiff(&out, base, cur, "md"); err != nil {
		t.Fatalf("runDiff md: %v", err)
	}
	if !strings.Contains(out.String(), "### Regressions") {
		t.Errorf("md output missing regression section:\n%s", out.String())
	}

	out.Reset()
	if _, err := runDiff(&out, base, cur, "json"); err != nil {
		t.Fatalf("runDiff json: %v", err)
	}
	var parsed packdiff.Delta
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("json output does not parse back into a Delta: %v\n%s", err, out.String())
	}
	if len(parsed.Regressions) != 1 {
		t.Errorf("json delta: %+v", parsed)
	}
}

func TestRunDiff_IdenticalPacksEmptyDelta(t *testing.T) {
	dir := t.TempDir()
	base := writeDiffFixture(t, dir, "base", diffFixturePack(model.StatusVerifiedPass), true)
	cur := writeDiffFixture(t, dir, "cur", diffFixturePack(model.StatusVerifiedPass), true)

	var out bytes.Buffer
	delta, err := runDiff(&out, base, cur, "text")
	if err != nil {
		t.Fatalf("runDiff: %v", err)
	}
	if !delta.Empty() || delta.HasRegressions() {
		t.Fatalf("identical packs must produce an empty delta: %+v", delta)
	}
}

// A pack whose bytes no longer match its .sha256 sidecar is refused
// outright — diff has no --force because diffing tampered evidence has
// no legitimate use (unlike report's banner-and-render).
func TestRunDiff_TamperedPackRefused(t *testing.T) {
	dir := t.TempDir()
	base := writeDiffFixture(t, dir, "base", diffFixturePack(model.StatusVerifiedPass), true)
	cur := writeDiffFixture(t, dir, "cur", diffFixturePack(model.StatusVerifiedPass), true)

	// Tamper after the sidecar was written: flip the recorded status.
	raw, err := os.ReadFile(cur)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte(`"verified-pass"`), []byte(`"verified-fail"`), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("fixture tampering did not change the file")
	}
	if err := os.WriteFile(cur, tampered, 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	_, err = runDiff(&out, base, cur, "text")
	if err == nil || !strings.Contains(err.Error(), "failed hash verification") {
		t.Fatalf("expected hash-verification refusal, got %v", err)
	}
}

func TestRunDiff_NoSidecarIsFine(t *testing.T) {
	dir := t.TempDir()
	base := writeDiffFixture(t, dir, "base", diffFixturePack(model.StatusVerifiedPass), false)
	cur := writeDiffFixture(t, dir, "cur", diffFixturePack(model.StatusVerifiedPass), false)

	var out bytes.Buffer
	if _, err := runDiff(&out, base, cur, "text"); err != nil {
		t.Fatalf("packs without sidecars must diff normally (nothing to verify): %v", err)
	}
}

func TestRunDiff_SchemaVersionMismatchRefused(t *testing.T) {
	dir := t.TempDir()
	// writeEvidencePack schema-validates before writing, so a
	// wrong-schema-version pack has to be written by hand — which is also
	// the realistic shape of this failure: a pack produced by a different
	// attestward version, not by this build.
	pack := diffFixturePack(model.StatusVerifiedPass)
	pack.SchemaVersion = model.SchemaVersion + 1
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(base, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	cur := writeDiffFixture(t, dir, "cur", diffFixturePack(model.StatusVerifiedPass), false)

	var out bytes.Buffer
	_, err = runDiff(&out, base, cur, "text")
	if err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("expected schema-version error, got %v", err)
	}
}

// A crafted pack with a status outside the five-value enum must be
// rejected by full schema validation, not flow through classification as
// "other" and into markdown that gets posted to issues (#36).
func TestRunDiff_InvalidStatusRefused(t *testing.T) {
	dir := t.TempDir()
	base := writeDiffFixture(t, dir, "base", diffFixturePack(model.StatusVerifiedPass), false)
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	crafted := bytes.Replace(raw, []byte(`"verified-pass"`), []byte(`"weird|status"`), 1)
	cur := filepath.Join(dir, "crafted.json")
	if err := os.WriteFile(cur, crafted, 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	_, err = runDiff(&out, base, cur, "md")
	if err == nil || !strings.Contains(err.Error(), "schema validation") {
		t.Fatalf("expected schema-validation refusal, got %v", err)
	}
}

func TestRunDiff_UnknownFormatRefused(t *testing.T) {
	var out bytes.Buffer
	_, err := runDiff(&out, "a.json", "b.json", "yaml")
	if err == nil || !strings.Contains(err.Error(), "unknown format") {
		t.Fatalf("expected unknown-format error, got %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("format validation must happen before any file I/O or output")
	}
}
