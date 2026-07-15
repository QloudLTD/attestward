package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sioakim/ssdf/internal/integrity"
	"github.com/sioakim/ssdf/internal/model"
)

func TestVerifyEvidencePack_MatchingHashIsOK(t *testing.T) {
	dir := t.TempDir()
	pack := model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "test",
		Scope:         model.ScanScope{Org: "attestor-demo", Repos: []string{"good-repo"}},
		Results:       []model.CheckResult{},
	}
	hash, err := writeEvidencePack(pack, dir)
	if err != nil {
		t.Fatalf("writeEvidencePack: %v", err)
	}
	if err := integrity.WriteSidecar(filepath.Join(dir, "evidence.json"), hash); err != nil {
		t.Fatalf("WriteSidecar: %v", err)
	}

	result, err := verifyEvidencePack(dir)
	if err != nil {
		t.Fatalf("verifyEvidencePack: %v", err)
	}
	if !result.OK {
		t.Errorf("result.OK = false, want true (got %q, want %q)", result.Got, result.Want)
	}
}

// TestVerifyEvidencePack_TamperedByteFails is issue #27's own named
// acceptance case, exercised through the exact real path attestor scan
// and attestor verify use — writeEvidencePack's real atomic writer,
// integrity's real sidecar format, no shortcuts.
func TestVerifyEvidencePack_TamperedByteFails(t *testing.T) {
	dir := t.TempDir()
	pack := model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "test",
		Scope:         model.ScanScope{Org: "attestor-demo", Repos: []string{"good-repo"}},
		Results: []model.CheckResult{
			{CheckID: "X", Status: model.StatusVerifiedPass, Scope: model.ScopeRef{Org: "attestor-demo"}, Provenance: []model.Provenance{}},
		},
	}
	hash, err := writeEvidencePack(pack, dir)
	if err != nil {
		t.Fatalf("writeEvidencePack: %v", err)
	}
	if err := integrity.WriteSidecar(filepath.Join(dir, "evidence.json"), hash); err != nil {
		t.Fatalf("WriteSidecar: %v", err)
	}

	path := filepath.Join(dir, "evidence.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read evidence.json: %v", err)
	}
	tampered := append([]byte{}, data...)
	tampered[len(tampered)-2] ^= 0xFF // evidence.json has no trailing newline (ends "}"); this flips the formatting newline right before that closing brace
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatalf("tamper evidence.json: %v", err)
	}

	result, err := verifyEvidencePack(dir)
	if err != nil {
		t.Fatalf("verifyEvidencePack: %v", err)
	}
	if result.OK {
		t.Error("result.OK = true on a tampered file, want false")
	}
	if result.Got == result.Want {
		t.Error("result.Got and result.Want are equal despite the tamper — test itself is broken")
	}
}

func TestVerifyEvidencePack_MissingEvidenceFileIsError(t *testing.T) {
	dir := t.TempDir()
	if _, err := verifyEvidencePack(dir); err == nil {
		t.Error("verifyEvidencePack on an empty dir returned no error, want one (no evidence.json)")
	}
}

func TestVerifyEvidencePack_MissingSidecarIsError(t *testing.T) {
	dir := t.TempDir()
	pack := model.EvidencePack{
		SchemaVersion: model.SchemaVersion, ToolVersion: "test",
		Scope: model.ScanScope{Org: "attestor-demo", Repos: []string{"good-repo"}}, Results: []model.CheckResult{},
	}
	if _, err := writeEvidencePack(pack, dir); err != nil {
		t.Fatalf("writeEvidencePack: %v", err)
	}
	// Deliberately no WriteSidecar call.
	if _, err := verifyEvidencePack(dir); err == nil {
		t.Error("verifyEvidencePack with no .sha256 sidecar returned no error, want one")
	}
}
