package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sioakim/ssdf/internal/integrity"
	"github.com/sioakim/ssdf/internal/model"
)

// fakeSigner is a mockable integrity.Signer for tests that need to
// exercise verifyEvidencePack's signature-checking branch without a real
// cosign binary or network/OIDC access.
type fakeSigner struct {
	verifyErr error
}

func (f fakeSigner) SignBlob(context.Context, string, []string) (string, error) {
	panic("fakeSigner.SignBlob not used by these tests")
}

func (f fakeSigner) VerifyBlob(_ context.Context, _ string, _ []string) error {
	return f.verifyErr
}

func writeFixturePack(t *testing.T, dir string) (path, hash string) {
	t.Helper()
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
	path = filepath.Join(dir, "evidence.json")
	if err := integrity.WriteSidecar(path, hash); err != nil {
		t.Fatalf("WriteSidecar: %v", err)
	}
	return path, hash
}

func TestVerifyEvidencePack_MatchingHashIsOK(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeFixturePack(t, dir)

	result, err := verifyEvidencePack(context.Background(), path, integrity.CosignSigner{}, nil)
	if err != nil {
		t.Fatalf("verifyEvidencePack: %v", err)
	}
	if !result.OK {
		t.Errorf("result.OK = false, want true (got %q, want %q)", result.Got, result.Want)
	}
	if result.BundlePresent {
		t.Error("result.BundlePresent = true with no .bundle file written, want false")
	}
}

// TestVerifyEvidencePack_TamperedByteFails is issue #27's own named
// acceptance case, exercised through the exact real path attestor scan
// and attestor verify use — writeEvidencePack's real atomic writer,
// integrity's real sidecar format, no shortcuts.
func TestVerifyEvidencePack_TamperedByteFails(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeFixturePack(t, dir)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read evidence.json: %v", err)
	}
	tampered := append([]byte{}, data...)
	tampered[len(tampered)-2] ^= 0xFF // evidence.json has no trailing newline (ends "}"); this flips the formatting newline right before that closing brace
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatalf("tamper evidence.json: %v", err)
	}

	result, err := verifyEvidencePack(context.Background(), path, integrity.CosignSigner{}, nil)
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
	path := filepath.Join(dir, "evidence.json")
	if _, err := verifyEvidencePack(context.Background(), path, integrity.CosignSigner{}, nil); err == nil {
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
	path := filepath.Join(dir, "evidence.json")
	if _, err := verifyEvidencePack(context.Background(), path, integrity.CosignSigner{}, nil); err == nil {
		t.Error("verifyEvidencePack with no .sha256 sidecar returned no error, want one")
	}
}

// TestVerifyEvidencePack_BundlePresentAndSignatureOK proves a present
// .bundle file is detected and its signature check surfaced as
// SignatureOK, using a fake signer so this doesn't depend on a real
// cosign binary.
func TestVerifyEvidencePack_BundlePresentAndSignatureOK(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeFixturePack(t, dir)
	if err := os.WriteFile(integrity.BundlePath(path), []byte(`{"fake":"bundle"}`), 0o644); err != nil {
		t.Fatalf("write fake bundle: %v", err)
	}

	result, err := verifyEvidencePack(context.Background(), path, fakeSigner{}, nil)
	if err != nil {
		t.Fatalf("verifyEvidencePack: %v", err)
	}
	if !result.BundlePresent {
		t.Fatal("result.BundlePresent = false with a .bundle file present, want true")
	}
	if !result.SignatureOK {
		t.Errorf("result.SignatureOK = false, want true (err: %v)", result.SignatureErr)
	}
}

// TestVerifyEvidencePack_BundlePresentSignatureFails proves a failing
// cosign verify-blob call (wrong identity, tampered bundle, whatever)
// surfaces as SignatureOK=false with the underlying error preserved, not
// silently treated as "no signature to check".
func TestVerifyEvidencePack_BundlePresentSignatureFails(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeFixturePack(t, dir)
	if err := os.WriteFile(integrity.BundlePath(path), []byte(`{"fake":"bundle"}`), 0o644); err != nil {
		t.Fatalf("write fake bundle: %v", err)
	}

	wantErr := errors.New("cosign: certificate identity mismatch")
	result, err := verifyEvidencePack(context.Background(), path, fakeSigner{verifyErr: wantErr}, nil)
	if err != nil {
		t.Fatalf("verifyEvidencePack: %v", err)
	}
	if !result.BundlePresent {
		t.Fatal("result.BundlePresent = false, want true")
	}
	if result.SignatureOK {
		t.Error("result.SignatureOK = true despite a failing signer, want false")
	}
	if result.SignatureErr == nil || result.SignatureErr.Error() != wantErr.Error() {
		t.Errorf("result.SignatureErr = %v, want %v", result.SignatureErr, wantErr)
	}
}

// TestVerifyEvidencePack_NoBundleMeansNothingToVerify proves an unsigned
// pack (the common case — --sign is opt-in) isn't itself flagged as a
// problem: BundlePresent/SignatureOK both false, but the hash check alone
// still determines OK.
func TestVerifyEvidencePack_NoBundleMeansNothingToVerify(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeFixturePack(t, dir)

	result, err := verifyEvidencePack(context.Background(), path, fakeSigner{verifyErr: errors.New("should never be called")}, nil)
	if err != nil {
		t.Fatalf("verifyEvidencePack: %v", err)
	}
	if result.BundlePresent {
		t.Error("result.BundlePresent = true with no .bundle file, want false")
	}
	if !result.OK {
		t.Error("result.OK = false for a valid, unsigned pack, want true — absence of a signature isn't a tamper finding")
	}
}

// TestVerifyEvidencePack_BundleStatErrorOtherThanNotExistIsError locks in
// that a non-ENOENT stat error on the bundle path (permissions, a symlink
// loop, an I/O error) is surfaced as a real execution error, not silently
// folded into "no bundle present" the way a genuinely missing file is.
// Treating any stat failure as "unsigned" would let a signed pack verify
// as if it had no signature to check at all whenever something merely
// prevented reading the bundle — a false OK this project's own security
// bar (SECURITY.md) doesn't tolerate.
func TestVerifyEvidencePack_BundleStatErrorOtherThanNotExistIsError(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeFixturePack(t, dir)
	bundlePath := integrity.BundlePath(path)
	// A self-referencing symlink makes os.Stat fail with ELOOP, not
	// ENOENT.
	if err := os.Symlink(bundlePath, bundlePath); err != nil {
		t.Fatalf("create symlink loop: %v", err)
	}

	if _, err := verifyEvidencePack(context.Background(), path, fakeSigner{}, nil); err == nil {
		t.Error("verifyEvidencePack with an unreadable (non-missing) bundle path returned no error, want one")
	}
}

// TestVerifyEvidencePack_CosignNotFoundIsExecutionErrorNotTampered locks
// in the documented distinction (verify.go's own Long help text): cosign
// missing from PATH while a bundle is present is an execution error, not
// a tamper finding — the environment isn't set up to check the signature
// at all, which is a different problem from "checked it and it's wrong."
func TestVerifyEvidencePack_CosignNotFoundIsExecutionErrorNotTampered(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeFixturePack(t, dir)
	if err := os.WriteFile(integrity.BundlePath(path), []byte(`{"fake":"bundle"}`), 0o644); err != nil {
		t.Fatalf("write fake bundle: %v", err)
	}

	signer := fakeSigner{verifyErr: fmt.Errorf("wrap: %w", integrity.ErrCosignNotFound)}
	_, err := verifyEvidencePack(context.Background(), path, signer, nil)
	if err == nil {
		t.Fatal("verifyEvidencePack with a cosign-not-found signature error returned no error, want one")
	}
	if !errors.Is(err, integrity.ErrCosignNotFound) {
		t.Errorf("returned error %v doesn't wrap integrity.ErrCosignNotFound", err)
	}
}
