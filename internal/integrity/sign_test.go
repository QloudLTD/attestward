package integrity

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withFakeCosign puts a fake "cosign" executable (running script) at the
// front of PATH for the duration of the test, so SignBlob/VerifyBlob's
// argument-construction and bundle-path handling can be exercised
// deterministically without a real cosign binary or network/OIDC access
// — the real binary is exercised by a CI-only integration test instead
// (see the keyless-signing workflow job), not here.
func withFakeCosign(t *testing.T, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-cosign shell script fixture is POSIX-only; the real binary is exercised in CI on every platform this project ships for")
	}
	dir := t.TempDir()
	fakePath := filepath.Join(dir, "cosign")
	if err := os.WriteFile(fakePath, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatalf("write fake cosign: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestBundlePath(t *testing.T) {
	if got, want := BundlePath("evidence.json"), "evidence.json.bundle"; got != want {
		t.Errorf("BundlePath = %q, want %q", got, want)
	}
}

func TestCosignSigner_SignBlob_MissingBinaryIsActionableError(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // a directory with nothing in it, cosign included
	_, err := CosignSigner{}.SignBlob(context.Background(), "evidence.json", nil)
	if err == nil {
		t.Fatal("SignBlob with no cosign on PATH returned no error, want one")
	}
	if !strings.Contains(err.Error(), cosignInstallURL) {
		t.Errorf("error %q doesn't name the install doc %q", err, cosignInstallURL)
	}
}

func TestCosignSigner_VerifyBlob_MissingBinaryIsActionableError(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	err := CosignSigner{}.VerifyBlob(context.Background(), "evidence.json", nil)
	if err == nil {
		t.Fatal("VerifyBlob with no cosign on PATH returned no error, want one")
	}
	if !strings.Contains(err.Error(), cosignInstallURL) {
		t.Errorf("error %q doesn't name the install doc %q", err, cosignInstallURL)
	}
}

// TestCosignSigner_SignBlob_PassesBundleFlagAndSignArgs locks in the exact
// invocation shape: `cosign sign-blob --bundle=<path>.bundle --yes
// <signArgs...> <path>` — matching .goreleaser.yaml's already-established
// release-checksum signing convention (see ADR-0006), not the legacy
// separate --output-signature/--output-certificate flags cosign v3
// removed.
func TestCosignSigner_SignBlob_PassesBundleFlagAndSignArgs(t *testing.T) {
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(evidencePath, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	argsFile := filepath.Join(dir, "args.txt")
	withFakeCosign(t, fmt.Sprintf("echo \"$@\" > %s\n", argsFile))

	bundlePath, err := CosignSigner{}.SignBlob(context.Background(), evidencePath, []string{"--key=cosign.key"})
	if err != nil {
		t.Fatalf("SignBlob: %v", err)
	}
	if want := BundlePath(evidencePath); bundlePath != want {
		t.Errorf("bundlePath = %q, want %q", bundlePath, want)
	}

	gotArgs, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	got := strings.TrimSpace(string(gotArgs))
	want := fmt.Sprintf("sign-blob --bundle=%s --yes --key=cosign.key %s", bundlePath, evidencePath)
	if got != want {
		t.Errorf("cosign invoked with args %q, want %q", got, want)
	}
}

func TestCosignSigner_SignBlob_NonZeroExitIsError(t *testing.T) {
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(evidencePath, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	withFakeCosign(t, "echo 'cosign: signing failed' >&2\nexit 1\n")

	if _, err := (CosignSigner{}).SignBlob(context.Background(), evidencePath, nil); err == nil {
		t.Error("SignBlob with a failing cosign process returned no error, want one")
	}
}

func TestCosignSigner_VerifyBlob_PassesBundleFlagAndVerifyArgs(t *testing.T) {
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.json")
	argsFile := filepath.Join(dir, "args.txt")
	withFakeCosign(t, fmt.Sprintf("echo \"$@\" > %s\n", argsFile))

	verifyArgs := []string{"--certificate-identity-regexp=^https://github.com/", "--certificate-oidc-issuer=https://token.actions.githubusercontent.com"}
	if err := (CosignSigner{}).VerifyBlob(context.Background(), evidencePath, verifyArgs); err != nil {
		t.Fatalf("VerifyBlob: %v", err)
	}

	gotArgs, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	got := strings.TrimSpace(string(gotArgs))
	want := fmt.Sprintf("verify-blob --bundle=%s --certificate-identity-regexp=^https://github.com/ --certificate-oidc-issuer=https://token.actions.githubusercontent.com %s", BundlePath(evidencePath), evidencePath)
	if got != want {
		t.Errorf("cosign invoked with args %q, want %q", got, want)
	}
}

func TestCosignSigner_VerifyBlob_NonZeroExitIsError(t *testing.T) {
	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "evidence.json")
	withFakeCosign(t, "echo 'cosign: verification failed' >&2\nexit 1\n")

	if err := (CosignSigner{}).VerifyBlob(context.Background(), evidencePath, nil); err == nil {
		t.Error("VerifyBlob with a failing cosign process returned no error, want one")
	}
}
