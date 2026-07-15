package integrity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// cosignInstallURL is the pointer given whenever cosign is required but
// not found on PATH — issue #27's own explicit requirement: a missing
// binary is a hard error, never a silent skip.
const cosignInstallURL = "https://docs.sigstore.dev/system_config/installation/"

// ErrCosignNotFound wraps every "cosign missing from PATH" error this
// package returns, so a caller (attestor verify, specifically) can tell
// "the environment isn't set up to check a signature" apart from "the
// signature check ran and failed" via errors.Is — the two are different
// classes of problem (an execution error vs. a genuine tamper finding)
// and must not be reported with the same "TAMPERED" language.
var ErrCosignNotFound = errors.New("cosign not found on PATH")

// Signer signs and verifies a file via the cosign CLI, shelled out to
// rather than vendored as a Go dependency — see ADR-0006 for why.
// Interfaced so cmd/attestor's tests can inject a fake rather than
// requiring a real cosign binary and network/OIDC access to exercise
// --sign/verify's own wiring; the real binary is exercised by a CI-only
// integration test instead (see .github/workflows for the keyless-signing
// job), not mocked there.
type Signer interface {
	// SignBlob signs path via `cosign sign-blob`, producing a Sigstore
	// bundle at BundlePath(path). signArgs is passed through to cosign
	// verbatim (e.g. --key=cosign.key, or nothing at all for keyless) —
	// this project never manages key material itself. Returns the bundle
	// path on success.
	SignBlob(ctx context.Context, path string, signArgs []string) (bundlePath string, err error)

	// VerifyBlob verifies path against BundlePath(path) via
	// `cosign verify-blob`. verifyArgs is passed through verbatim — for
	// keyless verification this must include, at minimum,
	// --certificate-identity(-regexp) and --certificate-oidc-issuer
	// (cosign itself requires these; attestor doesn't default or infer
	// them, since the correct identity is caller/producer-specific).
	VerifyBlob(ctx context.Context, path string, verifyArgs []string) error
}

// BundlePath is the conventional Sigstore bundle path for path —
// evidence.json -> evidence.json.bundle. Matches this repo's own release-
// checksum signing convention (.goreleaser.yaml's `signs:` block) rather
// than cosign v2's separate --output-signature/--output-certificate
// files, which cosign v3 removed outright.
func BundlePath(path string) string {
	return path + ".bundle"
}

// CosignSigner is the real Signer, shelling out to the cosign binary on
// PATH.
type CosignSigner struct{}

// cosignPath returns the resolved path to the cosign binary, or a hard
// error naming the install doc if it isn't on PATH — every SignBlob/
// VerifyBlob call goes through this first so "cosign missing" always
// produces the same actionable message, never a bare exec.ErrNotFound.
func cosignPath() (string, error) {
	path, err := exec.LookPath("cosign")
	if err != nil {
		return "", fmt.Errorf("%w (required for --sign / verifying a signed pack) — install it: %s", ErrCosignNotFound, cosignInstallURL)
	}
	return path, nil
}

// SignBlob implements Signer by shelling out to `cosign sign-blob`.
func (CosignSigner) SignBlob(ctx context.Context, path string, signArgs []string) (string, error) {
	cosign, err := cosignPath()
	if err != nil {
		return "", err
	}
	bundlePath := BundlePath(path)

	args := []string{"sign-blob", "--bundle=" + bundlePath, "--yes"}
	args = append(args, signArgs...)
	args = append(args, path)

	cmd := exec.CommandContext(ctx, cosign, args...)
	// cosign's own progress/prompt output goes to stderr, same as
	// attestor's own warning/progress lines elsewhere — never mixed into
	// stdout, which stays reserved for attestor's own structured status
	// lines (see runScanCmd/runVerify).
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("cosign sign-blob failed: %w", err)
	}
	return bundlePath, nil
}

// VerifyBlob implements Signer by shelling out to `cosign verify-blob`.
func (CosignSigner) VerifyBlob(ctx context.Context, path string, verifyArgs []string) error {
	cosign, err := cosignPath()
	if err != nil {
		return err
	}
	bundlePath := BundlePath(path)

	args := []string{"verify-blob", "--bundle=" + bundlePath}
	args = append(args, verifyArgs...)
	args = append(args, path)

	cmd := exec.CommandContext(ctx, cosign, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cosign verify-blob failed: %w", err)
	}
	return nil
}
