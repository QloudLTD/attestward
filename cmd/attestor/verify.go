package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sioakim/ssdf/internal/integrity"
)

var verifyArgsFlag []string

var verifyCmd = &cobra.Command{
	Use:   "verify <dir>",
	Short: "Verify an evidence pack's SHA-256 hash (and signature, if signed)",
	Long: `attestor verify recomputes <dir>/evidence.json's SHA-256 and compares it
against <dir>/evidence.json.sha256 — exactly what a plain
"sha256sum -c evidence.json.sha256" (run from inside <dir>) checks; attestor's
own involvement is not required to trust the hash half of the result.

If <dir>/evidence.json.bundle exists (attestor scan --sign produced one),
also runs "cosign verify-blob" against it — pass whatever cosign needs to
identify the signer via --verify-args (e.g. for keyless verification,
--verify-args=--certificate-identity-regexp=... and
--verify-args=--certificate-oidc-issuer=...; attestor doesn't default or
infer these, since the correct identity is producer-specific). No bundle
present means nothing to verify there — an unsigned pack isn't itself a
tamper finding.

Exit codes: 0 verified OK (hash, and signature if present), 1 tampered
(hash mismatch, or signature verification failed) or an execution error
(missing evidence.json, missing or malformed sidecar, cosign not on PATH
when a bundle is present).`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringArrayVar(&verifyArgsFlag, "verify-args", nil, "extra arg passed through to cosign verify-blob verbatim (repeatable); required for keyless verification")
	rootCmd.AddCommand(verifyCmd)
}

// verifyResult is verifyEvidencePack's outcome — split out from runVerify
// the same way runScan is split from runScanCmd (issue #10), so the
// os.Exit call the CLI wrapper makes on a TAMPERED result never has to run
// inside a test process.
type verifyResult struct {
	OK   bool // hash check
	Got  string
	Want string

	// BundlePresent is false when the pack was never signed — not itself
	// a tamper finding, just nothing more to check. SignatureOK/
	// SignatureErr are only meaningful when BundlePresent is true.
	BundlePresent bool
	SignatureOK   bool
	SignatureErr  error
}

// verifyEvidencePack checks path (an evidence.json file, wherever it
// lives — not assumed to be named "evidence.json" or to live in any
// particular directory) against its sidecar and, if present, its bundle.
// Takes a path rather than a directory so issue #28's `attestor report`
// can reuse this unchanged for an arbitrary evidence.json path, not just
// `attestor verify`'s own directory-based convention.
func verifyEvidencePack(ctx context.Context, path string, signer integrity.Signer, verifyArgs []string) (verifyResult, error) {
	ok, got, want, err := integrity.VerifyFile(path)
	if err != nil {
		return verifyResult{}, err
	}
	result := verifyResult{OK: ok, Got: got, Want: want}

	bundlePath := integrity.BundlePath(path)
	_, statErr := os.Stat(bundlePath)
	switch {
	case statErr == nil:
		result.BundlePresent = true
		sigErr := signer.VerifyBlob(ctx, path, verifyArgs)
		switch {
		case sigErr == nil:
			result.SignatureOK = true
		case errors.Is(sigErr, integrity.ErrCosignNotFound):
			// The environment isn't set up to check the signature at
			// all — a real execution error, not "checked it and it's
			// wrong" (see runVerify's TAMPERED/error distinction).
			return verifyResult{}, sigErr
		default:
			result.SignatureErr = sigErr
		}
	case os.IsNotExist(statErr):
		// No bundle at all — signing is opt-in, so this isn't a tamper
		// finding, just nothing more to check.
	default:
		// Any other stat failure (permissions, a symlink loop, I/O) must
		// not be silently folded into "no bundle" — that would let a
		// signed pack read as unsigned whenever something merely
		// prevented reading the bundle, a false OK this project doesn't
		// tolerate.
		return verifyResult{}, fmt.Errorf("stat %s: %w", bundlePath, statErr)
	}
	return result, nil
}

func runVerify(cmd *cobra.Command, args []string) error {
	path := filepath.Join(args[0], "evidence.json")

	result, err := verifyEvidencePack(cmd.Context(), path, integrity.CosignSigner{}, verifyArgsFlag)
	if err != nil {
		return err
	}

	if result.OK {
		logf(cmd.OutOrStdout(), "OK: %s\n  sha256: %s\n", path, result.Got)
	} else {
		logf(cmd.OutOrStdout(), "TAMPERED: %s\n  computed sha256: %s\n  sidecar sha256:  %s\n", path, result.Got, result.Want)
	}
	if result.BundlePresent {
		if result.SignatureOK {
			logf(cmd.OutOrStdout(), "OK: signature verified (%s)\n", integrity.BundlePath(path))
		} else {
			logf(cmd.OutOrStdout(), "TAMPERED: signature verification failed (%s): %v\n", integrity.BundlePath(path), result.SignatureErr)
		}
	}

	if !result.OK || (result.BundlePresent && !result.SignatureOK) {
		os.Exit(exitError)
	}
	return nil
}
