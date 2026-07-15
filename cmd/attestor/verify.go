package main

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sioakim/ssdf/internal/integrity"
)

var verifyCmd = &cobra.Command{
	Use:   "verify <dir>",
	Short: "Verify an evidence pack's SHA-256 hash against its .sha256 sidecar",
	Long: `attestor verify recomputes <dir>/evidence.json's SHA-256 and compares it
against <dir>/evidence.json.sha256 — exactly what a plain
"sha256sum -c evidence.json.sha256" (run from inside <dir>) checks; attestor's
own involvement is not required to trust the result.

Exit codes: 0 verified OK, 1 tampered (hash mismatch) or an execution error
(missing evidence.json, missing or malformed sidecar).`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}

// verifyResult is verifyEvidencePack's outcome — split out from runVerify
// the same way runScan is split from runScanCmd (issue #10), so the
// os.Exit call the CLI wrapper makes on a TAMPERED result never has to run
// inside a test process.
type verifyResult struct {
	OK   bool
	Got  string
	Want string
}

func verifyEvidencePack(dir string) (verifyResult, error) {
	ok, got, want, err := integrity.VerifyFile(filepath.Join(dir, "evidence.json"))
	if err != nil {
		return verifyResult{}, err
	}
	return verifyResult{OK: ok, Got: got, Want: want}, nil
}

func runVerify(cmd *cobra.Command, args []string) error {
	path := filepath.Join(args[0], "evidence.json")

	result, err := verifyEvidencePack(args[0])
	if err != nil {
		return err
	}
	if !result.OK {
		logf(cmd.OutOrStdout(), "TAMPERED: %s\n  computed sha256: %s\n  sidecar sha256:  %s\n", path, result.Got, result.Want)
		os.Exit(exitError)
	}
	logf(cmd.OutOrStdout(), "OK: %s\n  sha256: %s\n", path, result.Got)
	return nil
}
