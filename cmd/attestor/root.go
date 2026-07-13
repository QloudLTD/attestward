package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version, commit, and date are populated at build time via -ldflags (see the
// Makefile); they keep their zero-value defaults under `go run`/`go build`
// without ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "attestor",
	Short: "Verify the technical controls behind the CISA SSDA form against a GitHub org/repo",
	Long: `attestor is a read-only CLI that connects to a software producer's source-control
and CI/CD platform (GitHub first) and verifies — rather than asks about — the
technical controls behind the CISA Secure Software Development Attestation
(SSDA) form. It maps findings to NIST SSDF (SP 800-218) practices and emits a
signed, timestamped evidence pack.`,
	// Cobra already prints "Error: ..." plus a usage hint on a RunE error;
	// without these, Execute's own error print below duplicates it. Keep
	// SilenceErrors so Execute controls the one place the message appears.
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command and exits non-zero on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
