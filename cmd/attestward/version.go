package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the attestward version, commit, and build date",
	RunE: func(cmd *cobra.Command, _ []string) error {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "attestward %s (commit %s, built %s)\n", version, commit, date)
		return err
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
