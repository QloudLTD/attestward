package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the attestor version, commit, and build date",
	RunE: func(cmd *cobra.Command, _ []string) error {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "attestor %s (commit %s, built %s)\n", version, commit, date)
		return err
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
