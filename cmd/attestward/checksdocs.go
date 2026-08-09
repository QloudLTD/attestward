package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"gitlab.com/sioakeim/attestward/internal/checksref"
	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/mappings"
)

var (
	checksDocsOutFlag   string
	checksDocsCheckFlag bool
)

var checksDocsCmd = &cobra.Command{
	Use:   "docs",
	Short: "Regenerate docs/checks-reference.md from mappings and registered check metadata",
	Long: `attestward checks docs renders docs/checks-reference.md: the generated,
authoritative reference of every registered check — rubric, API endpoints, token
permission, SSDF task text, CISA form cluster, remediation, and fixture proof.

Never hand-edit docs/checks-reference.md — edit mappings/*.yaml or a collector's
registered CheckMeta instead, then regenerate. --check makes this a CI drift
guard: it renders in memory, compares against the committed file, and exits
nonzero (without writing) if they differ.`,
	RunE: runChecksDocs,
}

func init() {
	checksDocsCmd.Flags().StringVar(&checksDocsOutFlag, "out", "docs/checks-reference.md", "path to write the generated reference to")
	checksDocsCmd.Flags().BoolVar(&checksDocsCheckFlag, "check", false, "don't write — exit nonzero if the generated content would differ from --out's current content")
	checksCmd.AddCommand(checksDocsCmd)
}

func runChecksDocs(cmd *cobra.Command, _ []string) error {
	return runChecksDocsGen(cmd.OutOrStdout(), checksDocsOutFlag, checksDocsCheckFlag)
}

// runChecksDocsGen is the testable core of `attestward checks docs`: load
// mappings, render, then either write --out or (--check) diff against it
// without writing.
func runChecksDocsGen(stdout io.Writer, outPath string, check bool) error {
	ssdf, err := mapping.LoadSSDFFS(mappings.FS, "ssdf-800-218.yaml")
	if err != nil {
		return fmt.Errorf("load ssdf mapping: %w", err)
	}
	cisa, err := mapping.LoadCISAFS(mappings.FS, "cisa-ssda-form.yaml", ssdf)
	if err != nil {
		return fmt.Errorf("load cisa mapping: %w", err)
	}
	saQuestions, err := mapping.LoadSelfAttestationQuestionsFS(mappings.FS, "self-attestation-questions.yaml", ssdf)
	if err != nil {
		return fmt.Errorf("load self-attestation questions: %w", err)
	}

	rendered, err := checksref.Render(collect.Registered(), ssdf, cisa, saQuestions)
	if err != nil {
		return fmt.Errorf("generate %s: %w", outPath, err)
	}

	if check {
		existing, err := os.ReadFile(outPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("%s does not exist — run `attestward checks docs` to generate it", outPath)
			}
			return fmt.Errorf("read %s: %w", outPath, err)
		}
		if !bytes.Equal(existing, rendered) {
			return fmt.Errorf("%s is stale relative to the current mappings/registry — run `attestward checks docs` and commit the result", outPath)
		}
		logf(stdout, "%s is up to date\n", outPath)
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(outPath), err)
	}
	if err := os.WriteFile(outPath, rendered, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	logf(stdout, "wrote %s\n", outPath)
	return nil
}
