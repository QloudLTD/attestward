package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"gitlab.com/sioakeim/attestward/internal/model"
	"gitlab.com/sioakeim/attestward/internal/packdiff"
)

var diffFormatFlag string

var diffCmd = &cobra.Command{
	Use:   "diff <baseline-evidence.json> <current-evidence.json>",
	Short: "Compare two evidence packs semantically and report posture drift",
	Long: `attestward diff compares two evidence packs from the same org — typically a
stored baseline against a fresh scan — and reports what actually changed,
ignoring fields that legitimately differ between any two runs (scan
timestamps, provenance timestamps and response digests, reason wording).

Changes are classified so drift is never over- or under-stated:

  regressions     verified posture worsened (pass -> fail/partial, partial -> fail)
  improvements    the reverse direction
  coverage        a check moved between verified and not-checkable — a token or
                  plan capability change, reported separately because it is not
                  a posture change
  other           self-attested transitions, informational
  added/removed   checks present in only one pack, informational

Tool version, mapping versions, and repo-set differences between the packs
are surfaced as context: a status change across different tool versions may
reflect a checker change, not a posture change.

Exit codes: 0 no regressions, 2 regressions found, 1 execution error —
so a CI job (issue #36's drift mode) fails exactly when posture regressed.

If a .sha256 sidecar sits next to either input, it is checked first and a
mismatch is refused outright. Unlike attestward report there is no --force:
rendering tampered evidence behind a visible banner has a use; diffing
tampered evidence has none.`,
	Args: cobra.ExactArgs(2),
	RunE: runDiffCmd,
}

func init() {
	diffCmd.Flags().StringVar(&diffFormatFlag, "format", "text", "output format: text, md (drift-issue fragment), or json (stable machine shape)")
	rootCmd.AddCommand(diffCmd)
}

// runDiffCmd wraps runDiff for cobra, applying the custom exit-2-on-
// regressions contract the same way scan does: os.Exit directly, after
// all output is written (cobra's RunE error path only knows exit 1).
func runDiffCmd(cmd *cobra.Command, args []string) error {
	delta, err := runDiff(cmd.OutOrStdout(), args[0], args[1], diffFormatFlag)
	if err != nil {
		return err
	}
	if delta.HasRegressions() {
		os.Exit(exitGaps)
	}
	return nil
}

// runDiff is the testable core of `attestward diff`: load and
// integrity-check both packs, compare, render in the requested format.
func runDiff(stdout io.Writer, baselinePath, currentPath, format string) (packdiff.Delta, error) {
	switch format {
	case "text", "md", "json":
	default:
		return packdiff.Delta{}, fmt.Errorf("--format: unknown format %q (want text, md, or json)", format)
	}

	baseline, err := loadDiffPack(baselinePath)
	if err != nil {
		return packdiff.Delta{}, err
	}
	current, err := loadDiffPack(currentPath)
	if err != nil {
		return packdiff.Delta{}, err
	}

	delta, err := packdiff.Compare(baseline, current)
	if err != nil {
		return packdiff.Delta{}, err
	}

	switch format {
	case "text":
		if _, err := io.WriteString(stdout, packdiff.RenderText(delta)); err != nil {
			return packdiff.Delta{}, fmt.Errorf("write output: %w", err)
		}
	case "md":
		if _, err := io.WriteString(stdout, packdiff.RenderMarkdown(delta)); err != nil {
			return packdiff.Delta{}, fmt.Errorf("write output: %w", err)
		}
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(delta); err != nil {
			return packdiff.Delta{}, fmt.Errorf("encode delta: %w", err)
		}
	}
	return delta, nil
}

// loadDiffPack integrity-checks, reads, and schema-checks one input pack.
// Same load semantics as attestward report except tampering is always a
// hard refusal (see the command doc for why there is no --force here),
// and the sidecar check runs FIRST — a tampered file may also fail the
// content checks below, and "failed hash verification" is the error that
// must surface then, not a misleading "use a matching attestward
// version".
func loadDiffPack(path string) (model.EvidencePack, error) {
	tampered, err := checkPackIntegrity(path)
	if err != nil {
		return model.EvidencePack{}, err
	}
	if tampered {
		return model.EvidencePack{}, fmt.Errorf("%s failed hash verification against its .sha256 sidecar — refusing to diff possibly-tampered evidence", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return model.EvidencePack{}, fmt.Errorf("read %s: %w", path, err)
	}
	var pack model.EvidencePack
	if err := json.Unmarshal(data, &pack); err != nil {
		return model.EvidencePack{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if pack.SchemaVersion != model.SchemaVersion {
		return model.EvidencePack{}, fmt.Errorf("%s has schema_version %d, this build of attestward understands schema_version %d — use a matching attestward version to diff it", path, pack.SchemaVersion, model.SchemaVersion)
	}
	// Full schema validation, not just the version check report does:
	// diff's classification switches on Status values and its md output
	// gets posted into issues (#36), so a crafted pack with an invalid
	// status must be rejected here rather than flow through as "other".
	if err := pack.ValidateAgainstSchema(); err != nil {
		return model.EvidencePack{}, fmt.Errorf("%s failed schema validation: %w", path, err)
	}
	return pack, nil
}
