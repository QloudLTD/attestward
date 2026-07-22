package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/integrity"
	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/model"
	"github.com/sioakim/attestward/internal/report"
	"github.com/sioakim/attestward/mappings"
)

var (
	reportOutFlag    string
	reportFormatFlag []string
	reportForceFlag  bool
)

var reportCmd = &cobra.Command{
	Use:   "report <path-to-evidence.json>",
	Short: "Regenerate report.md/report.html/poam.md from an existing evidence pack",
	Long: `attestward report re-renders report.md, report.html, and poam.md from an
already-written evidence.json — no scan, no network access, safe to run
offline or air-gapped. Useful for re-rendering after a renderer upgrade,
rendering a pack received from someone else, or CI artifact
post-processing.

If evidence.json's schema_version isn't the one this build of attestward
understands, attestward report fails with a friendly error rather than
guessing at how to render an unfamiliar shape.

If a .sha256 sidecar sits next to the input file (written automatically by
attestward scan — see "Verifying an evidence pack" in the README), attestward
report checks it before rendering. A hash mismatch is refused unless
--force is given, in which case every rendered file carries a visible
hash-verification-failed banner — rendering possibly-tampered evidence
must be a conscious, visible act, never silent. A pack with no sidecar at
all isn't itself a problem: there's nothing to verify, so it renders
normally. --force only overrides a hash mismatch; a malformed or
unreadable sidecar is a different problem (verification couldn't run at
all, not "ran and found tampering") and stays a hard error either way.`,
	Args: cobra.ExactArgs(1),
	RunE: runReportCmd,
}

func init() {
	reportCmd.Flags().StringVar(&reportOutFlag, "out", "", "directory to write report(s) into (default: alongside the input evidence.json)")
	reportCmd.Flags().StringSliceVar(&reportFormatFlag, "format", []string{"md", "html", "poam"}, "which report(s) to render: md, html, poam (comma-separated)")
	reportCmd.Flags().BoolVar(&reportForceFlag, "force", false, "render even if the pack fails hash verification (rendered output carries a tamper-warning banner)")
	rootCmd.AddCommand(reportCmd)
}

func runReportCmd(cmd *cobra.Command, args []string) error {
	return runReport(cmd.Context(), cmd.OutOrStdout(), args[0], reportOutFlag, reportFormatFlag, reportForceFlag)
}

var validReportFormats = map[string]bool{"md": true, "html": true, "poam": true}

// runReport is the testable core of `attestward report`: read, validate
// schema version, integrity-check, render, write. It takes no cobra
// dependency so tests call it directly against a real temp directory
// (context.Context is accepted only because it's threaded through
// unrelated call chains in this file's siblings; runReport itself does no
// I/O that can be canceled).
func runReport(_ context.Context, stdout io.Writer, inputPath, outDir string, formats []string, force bool) error {
	for _, f := range formats {
		if !validReportFormats[f] {
			return fmt.Errorf("--format: unknown format %q (want md, html, or poam)", f)
		}
	}
	if outDir == "" {
		outDir = filepath.Dir(inputPath)
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", inputPath, err)
	}
	var pack model.EvidencePack
	if err := json.Unmarshal(data, &pack); err != nil {
		return fmt.Errorf("parse %s: %w", inputPath, err)
	}
	if pack.SchemaVersion != model.SchemaVersion {
		return fmt.Errorf("%s has schema_version %d, this build of attestward understands schema_version %d — use a matching attestward version to render it", inputPath, pack.SchemaVersion, model.SchemaVersion)
	}
	// The hash of the exact bytes being rendered from, not whatever (if
	// anything) was already embedded in the JSON — so report.md/html's
	// "Pack SHA-256" line always describes the file a reader actually has
	// in front of them, byte for byte, independent of the sidecar/tamper
	// check below.
	pack.Integrity = &model.Integrity{SHA256: integrity.Hash(data)}

	tampered, err := checkPackIntegrity(inputPath)
	if err != nil {
		return err
	}
	if tampered && !force {
		return fmt.Errorf("%s failed hash verification against its .sha256 sidecar — refusing to render possibly-tampered evidence (pass --force to render anyway; the rendered output will carry a tamper-warning banner)", inputPath)
	}

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

	remediationByCheckID := buildRemediationByCheckID(pack.Results, collect.LookupPlatform)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", outDir, err)
	}

	for _, f := range formats {
		var rendered []byte
		var name string
		switch f {
		case "md":
			name = "report.md"
			rendered, err = report.RenderMarkdown(pack, ssdf, cisa, saQuestions)
		case "html":
			name = "report.html"
			rendered, err = report.RenderHTML(pack, ssdf, cisa, saQuestions)
		case "poam":
			name = "poam.md"
			rendered, err = report.RenderPOAM(pack, ssdf, cisa, remediationByCheckID)
		}
		if err != nil {
			return fmt.Errorf("render %s: %w", name, err)
		}
		if tampered {
			rendered = withTamperBanner(rendered, f)
		}
		outPath := filepath.Join(outDir, name)
		if err := os.WriteFile(outPath, rendered, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", outPath, err)
		}
		logf(stdout, "wrote %s\n", outPath)
	}
	return nil
}

// buildRemediationByCheckID resolves each result's remediation text via its
// own Scope.Platform (falling back to github when absent, same convention
// as collect.LookupPlatform itself) rather than building the map from
// collect.Registered() wholesale. A pack covers exactly one platform (no
// mixed-platform packs), but Registered() returns every platform's checks —
// once a second platform registers the same check ID under different
// remediation text, building this map from the full registry would
// silently overwrite one platform's remediation with whichever platform's
// entry a range over Registered() happened to visit last (found in review
// of #164). lookup is collect.LookupPlatform in production, and a synthetic
// stand-in in tests, so this resolves per-platform correctly without ever
// registering a fake check into the real global registry.
func buildRemediationByCheckID(results []model.CheckResult, lookup func(platform, id string) (collect.CheckMeta, bool)) map[string]string {
	m := map[string]string{}
	for _, r := range results {
		if _, ok := m[r.CheckID]; ok {
			continue
		}
		if meta, ok := lookup(r.Scope.Platform, r.CheckID); ok {
			m[r.CheckID] = meta.Remediation
		}
	}
	return m
}

// checkPackIntegrity reports whether path fails hash verification against
// its .sha256 sidecar. A missing sidecar isn't itself a problem: hashing
// is something only attestward scan produces, and a pack handed over
// without one has nothing to verify against — so this is deliberately
// scoped narrower than attestward verify's hard "sidecar must exist"
// requirement (see verify.go's own doc comment for why that command needs
// the stricter rule and this one doesn't). Bundle/signature verification
// is out of scope here: issue #28 only asks for hash awareness, matching
// the banner text it names ("hash verification failed").
func checkPackIntegrity(path string) (tampered bool, err error) {
	sidecarPath := integrity.SidecarPath(path)
	_, statErr := os.Stat(sidecarPath)
	switch {
	case statErr == nil:
		ok, _, _, verifyErr := integrity.VerifyFile(path)
		if verifyErr != nil {
			return false, verifyErr
		}
		return !ok, nil
	case os.IsNotExist(statErr):
		return false, nil
	default:
		return false, fmt.Errorf("stat %s: %w", sidecarPath, statErr)
	}
}

const tamperBannerText = "hash verification failed against evidence.json.sha256 — this report was rendered with --force from a pack that may have been tampered with or corrupted after the scan that produced it. Treat every finding below as unverified."

// withTamperBanner prepends (md/poam) or injects (html) a visible warning
// into rendered, rather than threading a "tampered" parameter through the
// pure renderers in internal/report — those stay pure functions of
// (pack, mappings, ...) with no knowledge of this command's own integrity
// bookkeeping.
func withTamperBanner(rendered []byte, format string) []byte {
	if format == "html" {
		banner := []byte(`<div class="note"><strong>WARNING:</strong> ` + tamperBannerText + "</div>\n")
		return bytes.Replace(rendered, []byte("<body>\n"), append([]byte("<body>\n"), banner...), 1)
	}
	banner := "> **WARNING:** " + tamperBannerText + "\n\n"
	return append([]byte(banner), rendered...)
}
