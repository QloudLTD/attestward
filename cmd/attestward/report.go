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

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/integrity"
	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/internal/model"
	"gitlab.com/sioakeim/attestward/internal/report"
	"gitlab.com/sioakeim/attestward/mappings"
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
guessing at how to render an unfamiliar shape. The rest of the pack is
validated against the same schema too — a status outside the five defined
values, or any other shape the schema doesn't allow, is refused the same
way, with no --force override.

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
	// Issue #240: the schema declares status (CheckResult.Status,
	// TaskRollup.Status, ClusterRollup.Status — all three via the shared
	// $defs/status enum) as exactly the five defined values, and
	// model.Status's own doc comment claims the same thing at the Go level
	// ("Exactly these five values exist; nothing else may ever appear in an
	// evidence pack"). Neither renderer enforces that — statusLabel/
	// statusBadge's default branch renders an out-of-enum value verbatim,
	// unescaped, into a compliance document (report.md.tmpl/poam.md.tmpl
	// interpolate both without esc, having always trusted them to return one
	// of a handful of known-safe strings). Rejected here, the same way an
	// unrecognized schema_version already is — no --force bypass, unlike the
	// hash-tamper check below: a schema violation means the pack's SHAPE is
	// wrong, not that its unmodified content might be untrustworthy, and
	// that's not something a visible warning banner can meaningfully
	// override. ValidateAgainstSchema validates the whole pack, not just
	// status, which is deliberate: it's already-existing, already-tested
	// infrastructure (internal/model/validate_test.go), and it structurally
	// covers all three Status-typed fields (and any future one) the same
	// way, rather than three hand-written .Valid() loops that could each
	// individually go stale the way this repo has repeatedly found
	// hand-maintained enumerations do.
	if err := pack.ValidateAgainstSchema(); err != nil {
		return fmt.Errorf("%s failed schema validation: %w", inputPath, err)
	}
	// The hash of the exact bytes being rendered from, not whatever (if
	// anything) was already embedded in the JSON — so report.md/html's
	// "Pack SHA-256" line always describes the file a reader actually has
	// in front of them, byte for byte, independent of the sidecar/tamper
	// check below.
	//
	// This line is also load-bearing for injection safety, which is not
	// obvious from where it sits (issue #231's review): report.md.tmpl
	// renders Integrity.SHA256 inside an unescaped code span, and that is
	// only safe because this overwrite guarantees the value is a
	// freshly-computed hex digest rather than whatever string the pack
	// carried. The schema permits any string there, and `attestward report`
	// renders third-party packs by design (see this command's own --help),
	// so moving, conditionalizing, or removing this assignment silently
	// reopens a markdown-injection hole in a document compliance readers
	// are expected to read literally. Escape at the template instead if
	// this ever needs to become conditional.
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
	// Issue #264: loaded here too now, so RenderMarkdown/RenderHTML/
	// RenderPOAM can compare it against pack.MappingVersions.ScannerSignatures
	// the same way they already do for ssdf/cisa/self-attestation. #263
	// (merged) is what made this comparison live: scan.go now populates
	// ScannerSignatures on every new pack, the same way it already did for
	// the other three fields — a pack scanned before that PR still lacks
	// the field, and the pack.X != "" guard in mappingVersionMismatch
	// skips the comparison for exactly those, rather than asserting a
	// mismatch it has no evidence for.
	scannerSignatures, err := mapping.LoadScannerSignaturesFS(mappings.FS, "scanner-signatures.yaml")
	if err != nil {
		return fmt.Errorf("load scanner-signatures mapping: %w", err)
	}

	remediationByCheckID := buildRemediationByCheckID(pack.Results, collect.LookupPlatform)
	scopeLevelByCheckID := buildScopeLevelByCheckID(pack.Results, collect.LookupPlatform)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", outDir, err)
	}

	for _, f := range formats {
		var rendered []byte
		var name string
		switch f {
		case "md":
			name = "report.md"
			rendered, err = report.RenderMarkdown(pack, ssdf, cisa, saQuestions, scannerSignatures, scopeLevelByCheckID)
		case "html":
			name = "report.html"
			rendered, err = report.RenderHTML(pack, ssdf, cisa, saQuestions, scannerSignatures, scopeLevelByCheckID)
		case "poam":
			name = "poam.md"
			rendered, err = report.RenderPOAM(pack, ssdf, cisa, saQuestions, scannerSignatures, remediationByCheckID, scopeLevelByCheckID)
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

// buildScopeLevelByCheckID mirrors buildRemediationByCheckID exactly, same
// per-result-Platform lookup and reason (review of #164): the same check
// ID can register a genuinely different ScopeLevel per platform (e.g.
// C03.env.exists is repo-scoped on GitHub, project-scoped on Azure
// DevOps), so ranging over the full registry instead of resolving
// per-result would risk one platform's classification overwriting the
// other's. internal/report interprets the plain string value, never
// collect.ScopeLevel itself (ADR-0005's seam).
func buildScopeLevelByCheckID(results []model.CheckResult, lookup func(platform, id string) (collect.CheckMeta, bool)) map[string]string {
	m := map[string]string{}
	for _, r := range results {
		if _, ok := m[r.CheckID]; ok {
			continue
		}
		if meta, ok := lookup(r.Scope.Platform, r.CheckID); ok {
			m[r.CheckID] = string(meta.ScopeLevel)
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
