package mapping

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// ScannerCategory is one of the fixed scanner-signature categories — kept
// as a plain string type (not a strict enum) so an unrecognized category in
// the YAML is still caught by decodeScannerSignatures' explicit validation
// below, with a clear error naming the field, rather than a cryptic
// unmarshal failure.
type ScannerCategory string

// The fixed set of scanner-signature categories — see validScannerCategories.
const (
	CategorySAST       ScannerCategory = "sast"
	CategorySCA        ScannerCategory = "sca"
	CategoryContainer  ScannerCategory = "container"
	CategorySecrets    ScannerCategory = "secrets"
	CategorySBOM       ScannerCategory = "sbom"
	CategoryProvenance ScannerCategory = "provenance"
)

var validScannerCategories = map[ScannerCategory]bool{
	CategorySAST:       true,
	CategorySCA:        true,
	CategoryContainer:  true,
	CategorySecrets:    true,
	CategorySBOM:       true,
	CategoryProvenance: true,
}

// ActionMatcher matches a workflow step's `uses:` slug (the part before
// `@`), optionally pinned to an exact ref (the part after `@`) — Version
// empty means match the slug at any ref.
type ActionMatcher struct {
	Slug    string `yaml:"slug"`
	Version string `yaml:"version,omitempty"`
}

// ADOTaskMatcher matches an Azure Pipelines step's `task:` reference —
// written "TaskName@Version" (e.g. "AdvancedSecurity-Codeql-Init@1", or a
// full version pin like "GoTool@0.3.1", a form Microsoft's own docs use) —
// by task name, case-insensitively, and, optionally, a major-version pin:
// Major, if set, is compared against only the segment of the post-`@`
// version before its first `.` (so major: "1" matches both "@1" and
// "@1.2.3"), never the whole version string. Major empty means match the
// task at any version.
//
// Task is matched as the exact, full string written before the last `@`
// — no dot-segment splitting is performed on it. Azure Pipelines also
// allows referencing a task by its fully-qualified marketplace form —
// four segments, `publisher.extensionId.contributionId.taskName@version`
// (e.g. `qetza.replacetokens.replacetokens-task.replacetokens@3`), not
// three — or by a bare task GUID; neither cross-matches a short-name Task
// value here, and that's deliberate: two different publishers' tasks can
// share a bare task name, so collapsing a fully-qualified or GUID
// reference down to "the part that looks like the short name" could
// cross-match the wrong tool, against this registry's per-signature
// accuracy standard (see scanner-signatures.yaml's header comment). A
// signature that needs to recognize the fully-qualified or GUID form
// lists that exact string as its own ado_tasks entry instead.
//
// This is ActionMatcher's Azure-Pipelines-native counterpart (Slug+Version
// there, Task+Major here): Actions itself isn't reused for ADO because an
// action `uses:` slug and an ADO task name are different namespaces
// entirely, not two spellings of the same thing.
type ADOTaskMatcher struct {
	Task  string `yaml:"task"`
	Major string `yaml:"major,omitempty"`
}

// ScannerSignatureDetect lists a signature's any-of matchers, tried in
// confidence order by MatchWorkflow/MatchPipeline: Actions/ADOTasks
// (high), then RunPatterns (medium), then WorkflowNamePatterns (low). All
// four may be empty — see scanner-signatures.yaml's "dependabot" entry,
// whose real detection mechanism (a config file's presence) this
// workflow/pipeline-content-only schema can't express.
//
// RunPatterns and WorkflowNamePatterns are cross-platform, not
// GitHub-specific, despite their names (kept for backward compatibility
// rather than renamed): on GitHub Actions (MatchWorkflow) RunPatterns
// matches a step's `run:` text and WorkflowNamePatterns matches the
// workflow's own `name:`; on Azure Pipelines (MatchPipeline, added by
// #149) RunPatterns matches a step's `script:`/`bash:`/`pwsh:`/
// `powershell:` text and WorkflowNamePatterns matches the pipeline's own
// `name:` plus each step's `displayName:`. ADOTasks has no GitHub
// equivalent — it's the ADO-only high-confidence tier, alongside Actions.
type ScannerSignatureDetect struct {
	Actions              []ActionMatcher  `yaml:"actions"`
	ADOTasks             []ADOTaskMatcher `yaml:"ado_tasks,omitempty"`
	RunPatterns          []string         `yaml:"run_patterns"`
	WorkflowNamePatterns []string         `yaml:"workflow_name_patterns"`
}

// ScannerSignature is one detectable tool entry.
type ScannerSignature struct {
	ID          string                 `yaml:"id"`
	Name        string                 `yaml:"name"`
	Category    ScannerCategory        `yaml:"category"`
	Detect      ScannerSignatureDetect `yaml:"detect"`
	RunEvidence string                 `yaml:"run_evidence,omitempty"`

	// Compiled once at load time by decodeScannerSignatures — regexp.
	// MustCompile inside the hot matching path would recompile on every
	// call; compiling here also means a malformed regex is a load-time
	// error (loud, at startup) rather than a silent per-match failure.
	// Unexported: only this package's matcher needs them, and a value copy
	// of ScannerSignature (as stored in SignatureByID) still carries them —
	// unexported fields survive an in-package struct copy.
	runPatternRegexps          []*regexp.Regexp
	workflowNamePatternRegexps []*regexp.Regexp
}

// ScannerSignatureRegistry is the parsed, validated content of
// mappings/scanner-signatures.yaml.
type ScannerSignatureRegistry struct {
	Version    string             `yaml:"version"`
	Signatures []ScannerSignature `yaml:"signatures"`

	// SignatureByID indexes Signatures by ID; populated by the loader, not
	// part of the YAML itself.
	SignatureByID map[string]ScannerSignature `yaml:"-"`
}

// LoadScannerSignatures reads and strictly validates a
// scanner-signatures.yaml-shaped file from the local filesystem — see
// LoadSSDF's doc comment for why this and LoadScannerSignaturesFS both
// exist.
func LoadScannerSignatures(path string) (*ScannerSignatureRegistry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return decodeScannerSignatures(f, path)
}

// LoadScannerSignaturesFS is LoadScannerSignatures for an fs.FS (e.g. the
// embedded mappings.FS).
func LoadScannerSignaturesFS(fsys fs.FS, name string) (*ScannerSignatureRegistry, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	return decodeScannerSignatures(f, name)
}

// decodeScannerSignatures holds the actual decode+validate logic: unknown
// fields, duplicate signature IDs, unrecognized categories, and malformed
// regexes are all reported as errors naming the offending field, rather
// than silently accepted or surfacing as an opaque panic later — this is
// the enforcement layer behind
// docs/schema/mapping-scanner-signatures.schema.json.
func decodeScannerSignatures(r io.Reader, source string) (*ScannerSignatureRegistry, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var reg ScannerSignatureRegistry
	if err := dec.Decode(&reg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", source, err)
	}

	reg.SignatureByID = make(map[string]ScannerSignature, len(reg.Signatures))
	for i := range reg.Signatures {
		sig := &reg.Signatures[i]
		if sig.ID == "" {
			return nil, fmt.Errorf("%s: signature at index %d has an empty id", source, i)
		}
		if _, dup := reg.SignatureByID[sig.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate signature id %q", source, sig.ID)
		}
		if sig.Name == "" {
			return nil, fmt.Errorf("%s: signature %s: name is empty", source, sig.ID)
		}
		if !validScannerCategories[sig.Category] {
			return nil, fmt.Errorf("%s: signature %s: category %q is not one of sast, sca, container, secrets, sbom, provenance", source, sig.ID, sig.Category)
		}
		for j, am := range sig.Detect.Actions {
			if am.Slug == "" {
				return nil, fmt.Errorf("%s: signature %s: actions[%d] has an empty slug", source, sig.ID, j)
			}
		}
		for j, tm := range sig.Detect.ADOTasks {
			if tm.Task == "" {
				return nil, fmt.Errorf("%s: signature %s: ado_tasks[%d] has an empty task", source, sig.ID, j)
			}
		}

		sig.runPatternRegexps = make([]*regexp.Regexp, len(sig.Detect.RunPatterns))
		for j, pattern := range sig.Detect.RunPatterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("%s: signature %s: run_patterns[%d] %q does not compile: %w", source, sig.ID, j, pattern, err)
			}
			sig.runPatternRegexps[j] = re
		}
		sig.workflowNamePatternRegexps = make([]*regexp.Regexp, len(sig.Detect.WorkflowNamePatterns))
		for j, pattern := range sig.Detect.WorkflowNamePatterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("%s: signature %s: workflow_name_patterns[%d] %q does not compile: %w", source, sig.ID, j, pattern, err)
			}
			sig.workflowNamePatternRegexps[j] = re
		}

		reg.SignatureByID[sig.ID] = *sig
	}

	return &reg, nil
}
