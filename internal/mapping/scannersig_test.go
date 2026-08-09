package mapping

import (
	"regexp"
	"strings"
	"testing"
)

func TestLoadScannerSignatures_RealFileLoadsAndValidates(t *testing.T) {
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}
	if reg.Version == "" {
		t.Error("Version is empty")
	}
	if len(reg.Signatures) == 0 {
		t.Fatal("no signatures loaded")
	}
	if len(reg.SignatureByID) != len(reg.Signatures) {
		t.Errorf("SignatureByID has %d entries, want %d (a duplicate ID should have errored, not silently overwritten)", len(reg.SignatureByID), len(reg.Signatures))
	}
	for _, sig := range reg.Signatures {
		if !validScannerCategories[sig.Category] {
			t.Errorf("signature %s has invalid category %q", sig.ID, sig.Category)
		}
	}
}

func TestLoadScannerSignatures_RejectsDuplicateIDs(t *testing.T) {
	_, err := LoadScannerSignatures("testdata/scannersig-bad-duplicate.yaml")
	if err == nil {
		t.Fatal("expected an error for a duplicate signature id, got nil")
	}
}

func TestLoadScannerSignatures_RejectsUnknownFields(t *testing.T) {
	_, err := LoadScannerSignatures("testdata/scannersig-bad-unknown-field.yaml")
	if err == nil {
		t.Fatal("expected an error for an unknown field, got nil")
	}
}

func TestLoadScannerSignatures_RejectsInvalidCategory(t *testing.T) {
	_, err := LoadScannerSignatures("testdata/scannersig-bad-category.yaml")
	if err == nil {
		t.Fatal("expected an error for an invalid category, got nil")
	}
}

func TestLoadScannerSignatures_RejectsMalformedRegex(t *testing.T) {
	_, err := LoadScannerSignatures("testdata/scannersig-bad-regex.yaml")
	if err == nil {
		t.Fatal("expected an error for a malformed run_patterns regex, got nil")
	}
}

func TestLoadScannerSignatures_RejectsEmptyADOTask(t *testing.T) {
	_, err := LoadScannerSignatures("testdata/scannersig-bad-ado-task-empty.yaml")
	if err == nil {
		t.Fatal("expected an error for an ado_tasks entry with an empty task, got nil")
	}
}

func TestLoadScannerSignatures_MissingFile(t *testing.T) {
	_, err := LoadScannerSignatures("testdata/does-not-exist.yaml")
	if err == nil {
		t.Fatal("expected an error for a missing file, got nil")
	}
}

// yamlBooleanLikeRE matches the full YAML 1.1 boolean vocabulary —
// true/false/yes/no/on/off/y/n/1/0, case-insensitive — not just the subset
// yaml.v3 itself resolves as !!bool. Measured directly against yaml.v3,
// not assumed (issue #253's second review round): decoding each of these
// into an `interface{}` shows only true/True/TRUE/false/False/FALSE
// actually resolve to a Go bool; yes/no/on/off/y/n (any case) resolve as
// a plain string, and 0/1 resolve as an int — an earlier version of this
// comment claimed yaml.v3 "decodes a boolean from" the whole set, which
// overstated it exactly the way #248's review round was about. What IS
// true, and is the actual reason this regex exists: none of that
// semantic-type distinction survives decoding into NoADOTask, a Go string
// field — yaml.v3 decodes an untagged scalar into a string field by its
// raw text regardless of what type family the scalar would otherwise
// resolve to, so `no_ado_task: y` lands as the Go string "y" exactly the
// same way `no_ado_task: true` lands as "true". A bare non-empty check
// (the field's original guard) accepted all of them as a real decision.
// An explicit `null` is the one exception, decoding to the empty string,
// which the pre-existing TrimSpace check already caught — y/n themselves
// were a real gap the regex's first round missed (issue #253's second
// review round, N1): behaviorally the same vacuity class as "x", which
// this guard deliberately doesn't police, except y/n are actual YAML 1.1
// booleans and "x" isn't, so closing them is worth the two characters.
var yamlBooleanLikeRE = regexp.MustCompile(`(?i)^(true|false|yes|no|on|off|y|n|0|1)$`)

// hasExplicitADODecision reports whether sig satisfies the
// every-signature-records-a-decision invariant (issue #243): either a
// non-empty ado_tasks block, or a no_ado_task reason that's non-empty
// after trimming whitespace AND isn't one of the boolean-shaped scalars
// yamlBooleanLikeRE rejects (issue #253's F1). Free text beyond that is
// deliberately NOT policed further — "x" or a copy-pasted reason from
// another entry both pass, which is the inherent limit of a free-text
// field and not this guard's job to close; only the one input the
// package doc comment already claims is impossible (a bare boolean) is
// actually rejected here.
func hasExplicitADODecision(sig ScannerSignature) bool {
	if len(sig.Detect.ADOTasks) > 0 {
		return true
	}
	trimmed := strings.TrimSpace(sig.Detect.NoADOTask)
	if trimmed == "" {
		return false
	}
	return !yamlBooleanLikeRE.MatchString(trimmed)
}

// TestEveryScannerSignatureHasADOTasksOrAnExplicitAbsenceMarker is issue
// #243's point 4 — the part meant to stop this class of gap recurring, not
// just close the one-time sweep: only 4 of the registry's 14 signatures
// carried any ADO detection at all before this fix (5 after — trivy's own
// #238 fix), discovered only because #238's trivy miss prompted an audit,
// not by anything enforcing the invariant. See
// hasExplicitADODecision's own doc comment for exactly what satisfies this
// — a reason string forces whoever adds a signature to write down which
// case applies (structural absence vs. a checked negative) and, for the
// latter, when it was checked. This is a registry-level test rather than a
// load-time decodeScannerSignatures validation on purpose: a documentation
// gap here shouldn't be able to take down `attestward scan` itself, only
// fail CI.
func TestEveryScannerSignatureHasADOTasksOrAnExplicitAbsenceMarker(t *testing.T) {
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}

	for _, sig := range reg.Signatures {
		if !hasExplicitADODecision(sig) {
			t.Errorf("signature %q has neither an ado_tasks block nor a no_ado_task reason — every signature must record one or the other explicitly (issue #243)", sig.ID)
		}
	}
}

// TestHasExplicitADODecision_RejectsBooleanLikeScalars is issue #253's F1
// (round 1) and N1 (round 2 — y/n were still missing after round 1):
// proves the full YAML 1.1 boolean vocabulary, in any case and with
// surrounding whitespace, is rejected — while also pinning the reviewer's
// own confirmed-safe negative cases (a real reason, a bare non-boolean
// word, a copy-pasted placeholder like "TODO") so a future change to
// yamlBooleanLikeRE can't silently widen or narrow what it rejects without
// a visible test change.
func TestHasExplicitADODecision_RejectsBooleanLikeScalars(t *testing.T) {
	tests := []struct {
		name       string
		noADOTask  string
		wantDecide bool
	}{
		{"true", "true", false},
		{"false", "false", false},
		{"yes", "yes", false},
		{"no", "no", false},
		{"on", "on", false},
		{"off", "off", false},
		{"y", "y", false},
		{"n", "n", false},
		{"0", "0", false},
		{"1", "1", false},
		{"TRUE uppercase", "TRUE", false},
		{"False mixed case", "False", false},
		{"Yes mixed case", "Yes", false},
		{"Y uppercase", "Y", false},
		{"N uppercase", "N", false},
		{"boolean with surrounding whitespace", "  true  ", false},
		{"empty string", "", false},
		{"whitespace only", "   ", false},
		{"tabs and newline only", "\t\n  ", false},
		{"real reason", "No official vendor task exists (checked 2026-07-26).", true},
		{"single non-boolean word", "x", true},
		{"placeholder TODO", "TODO", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := ScannerSignature{ID: "test-sig", Detect: ScannerSignatureDetect{NoADOTask: tt.noADOTask}}
			if got := hasExplicitADODecision(sig); got != tt.wantDecide {
				t.Errorf("hasExplicitADODecision(no_ado_task=%q) = %v, want %v", tt.noADOTask, got, tt.wantDecide)
			}
		})
	}
}
