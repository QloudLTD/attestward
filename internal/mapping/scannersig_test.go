package mapping

import "testing"

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
