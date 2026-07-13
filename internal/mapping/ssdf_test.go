package mapping

import (
	"strings"
	"testing"
)

func TestLoadSSDF_RealMappingFileLoadsAndValidates(t *testing.T) {
	m, err := LoadSSDF("../../mappings/ssdf-800-218.yaml")
	if err != nil {
		t.Fatalf("LoadSSDF(mappings/ssdf-800-218.yaml) = %v, want no error", err)
	}
	if m.Version == "" {
		t.Error("Version is empty")
	}
	if len(m.Tasks) == 0 {
		t.Fatal("Tasks is empty")
	}
	if _, ok := m.TaskByID["PO.5.1"]; !ok {
		t.Error(`TaskByID["PO.5.1"] missing — expected PO.5.1 (separate/protect environments) to be present`)
	}
	for _, task := range m.Tasks {
		if !taskIDPattern.MatchString(task.ID) {
			t.Errorf("task %q does not match the SSDF task ID format", task.ID)
		}
		if strings.TrimSpace(task.Text) == "" {
			t.Errorf("task %q has empty text", task.ID)
		}
	}
}

func TestLoadSSDF_RejectsDuplicateIDs(t *testing.T) {
	_, err := LoadSSDF("testdata/ssdf-bad-duplicate.yaml")
	if err == nil {
		t.Fatal("LoadSSDF(ssdf-bad-duplicate.yaml) = nil error, want a duplicate-id error")
	}
	if !strings.Contains(err.Error(), "duplicate task id") {
		t.Errorf("error = %v, want it to mention 'duplicate task id'", err)
	}
}

func TestLoadSSDF_RejectsInventedIDFormat(t *testing.T) {
	_, err := LoadSSDF("testdata/ssdf-bad-format.yaml")
	if err == nil {
		t.Fatal("LoadSSDF(ssdf-bad-format.yaml) = nil error, want an ID-format error")
	}
	if !strings.Contains(err.Error(), "does not match the SSDF task ID format") {
		t.Errorf("error = %v, want it to mention the ID format", err)
	}
}

func TestLoadSSDF_RejectsUnknownFields(t *testing.T) {
	_, err := LoadSSDF("testdata/ssdf-bad-unknown-field.yaml")
	if err == nil {
		t.Fatal("LoadSSDF(ssdf-bad-unknown-field.yaml) = nil error, want an unknown-field error")
	}
}

func TestLoadSSDF_MissingFile(t *testing.T) {
	_, err := LoadSSDF("testdata/does-not-exist.yaml")
	if err == nil {
		t.Fatal("LoadSSDF(does-not-exist.yaml) = nil error, want a file-not-found error")
	}
}
