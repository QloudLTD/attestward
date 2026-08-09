package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/mappings"
)

func loadRealSelfAttestationQuestions(t *testing.T) *mapping.SelfAttestationQuestions {
	t.Helper()
	ssdf, err := mapping.LoadSSDFFS(mappings.FS, "ssdf-800-218.yaml")
	if err != nil {
		t.Fatalf("LoadSSDFFS: %v", err)
	}
	questions, err := mapping.LoadSelfAttestationQuestionsFS(mappings.FS, "self-attestation-questions.yaml", ssdf)
	if err != nil {
		t.Fatalf("LoadSelfAttestationQuestionsFS: %v", err)
	}
	return questions
}

// TestRenderAttestTemplate_MatchesGoldenFile locks in the exact generated
// template against a checked-in golden file — issue #23's own "template
// generator + golden test" requirement. If mappings/self-attestation-
// questions.yaml's question set or wording ever changes, this test fails
// with a byte diff until testdata/attest-init.golden.yaml is regenerated
// (`go run ./cmd/attestward attest init --out cmd/attestward/testdata/attest-init.golden.yaml`),
// a deliberate speed bump so a question-set change is never silently
// unreflected in what users actually see.
func TestRenderAttestTemplate_MatchesGoldenFile(t *testing.T) {
	got := renderAttestTemplate(loadRealSelfAttestationQuestions(t))
	want, err := os.ReadFile("testdata/attest-init.golden.yaml")
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("renderAttestTemplate output does not match testdata/attest-init.golden.yaml\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRenderAttestTemplate_OutputParsesBackCleanly is the structural
// round-trip half of the "template round-trip: init -> fill -> scan
// consumes without edits to structure" acceptance criterion: the
// generated template, completely unfilled, must load through
// LoadSelfAttestationAnswers with no error and produce one (blank)
// answer entry per question, in the same order.
func TestRenderAttestTemplate_OutputParsesBackCleanly(t *testing.T) {
	questions := loadRealSelfAttestationQuestions(t)
	data := renderAttestTemplate(questions)

	path := filepath.Join(t.TempDir(), "answers.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	answers, err := mapping.LoadSelfAttestationAnswers(path, questions)
	if err != nil {
		t.Fatalf("LoadSelfAttestationAnswers(generated template): %v", err)
	}
	if len(answers.Answers) != len(questions.Questions) {
		t.Fatalf("len(Answers) = %d, want %d (one per question)", len(answers.Answers), len(questions.Questions))
	}
	if answers.QuestionsVersion != questions.Version {
		t.Errorf("QuestionsVersion = %q, want %q", answers.QuestionsVersion, questions.Version)
	}
	for i, a := range answers.Answers {
		if a.ID != questions.Questions[i].ID {
			t.Errorf("Answers[%d].ID = %q, want %q (same order as Questions)", i, a.ID, questions.Questions[i].ID)
		}
		if a.Answer != "" {
			t.Errorf("Answers[%d].Answer = %q, want empty (freshly generated, unfilled)", i, a.Answer)
		}
	}
}

func TestRunAttestInit_WritesFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "self-attestation.yaml")
	attestInitOut = out
	t.Cleanup(func() { attestInitOut = "self-attestation.yaml" })

	cmd := attestInitCmd
	cmd.SetOut(&bytes.Buffer{})
	if err := runAttestInit(cmd, nil); err != nil {
		t.Fatalf("runAttestInit: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read generated file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("generated file is empty")
	}
}
