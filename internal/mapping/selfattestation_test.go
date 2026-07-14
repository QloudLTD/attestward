package mapping

import (
	"strings"
	"testing"
)

func TestLoadSelfAttestationQuestions_RealMappingFileLoadsAndResolves(t *testing.T) {
	ssdf, err := LoadSSDF("../../mappings/ssdf-800-218.yaml")
	if err != nil {
		t.Fatalf("LoadSSDF: %v", err)
	}
	q, err := LoadSelfAttestationQuestions("../../mappings/self-attestation-questions.yaml", ssdf)
	if err != nil {
		t.Fatalf("LoadSelfAttestationQuestions(mappings/self-attestation-questions.yaml) = %v, want no error", err)
	}
	if len(q.Questions) == 0 {
		t.Fatal("no questions loaded")
	}
	for _, question := range q.Questions {
		if _, ok := q.QuestionByID[question.ID]; !ok {
			t.Errorf("QuestionByID[%q] missing", question.ID)
		}
		if !validAnswerTypes[question.AnswerType] {
			t.Errorf("question %s: answer_type %q is not valid", question.ID, question.AnswerType)
		}
	}
}

func TestLoadSelfAttestationQuestions_RejectsUnknownSSDFTaskReference(t *testing.T) {
	_, err := LoadSelfAttestationQuestions("testdata/selfattest-questions-bad-unknown-task.yaml", minimalSSDFFixture())
	if err == nil {
		t.Fatal("want an unknown-task error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown SSDF task") {
		t.Errorf("error = %v, want it to mention 'unknown SSDF task'", err)
	}
}

func TestLoadSelfAttestationQuestions_RejectsDuplicateID(t *testing.T) {
	_, err := LoadSelfAttestationQuestions("testdata/selfattest-questions-bad-duplicate-id.yaml", minimalSSDFFixture())
	if err == nil {
		t.Fatal("want a duplicate-id error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate question id") {
		t.Errorf("error = %v, want it to mention 'duplicate question id'", err)
	}
}

func TestLoadSelfAttestationQuestions_RejectsInvalidAnswerType(t *testing.T) {
	_, err := LoadSelfAttestationQuestions("testdata/selfattest-questions-bad-answer-type.yaml", minimalSSDFFixture())
	if err == nil {
		t.Fatal("want an invalid-answer_type error, got nil")
	}
	if !strings.Contains(err.Error(), "answer_type") {
		t.Errorf("error = %v, want it to mention 'answer_type'", err)
	}
}

func TestLoadSelfAttestationQuestions_RejectsBadIDFormat(t *testing.T) {
	_, err := LoadSelfAttestationQuestions("testdata/selfattest-questions-bad-id-format.yaml", minimalSSDFFixture())
	if err == nil {
		t.Fatal("want an id-format error, got nil")
	}
	if !strings.Contains(err.Error(), "does not match the self-attestation ID format") {
		t.Errorf("error = %v, want it to mention the ID format", err)
	}
}
