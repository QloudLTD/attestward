package mapping

import (
	"strings"
	"testing"
)

func minimalSelfAttestQuestionsFixture() *SelfAttestationQuestions {
	return &SelfAttestationQuestions{
		QuestionByID: map[string]SelfAttestationQuestion{
			"SA.yes-no-question": {ID: "SA.yes-no-question", AnswerType: "yes_no"},
			"SA.text-question":   {ID: "SA.text-question", AnswerType: "text"},
		},
	}
}

func TestLoadSelfAttestationAnswers_GoodFileLoadsCleanly(t *testing.T) {
	questions := &SelfAttestationQuestions{
		QuestionByID: map[string]SelfAttestationQuestion{
			"SA.yes-no-question":     {ID: "SA.yes-no-question", AnswerType: "yes_no"},
			"SA.text-question":       {ID: "SA.text-question", AnswerType: "text"},
			"SA.unanswered-question": {ID: "SA.unanswered-question", AnswerType: "yes_no"},
		},
	}
	answers, err := LoadSelfAttestationAnswers("testdata/selfattest-answers-good.yaml", questions)
	if err != nil {
		t.Fatalf("LoadSelfAttestationAnswers: %v", err)
	}
	if len(answers.Answers) != 3 {
		t.Fatalf("len(Answers) = %d, want 3", len(answers.Answers))
	}
	if answers.QuestionsVersion != "1.0.0" {
		t.Errorf("QuestionsVersion = %q, want %q", answers.QuestionsVersion, "1.0.0")
	}
}

func TestLoadSelfAttestationAnswers_RejectsUnknownQuestionID(t *testing.T) {
	_, err := LoadSelfAttestationAnswers("testdata/selfattest-answers-bad-unknown-id.yaml", minimalSelfAttestQuestionsFixture())
	if err == nil {
		t.Fatal("want an unknown-question-id error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown question id") {
		t.Errorf("error = %v, want it to mention 'unknown question id'", err)
	}
}

func TestLoadSelfAttestationAnswers_RejectsDuplicateAnswerID(t *testing.T) {
	_, err := LoadSelfAttestationAnswers("testdata/selfattest-answers-bad-duplicate-id.yaml", minimalSelfAttestQuestionsFixture())
	if err == nil {
		t.Fatal("want a duplicate-answer error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate answer") {
		t.Errorf("error = %v, want it to mention 'duplicate answer'", err)
	}
}

func TestLoadSelfAttestationAnswers_RejectsInvalidYesNoValue(t *testing.T) {
	_, err := LoadSelfAttestationAnswers("testdata/selfattest-answers-bad-yesno-value.yaml", minimalSelfAttestQuestionsFixture())
	if err == nil {
		t.Fatal("want a bad-yes/no-value error, got nil")
	}
	if !strings.Contains(err.Error(), `must be "yes" or "no"`) {
		t.Errorf("error = %v, want it to mention the yes/no requirement", err)
	}
}

func TestLoadSelfAttestationAnswers_BlankAnswerIsNotAnError(t *testing.T) {
	// A blank answer.Answer for a yes_no question must load cleanly —
	// "unanswered" is a legitimate state at this layer; only
	// BuildSelfAttestedResults turns it into not-checkable.
	answers, err := LoadSelfAttestationAnswers("testdata/selfattest-answers-good.yaml", &SelfAttestationQuestions{
		QuestionByID: map[string]SelfAttestationQuestion{
			"SA.yes-no-question":     {ID: "SA.yes-no-question", AnswerType: "yes_no"},
			"SA.text-question":       {ID: "SA.text-question", AnswerType: "text"},
			"SA.unanswered-question": {ID: "SA.unanswered-question", AnswerType: "yes_no"},
		},
	})
	if err != nil {
		t.Fatalf("LoadSelfAttestationAnswers: %v", err)
	}
	found := false
	for _, a := range answers.Answers {
		if a.ID == "SA.unanswered-question" {
			found = true
			if a.Answer != "" {
				t.Errorf("Answer = %q, want empty", a.Answer)
			}
		}
	}
	if !found {
		t.Fatal("SA.unanswered-question not found in loaded answers")
	}
}
