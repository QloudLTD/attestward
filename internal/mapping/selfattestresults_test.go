package mapping

import (
	"testing"

	"github.com/sioakim/attestward/internal/model"
)

func TestBuildSelfAttestedResults(t *testing.T) {
	questions := &SelfAttestationQuestions{
		Questions: []SelfAttestationQuestion{
			{ID: "SA.answered-yes", Question: "answered yes?", AnswerType: "yes_no"},
			{ID: "SA.answered-text", Question: "answered text?", AnswerType: "text"},
			{ID: "SA.unanswered", Question: "unanswered?", AnswerType: "yes_no"},
			{ID: "SA.blank-answer", Question: "blank answer?", AnswerType: "yes_no"},
		},
	}
	answers := &SelfAttestationAnswers{
		Answers: []SelfAttestationAnswer{
			{ID: "SA.answered-yes", Answer: "yes", EvidenceRef: "https://example.invalid", AttestedBy: "Jane Doe", Date: "2026-07-14"},
			{ID: "SA.answered-text", Answer: "5 business days"},
			{ID: "SA.blank-answer", Answer: "   "},
		},
	}

	results := BuildSelfAttestedResults(questions, answers, "acme")
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want 4", len(results))
	}
	byID := map[string]model.CheckResult{}
	for _, r := range results {
		byID[r.CheckID] = r
	}

	yes := byID["SA.answered-yes"]
	if yes.Status != model.StatusSelfAttested {
		t.Errorf("SA.answered-yes status = %q, want self-attested", yes.Status)
	}
	if yes.Facts["answer"] != "yes" || yes.Facts["evidence_ref"] != "https://example.invalid" || yes.Facts["attested_by"] != "Jane Doe" || yes.Facts["date"] != "2026-07-14" {
		t.Errorf("SA.answered-yes facts = %#v, want answer/evidence_ref/attested_by/date all populated", yes.Facts)
	}
	if yes.Scope.Org != "acme" || yes.Scope.Repo != "" {
		t.Errorf("SA.answered-yes scope = %+v, want org-scoped only", yes.Scope)
	}
	if yes.Provenance == nil || len(yes.Provenance) != 0 {
		t.Errorf("SA.answered-yes provenance = %#v, want a non-nil empty slice", yes.Provenance)
	}

	text := byID["SA.answered-text"]
	if text.Status != model.StatusSelfAttested {
		t.Errorf("SA.answered-text status = %q, want self-attested", text.Status)
	}
	if text.Facts["answer"] != "5 business days" {
		t.Errorf("SA.answered-text answer fact = %v, want %q", text.Facts["answer"], "5 business days")
	}
	if _, ok := text.Facts["evidence_ref"]; ok {
		t.Errorf("SA.answered-text facts unexpectedly has evidence_ref: %#v", text.Facts)
	}

	unanswered := byID["SA.unanswered"]
	if unanswered.Status != model.StatusNotCheckable {
		t.Errorf("SA.unanswered status = %q, want not-checkable (no matching answer at all)", unanswered.Status)
	}

	blank := byID["SA.blank-answer"]
	if blank.Status != model.StatusNotCheckable {
		t.Errorf("SA.blank-answer status = %q, want not-checkable (whitespace-only answer)", blank.Status)
	}
}

func TestBuildSelfAttestedResults_NilAnswers_AllNotCheckable(t *testing.T) {
	questions := &SelfAttestationQuestions{
		Questions: []SelfAttestationQuestion{
			{ID: "SA.q1", Question: "q1?", AnswerType: "yes_no"},
			{ID: "SA.q2", Question: "q2?", AnswerType: "text"},
		},
	}
	results := BuildSelfAttestedResults(questions, nil, "acme")
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable (no answers file at all)", r.CheckID, r.Status)
		}
		if r.Reason == "" {
			t.Errorf("%s reason is empty", r.CheckID)
		}
	}
}

// TestBuildSelfAttestedResults_NeverProducesVerifiedPass locks in this
// package's own rollup precedence (rollup.go): self-attested must never
// rank as verified — every answer, regardless of its own content, must
// produce StatusSelfAttested or StatusNotCheckable, never
// StatusVerifiedPass.
func TestBuildSelfAttestedResults_NeverProducesVerifiedPass(t *testing.T) {
	questions := &SelfAttestationQuestions{
		Questions: []SelfAttestationQuestion{
			{ID: "SA.q1", Question: "q1?", AnswerType: "yes_no"},
		},
	}
	for _, answer := range []string{"yes", "no", "some free text"} {
		answers := &SelfAttestationAnswers{Answers: []SelfAttestationAnswer{{ID: "SA.q1", Answer: answer}}}
		results := BuildSelfAttestedResults(questions, answers, "acme")
		if results[0].Status != model.StatusSelfAttested {
			t.Errorf("answer %q produced status %q, want self-attested", answer, results[0].Status)
		}
		if !results[0].Status.Valid() {
			t.Errorf("answer %q produced an invalid status %q", answer, results[0].Status)
		}
	}
}
