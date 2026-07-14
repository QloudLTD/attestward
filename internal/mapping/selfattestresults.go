package mapping

import (
	"fmt"
	"strings"

	"github.com/sioakim/ssdf/internal/model"
)

// BuildSelfAttestedResults turns questions plus (possibly nil, when no
// --self-attestation-file was given) answers into one CheckResult per
// question, org-scoped (self-attestation has no per-repo concept). An
// unanswered question — no matching answer at all, or one whose Answer is
// blank — is reported not-checkable, never assumed to be "no" or skipped
// entirely (issue #23: "Unanswered questions ⇒ not-checkable... never
// assumed"; "Missing answers file... ⇒ ... all self-attested checks
// not-checkable"). A real answer always produces StatusSelfAttested,
// regardless of whether it's affirmative, negative, or free text — this
// package's Rollup already ranks self-attested below verified-pass
// (rollup.go) and below not-checkable/partial/verified-fail, so an
// answer's own polarity never needs to be baked into Status itself to get
// correct rollup behavior; the actual answer/evidence/attestor is carried
// in Facts for a report or POA&M generator (issues #25/#26) to render or
// flag as it sees fit. Provenance is always empty — nothing was queried
// from a platform API for a self-attested result, by definition.
func BuildSelfAttestedResults(questions *SelfAttestationQuestions, answers *SelfAttestationAnswers, org string) []model.CheckResult {
	answerByID := map[string]SelfAttestationAnswer{}
	if answers != nil {
		for _, a := range answers.Answers {
			answerByID[a.ID] = a
		}
	}

	results := make([]model.CheckResult, 0, len(questions.Questions))
	for _, q := range questions.Questions {
		a, answered := answerByID[q.ID]
		trimmed := strings.TrimSpace(a.Answer)
		if !answered || trimmed == "" {
			results = append(results, model.CheckResult{
				CheckID: q.ID, Title: q.Question, Status: model.StatusNotCheckable,
				Reason: "no self-attestation provided for this question",
				Scope:  model.ScopeRef{Org: org}, Provenance: []model.Provenance{},
			})
			continue
		}

		facts := map[string]any{"answer": a.Answer}
		if a.EvidenceRef != "" {
			facts["evidence_ref"] = a.EvidenceRef
		}
		if a.AttestedBy != "" {
			facts["attested_by"] = a.AttestedBy
		}
		if a.Date != "" {
			facts["date"] = a.Date
		}
		results = append(results, model.CheckResult{
			CheckID: q.ID, Title: q.Question, Status: model.StatusSelfAttested,
			Reason: fmt.Sprintf("self-attested (not independently verified): %s", a.Answer),
			Scope:  model.ScopeRef{Org: org}, Provenance: []model.Provenance{},
			Facts: facts,
		})
	}
	return results
}
