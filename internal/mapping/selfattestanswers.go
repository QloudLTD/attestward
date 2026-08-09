package mapping

import (
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SelfAttestationAnswer is one user-provided answer to a
// SelfAttestationQuestion. EvidenceRef/AttestedBy/Date are recorded
// verbatim as provenance-of-*assertion* — clearly not independently
// verified, unlike model.Provenance's platform-API evidence — so a reader
// of the pack can judge the claim's credibility themselves rather than
// this tool implying it checked.
type SelfAttestationAnswer struct {
	ID          string `yaml:"id"`
	Answer      string `yaml:"answer"`
	EvidenceRef string `yaml:"evidence_ref,omitempty"`
	AttestedBy  string `yaml:"attested_by,omitempty"`
	Date        string `yaml:"date,omitempty"`
}

// SelfAttestationAnswers is the parsed, validated content of a
// user-authored self-attestation answers file (generated as a template by
// `attestward attest init`, then filled in by hand).
type SelfAttestationAnswers struct {
	QuestionsVersion string                  `yaml:"questions_version,omitempty"`
	Answers          []SelfAttestationAnswer `yaml:"answers"`
}

// LoadSelfAttestationAnswers reads and strictly validates a user-authored
// answers file from the local filesystem — this file always lives outside
// the binary (it's per-producer data, never embedded), so there is no *FS
// variant. questions must be an already-loaded SelfAttestationQuestions:
// every answer's id must resolve to a real question (an unknown id is
// treated as a real error — issue #23's own "unknown IDs error"
// requirement — rather than silently ignored, since a typo'd id would
// otherwise leave that question looking unanswered without any warning
// why). An answer left blank (Answer == "") is valid at this layer —
// "unanswered" is a legitimate, common state; BuildSelfAttestedResults is
// where that becomes not-checkable, not here.
func LoadSelfAttestationAnswers(path string, questions *SelfAttestationQuestions) (*SelfAttestationAnswers, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return decodeSelfAttestationAnswers(f, path, questions)
}

func decodeSelfAttestationAnswers(r io.Reader, source string, questions *SelfAttestationQuestions) (*SelfAttestationAnswers, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var a SelfAttestationAnswers
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("parse %s: %w", source, err)
	}

	seen := map[string]bool{}
	for _, ans := range a.Answers {
		q, ok := questions.QuestionByID[ans.ID]
		if !ok {
			return nil, fmt.Errorf("%s: answer references unknown question id %q", source, ans.ID)
		}
		if seen[ans.ID] {
			return nil, fmt.Errorf("%s: duplicate answer for question id %q", source, ans.ID)
		}
		seen[ans.ID] = true

		trimmed := strings.TrimSpace(ans.Answer)
		if trimmed == "" {
			continue
		}
		if q.AnswerType == "yes_no" || q.AnswerType == "yes_no_evidence" {
			normalized := strings.ToLower(trimmed)
			if normalized != "yes" && normalized != "no" {
				return nil, fmt.Errorf("%s: question %s (answer_type %s): answer %q must be \"yes\" or \"no\"", source, ans.ID, q.AnswerType, ans.Answer)
			}
		}
	}

	return &a, nil
}
