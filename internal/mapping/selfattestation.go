package mapping

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

var (
	selfAttestIDPattern = regexp.MustCompile(`^SA\.[a-z0-9-]+$`)
	validAnswerTypes    = map[string]bool{"yes_no": true, "yes_no_evidence": true, "text": true}
)

// SelfAttestationQuestion is one questionnaire entry (issue #23): a
// non-API-verifiable practice, optionally tied to SSDF tasks (empty when
// no task in this file's deliberately-scoped subset fits — see
// mappings/self-attestation-questions.yaml's header comment) and to the
// API-verified checks it complements (Pairing — informational only, not
// enforced against the check registry, since this package has no
// dependency on internal/collect per ADR-0005's seam).
type SelfAttestationQuestion struct {
	ID             string   `yaml:"id"`
	Question       string   `yaml:"question"`
	SSDFTasks      []string `yaml:"ssdf_tasks"`
	AnswerType     string   `yaml:"answer_type"`
	EvidencePrompt string   `yaml:"evidence_prompt,omitempty"`
	Pairing        []string `yaml:"pairing,omitempty"`
}

// SelfAttestationQuestions is the parsed, validated content of
// mappings/self-attestation-questions.yaml.
type SelfAttestationQuestions struct {
	Version   string                    `yaml:"version"`
	Questions []SelfAttestationQuestion `yaml:"questions"`

	// QuestionByID indexes Questions by ID for O(1) lookup; populated by
	// LoadSelfAttestationQuestions, not part of the YAML itself.
	QuestionByID map[string]SelfAttestationQuestion `yaml:"-"`
}

// LoadSelfAttestationQuestions reads and strictly validates a
// self-attestation-questions.yaml-shaped file from the local filesystem —
// used by tests. The shipped binary uses LoadSelfAttestationQuestionsFS
// against the embedded mappings.FS instead.
func LoadSelfAttestationQuestions(path string, ssdf *SSDFMapping) (*SelfAttestationQuestions, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return decodeSelfAttestationQuestions(f, path, ssdf)
}

// LoadSelfAttestationQuestionsFS is LoadSelfAttestationQuestions for an
// fs.FS (e.g. the embedded mappings.FS) instead of the local filesystem.
func LoadSelfAttestationQuestionsFS(fsys fs.FS, name string, ssdf *SSDFMapping) (*SelfAttestationQuestions, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	return decodeSelfAttestationQuestions(f, name, ssdf)
}

// decodeSelfAttestationQuestions holds the decode+validate logic shared by
// LoadSelfAttestationQuestions and LoadSelfAttestationQuestionsFS. ssdf
// must be an already-loaded SSDFMapping: every ssdf_tasks entry must
// resolve to a task defined there, the same cross-file referential-
// integrity check LoadCISA already enforces for cisa-ssda-form.yaml.
func decodeSelfAttestationQuestions(r io.Reader, source string, ssdf *SSDFMapping) (*SelfAttestationQuestions, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var m SelfAttestationQuestions
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", source, err)
	}

	m.QuestionByID = make(map[string]SelfAttestationQuestion, len(m.Questions))
	for _, q := range m.Questions {
		if !selfAttestIDPattern.MatchString(q.ID) {
			return nil, fmt.Errorf("%s: question id %q does not match the self-attestation ID format (e.g. SA.threat-modeling)", source, q.ID)
		}
		if _, dup := m.QuestionByID[q.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate question id %q", source, q.ID)
		}
		if !validAnswerTypes[q.AnswerType] {
			return nil, fmt.Errorf("%s: question %s: answer_type %q must be one of yes_no, yes_no_evidence, text", source, q.ID, q.AnswerType)
		}
		for _, taskID := range q.SSDFTasks {
			if _, ok := ssdf.TaskByID[taskID]; !ok {
				return nil, fmt.Errorf("%s: question %s references unknown SSDF task %q", source, q.ID, taskID)
			}
		}
		m.QuestionByID[q.ID] = q
	}

	return &m, nil
}
