package mapping

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	taskIDPattern     = regexp.MustCompile(`^(PO|PS|PW|RV)\.[0-9]+\.[0-9]+$`)
	practiceIDPattern = regexp.MustCompile(`^(PO|PS|PW|RV)\.[0-9]+$`)
)

// SSDFSource cites the primary source a mapping file was transcribed from.
type SSDFSource struct {
	Title      string `yaml:"title"`
	Publisher  string `yaml:"publisher"`
	Identifier string `yaml:"identifier"`
	DOI        string `yaml:"doi,omitempty"`
	URL        string `yaml:"url"`
	Published  string `yaml:"published"`
}

// SSDFPractice is the title/text of one SSDF practice (e.g. "PO.5").
type SSDFPractice struct {
	Title string `yaml:"title"`
	Text  string `yaml:"text"`
}

// SSDFTask is one SSDF task entry: verbatim source text plus the attestor
// check IDs (if any yet) that provide evidence for it.
type SSDFTask struct {
	ID       string   `yaml:"id"`
	Family   string   `yaml:"family"`
	Practice string   `yaml:"practice"`
	Text     string   `yaml:"text"`
	Summary  string   `yaml:"summary,omitempty"`
	Notes    string   `yaml:"notes,omitempty"`
	Checks   []string `yaml:"checks"`
}

// SSDFMapping is the parsed, validated content of mappings/ssdf-800-218.yaml.
type SSDFMapping struct {
	Version   string                  `yaml:"version"`
	Source    SSDFSource              `yaml:"source"`
	Retrieved string                  `yaml:"retrieved"`
	Practices map[string]SSDFPractice `yaml:"practices"`
	Tasks     []SSDFTask              `yaml:"tasks"`

	// TaskByID indexes Tasks by ID for O(1) lookup; populated by LoadSSDF,
	// not part of the YAML itself.
	TaskByID map[string]SSDFTask `yaml:"-"`
}

// LoadSSDF reads and strictly validates an ssdf-800-218.yaml-shaped file
// from the local filesystem — used by tests, which read straight from the
// repo checkout. The shipped binary uses LoadSSDFFS against the embedded
// mappings.FS instead (ADR-0002: single static binary — mapping data can't
// depend on files existing next to the executable at runtime).
func LoadSSDF(path string) (*SSDFMapping, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return decodeSSDF(f, path)
}

// LoadSSDFFS is LoadSSDF for an fs.FS (e.g. the embedded mappings.FS) instead
// of the local filesystem.
func LoadSSDFFS(fsys fs.FS, name string) (*SSDFMapping, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	return decodeSSDF(f, name)
}

// decodeSSDF holds the actual decode+validate logic shared by LoadSSDF and
// LoadSSDFFS: unknown fields, duplicate task IDs, malformed ID formats, and
// task/practice/family mismatches are all reported as errors rather than
// silently accepted — this is the enforcement layer behind
// docs/schema/mapping-ssdf-800-218.schema.json. source is used only to
// prefix error messages.
func decodeSSDF(r io.Reader, source string) (*SSDFMapping, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var m SSDFMapping
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", source, err)
	}

	m.TaskByID = make(map[string]SSDFTask, len(m.Tasks))
	for _, task := range m.Tasks {
		if !taskIDPattern.MatchString(task.ID) {
			return nil, fmt.Errorf("%s: task id %q does not match the SSDF task ID format (e.g. PO.5.1)", source, task.ID)
		}
		if !practiceIDPattern.MatchString(task.Practice) {
			return nil, fmt.Errorf("%s: task %s: practice %q does not match the SSDF practice ID format (e.g. PO.5)", source, task.ID, task.Practice)
		}
		if !strings.HasPrefix(task.ID, task.Practice+".") {
			return nil, fmt.Errorf("%s: task %s: practice %q is not a prefix of its own task id", source, task.ID, task.Practice)
		}
		if task.Family != strings.SplitN(task.ID, ".", 2)[0] {
			return nil, fmt.Errorf("%s: task %s: family %q does not match the task id's family prefix", source, task.ID, task.Family)
		}
		if _, exists := m.Practices[task.Practice]; !exists {
			return nil, fmt.Errorf("%s: task %s: practice %q has no entry in practices", source, task.ID, task.Practice)
		}
		if _, dup := m.TaskByID[task.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate task id %q", source, task.ID)
		}
		m.TaskByID[task.ID] = task
	}

	return &m, nil
}
