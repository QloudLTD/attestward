package mapping

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// CISASource cites the primary source a mapping file was transcribed from.
type CISASource struct {
	Title          string `yaml:"title"`
	Publisher      string `yaml:"publisher"`
	Identifier     string `yaml:"identifier"`
	URL            string `yaml:"url"`
	FileDated      string `yaml:"file_dated"`
	LegalAuthority string `yaml:"legal_authority"`
}

// CISASubElement is one lettered sub-part of a cluster (e.g. "1a"). SSDFTasks
// is only populated where CISA's own Appendix table provides that
// granularity — see mappings/cisa-ssda-form.yaml's cluster "4" notes for the
// case where it doesn't.
type CISASubElement struct {
	ID        string   `yaml:"id"`
	FormText  string   `yaml:"form_text"`
	SSDFTasks []string `yaml:"ssdf_tasks,omitempty"`
}

// CISACluster is one of the SSDA form's four attestation clusters.
type CISACluster struct {
	ID          string           `yaml:"id"`
	Title       string           `yaml:"title"`
	FormText    string           `yaml:"form_text"`
	SSDFTasks   []string         `yaml:"ssdf_tasks"`
	Notes       string           `yaml:"notes,omitempty"`
	SubElements []CISASubElement `yaml:"sub_elements,omitempty"`
}

// CISAMapping is the parsed, validated content of mappings/cisa-ssda-form.yaml.
type CISAMapping struct {
	Version                 string        `yaml:"version"`
	Source                  CISASource    `yaml:"source"`
	Retrieved               string        `yaml:"retrieved"`
	NotifyOnCessationClause string        `yaml:"notify_on_cessation_clause,omitempty"`
	Clusters                []CISACluster `yaml:"clusters"`

	// ClusterByID indexes Clusters by ID; populated by LoadCISA, not part
	// of the YAML itself.
	ClusterByID map[string]CISACluster `yaml:"-"`
}

// LoadCISA reads and strictly validates a cisa-ssda-form.yaml-shaped file.
// ssdf must be an already-loaded SSDFMapping (see LoadSSDF): every
// ssdf_tasks entry, at cluster level and sub-element level, must resolve to
// a task defined there — this is the cross-file referential-integrity check
// issue #7 requires, and it fails loudly rather than silently accepting a
// dangling reference.
func LoadCISA(path string, ssdf *SSDFMapping) (*CISAMapping, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var m CISAMapping
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	m.ClusterByID = make(map[string]CISACluster, len(m.Clusters))
	for _, cluster := range m.Clusters {
		if _, dup := m.ClusterByID[cluster.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate cluster id %q", path, cluster.ID)
		}
		for _, taskID := range cluster.SSDFTasks {
			if _, ok := ssdf.TaskByID[taskID]; !ok {
				return nil, fmt.Errorf("%s: cluster %s references unknown SSDF task %q", path, cluster.ID, taskID)
			}
		}
		for _, sub := range cluster.SubElements {
			for _, taskID := range sub.SSDFTasks {
				if _, ok := ssdf.TaskByID[taskID]; !ok {
					return nil, fmt.Errorf("%s: cluster %s sub-element %s references unknown SSDF task %q", path, cluster.ID, sub.ID, taskID)
				}
			}
		}
		m.ClusterByID[cluster.ID] = cluster
	}

	return &m, nil
}
