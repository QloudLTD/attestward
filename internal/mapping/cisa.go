package mapping

import (
	"fmt"
	"io"
	"io/fs"
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

// LoadCISA reads and strictly validates a cisa-ssda-form.yaml-shaped file
// from the local filesystem — used by tests. The shipped binary uses
// LoadCISAFS against the embedded mappings.FS instead.
func LoadCISA(path string, ssdf *SSDFMapping) (*CISAMapping, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return decodeCISA(f, path, ssdf)
}

// LoadCISAFS is LoadCISA for an fs.FS (e.g. the embedded mappings.FS)
// instead of the local filesystem.
func LoadCISAFS(fsys fs.FS, name string, ssdf *SSDFMapping) (*CISAMapping, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	return decodeCISA(f, name, ssdf)
}

// decodeCISA holds the decode+validate logic shared by LoadCISA and
// LoadCISAFS. ssdf must be an already-loaded SSDFMapping (see LoadSSDF):
// every ssdf_tasks entry, at cluster level and sub-element level, must
// resolve to a task defined there — this is the cross-file
// referential-integrity check issue #7 requires, and it fails loudly rather
// than silently accepting a dangling reference. source is used only to
// prefix error messages.
func decodeCISA(r io.Reader, source string, ssdf *SSDFMapping) (*CISAMapping, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var m CISAMapping
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", source, err)
	}

	m.ClusterByID = make(map[string]CISACluster, len(m.Clusters))
	for _, cluster := range m.Clusters {
		if _, dup := m.ClusterByID[cluster.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate cluster id %q", source, cluster.ID)
		}
		for _, taskID := range cluster.SSDFTasks {
			if _, ok := ssdf.TaskByID[taskID]; !ok {
				return nil, fmt.Errorf("%s: cluster %s references unknown SSDF task %q", source, cluster.ID, taskID)
			}
		}
		for _, sub := range cluster.SubElements {
			for _, taskID := range sub.SSDFTasks {
				if _, ok := ssdf.TaskByID[taskID]; !ok {
					return nil, fmt.Errorf("%s: cluster %s sub-element %s references unknown SSDF task %q", source, cluster.ID, sub.ID, taskID)
				}
			}
		}
		m.ClusterByID[cluster.ID] = cluster
	}

	return &m, nil
}
