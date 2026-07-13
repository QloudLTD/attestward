package model

import "time"

// SchemaVersion is the current evidence-pack schema version embedded in
// every pack. Bump only on a breaking change to the JSON structure — see
// the versioning policy in docs/architecture.md — and keep
// docs/schema/evidence-pack.v<N>.schema.json in lockstep with the bump.
const SchemaVersion = 1

// MappingVersions records the version field of every mappings/*.yaml file
// consulted during a scan, so a pack can be re-interpreted correctly even
// after the mapping files themselves evolve.
type MappingVersions struct {
	SSDF              string `json:"ssdf,omitempty"`
	CISAForm          string `json:"cisa_form,omitempty"`
	ScannerSignatures string `json:"scanner_signatures,omitempty"`
	SelfAttestation   string `json:"self_attestation,omitempty"`
}

// ScanScope is what a scan covered: the org, the in-scope repos, the
// release-tag pattern and lookback window used for release-history checks.
type ScanScope struct {
	Org               string   `json:"org"`
	Repos             []string `json:"repos"`
	ReleaseTagPattern string   `json:"release_tag_pattern,omitempty"`
	LookbackReleases  int      `json:"lookback_releases,omitempty"`
	LookbackMonths    int      `json:"lookback_months,omitempty"`
}

// TaskRollup is one SSDF task's rolled-up status: the reduction (via
// mapping.Rollup) of every CheckResult whose CheckID that task's `checks:`
// list cites.
type TaskRollup struct {
	TaskID string `json:"task_id"`
	Status Status `json:"status"`
}

// ClusterRollup is one CISA form cluster's rolled-up status: the reduction
// of every TaskRollup its ssdf_tasks list references.
type ClusterRollup struct {
	ClusterID string `json:"cluster_id"`
	Status    Status `json:"status"`
}

// Rollup is the mapping engine's check -> SSDF task -> CISA form cluster
// output (issues #6, #7, assembled by #10's orchestrator via
// internal/mapping.BuildRollup). Tasks/Clusters not cited by any check
// result are omitted, not present with a zero-value status — absence means
// "nothing in this pack speaks to this task/cluster," which is a different,
// honest claim from any of the five Status values.
type Rollup struct {
	Tasks    []TaskRollup    `json:"tasks"`
	Clusters []ClusterRollup `json:"clusters"`
}

// Integrity is reserved for pack hashing/signing (issue #27). Empty until
// then.
type Integrity struct {
	SHA256    string `json:"sha256,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// EvidencePack is the top-level evidence.json document: the full,
// self-contained record of one scan. It is a long-lived artifact — a vendor
// may need to re-read one years later during an FCA dispute — so every
// field here is meant to still make sense read cold, without this codebase.
//
// INVARIANT for whoever builds one (issue #24's writer): Results,
// Scope.Repos, every CheckResult's Provenance, and (when Rollup is set) its
// Tasks/Clusters must be initialized to an empty slice, never left nil.
// encoding/json marshals a nil slice as JSON null, and
// docs/schema/evidence-pack.v1.schema.json declares all of these
// `type: array` — a zero-value-ish pack fails its own schema. There's no
// MarshalJSON hook normalizing this; the writer must get it right at
// construction time.
type EvidencePack struct {
	SchemaVersion   int             `json:"schema_version"`
	ToolVersion     string          `json:"tool_version"`
	MappingVersions MappingVersions `json:"mapping_versions"`
	Scope           ScanScope       `json:"scope"`
	ScanStartedAt   time.Time       `json:"scan_started_at"`
	ScanEndedAt     time.Time       `json:"scan_ended_at"`
	Results         []CheckResult   `json:"results"`
	Rollup          *Rollup         `json:"rollup,omitempty"`
	Integrity       *Integrity      `json:"integrity,omitempty"`
}
