package model

import "time"

// Provenance records exactly what the tool queried to reach a CheckResult's
// status, so the claim is independently auditable: the endpoint, when it was
// called, and a digest of what came back. Never the raw response body —
// responses may carry sensitive content (org member lists, alert detail);
// see ADR-0004 and docs/threat-model.md.
type Provenance struct {
	Endpoint       string    `json:"endpoint"`
	Method         string    `json:"method"`
	Timestamp      time.Time `json:"timestamp"`
	HTTPStatus     int       `json:"http_status"`
	ResponseSHA256 string    `json:"response_sha256"`
}

// ScopeRef identifies the org (and, for repo-level checks, the repo) a
// CheckResult applies to.
type ScopeRef struct {
	Org  string `json:"org"`
	Repo string `json:"repo,omitempty"`
	// Platform names which platform this specific check ran against:
	// "github" or "azuredevops" (issue #34's v0.2 epic). Additive/optional
	// — no SchemaVersion bump (docs/architecture.md's versioning policy).
	// Absent means "github": every check result produced before v0.2 never
	// set this field, and that must keep meaning exactly what it always
	// meant now that a second platform exists, not become ambiguous.
	Platform string `json:"platform,omitempty"`
	// Project is the project scope of the scan that produced this result —
	// stamped by the orchestrator from the scan's own config (cmd/attestward's
	// runScan), not derived per-check. An org-level check has no project of
	// its own, but still carries this to describe which scan produced it,
	// same as every other result from that scan. Empty for GitHub checks,
	// which have no project concept at this level.
	Project string `json:"project,omitempty"`
}

// CheckResult is one check's execution against one scope. Collectors
// produce these as pure data (ADR-0005) — no rendering or mapping logic
// belongs here or in anything that builds a CheckResult.
type CheckResult struct {
	// CheckID is the stable identifier a mapping file references, e.g.
	// "C02.repo-protection.required-reviews".
	CheckID string `json:"check_id"`
	Title   string `json:"title"`
	Status  Status `json:"status"`
	// Reason is the human-readable explanation of why Status was chosen —
	// this is what a reader sees next to the status in the report.
	Reason     string       `json:"reason"`
	Scope      ScopeRef     `json:"scope"`
	Provenance []Provenance `json:"provenance"`
	// Facts holds the minimal extracted key/value data that justified the
	// decision — never full API payloads. Values must be JSON-marshalable
	// scalars, slices, or maps thereof.
	Facts map[string]any `json:"facts,omitempty"`
}
