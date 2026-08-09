// Package mapping loads the versioned YAML mapping files under /mappings (SSDF
// SP 800-218 tasks, the CISA SSDA form's four practice clusters, and the
// scanner-signature registry) and rolls check results up through
// check -> SSDF task -> form cluster. Mappings are data, not code (ADR-0003);
// this package is the only place that interprets them.
package mapping
