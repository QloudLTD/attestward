// Package collect defines the Collector interface that every platform-specific
// implementation (GitHub in v0.1; Azure DevOps and GitLab post-v0.1) satisfies.
// Collectors return pure []CheckResult data with no rendering or mapping logic;
// platform API access stays behind this seam so onboarding a new platform never
// touches internal/model, internal/mapping, or internal/report. See ADR-0005.
package collect
