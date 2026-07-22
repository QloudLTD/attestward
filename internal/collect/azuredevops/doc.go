// Package azuredevops implements the collect.Collector interface against the
// Azure DevOps REST API. This package owns PAT authentication, the read-only
// transport guard (ADR-0004), and rate-limit handling; the client/pagination
// plumbing individual collectors call lands in a later PR, and the
// collectors themselves (C01-C10 parity) start after that — see issue #34.
//
// Azure DevOps's rate-limit model differs from GitHub's in a way that
// shapes ratelimit.go: GitHub signals a single failure mode (403/429) split
// into two tiers by response headers — primary (retryable once the window
// resets) and secondary (a permanent stop, never retried). ADO instead
// attaches Retry-After to two distinct outcomes: a "delay" that still
// succeeds (HTTP 200) but asks the caller to slow down before its *next*
// request, and a "block" (HTTP 429, error code TF400733) that must be
// retried in place, bounded, before surfacing as an error. See
// rateLimitTransport's doc comment for the detail.
//
// Multi-host: unlike GitHub's single api.github.com, a single ADO scan
// spreads across dev.azure.com (core), vssps.dev.azure.com (Graph),
// advsec.dev.azure.com (Advanced Security), and auditservice.dev.azure.com
// (Audit) — so provenance and fixture keys include the host, never just the
// path.
package azuredevops
