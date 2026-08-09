// Package gogs implements the platform-access layer for scanning a
// self-hosted Gogs instance (Gogs issue #4), the third platform behind
// ADR-0005's Collector seam after GitHub and Azure DevOps.
//
// Three things make Gogs different from both existing platforms, and every
// design choice in this package follows from one of them.
//
// # There is no hosted instance
//
// GitHub collectors talk to api.github.com and Azure DevOps collectors to a
// fixed set of dev.azure.com hosts; both are compile-time constants. Every
// Gogs install lives at its own hostname, so Client carries a base URL
// supplied by the caller (--gogs-url) and resolves every request against
// it. Gogs supports being served under a suburl, so the base URL may carry
// a path prefix, which is why paths are joined rather than concatenated.
//
// # A token is the only credential that works
//
// The Gogs REST API rejects HTTP basic auth outright — it answers 401 even
// for a correct username and account password — so provenanceTransport
// injects "Authorization: token <t>" and there is deliberately no second
// auth scheme to fall back to.
//
// # There is no rate limiting, and the one list endpoint tested does not paginate
//
// Gogs sends no rate-limit headers at all, so this package has no analog of
// the GitHub or ADO rate-limit transports; retryTransport handles transient
// 5xx and nothing else.
//
// Nor does it paginate — but the evidence is narrower than the habit it
// establishes, so it is stated precisely: verified against Gogs 0.15 on
// 2026-08-03, GET /user/repos returned all 48 repositories in one response
// and the identical 48 for ?page=1 and ?page=2. The parameter is accepted
// and ignored. That is one endpoint on one version, not a proven property
// of every list endpoint on every version, and a client written to follow
// pages the way the ADO client does would never terminate against that
// observed behaviour.
//
// So this package does not page. checkNoPagination catches one specific way
// that could go wrong: any response *advertising* pagination fails the call
// loudly, rather than being read as a complete set.
//
// It does not catch the other way, and that limitation is worth stating
// plainly rather than leaving a reader to assume the assumption is fully
// self-enforcing. A server that silently truncates — returning a first page
// with no pagination headers at all — is indistinguishable here from one
// returning everything, so a partial result would decode cleanly, return a
// nil error, and reach signed evidence presented as complete. That is not a
// hypothetical shape: Gogs already accepts and ignores ?page today, so the
// request-side plumbing exists and a version that starts honouring it with
// a default page size would defeat the header check entirely.
//
// Closing that properly needs either a probe (request page 2 and fail if it
// returns a different non-empty set) or a recorded count fact, so a pack
// diff surfaces 48 -> 30. Neither is done here; the gap is tracked rather
// than papered over.
//
// # What this package deliberately does not record
//
// model.Provenance entries carry the request path only, never the instance
// hostname — matching the GitHub transport rather than the ADO one, and for
// a reason specific to self-hosting: a Gogs instance is frequently on a
// private address or an internal DNS name, and an evidence pack is a
// document a producer hands to a customer or a regulator. Recording which
// checks ran against which path is the point; publishing a company's
// internal network topology in the same artifact is not. The instance
// identity belongs to the scan as a whole, not to each of its calls.
//
// Read-only forever (ADR-0004) is enforced structurally here, exactly as in
// the other two platform packages: see transport.go.
package gogs
