// Package gitlab implements the platform-access layer for scanning GitLab,
// the fourth platform behind ADR-0005's Collector seam after GitHub, Azure
// DevOps and Gogs.
//
// GitLab sits between the platforms that already exist rather than beside
// them, and the three things that follow from that shape every decision
// here.
//
// # It is both hosted and self-managed
//
// GitHub collectors talk to a compile-time api.github.com and Gogs
// collectors to whatever host the operator supplied. GitLab is both: most
// users mean gitlab.com, many run their own instance, and the API is
// identical either way. So Client carries a base URL like the Gogs client
// does, but defaults to gitlab.com when the caller supplies none — the
// default is safe here in a way it is not for Gogs, because there genuinely
// is a canonical hosted instance to mean.
//
// As with Gogs, a self-managed instance may be served under a path prefix,
// so paths are joined rather than concatenated.
//
// # It paginates, and says so
//
// This is the sharpest difference from Gogs, where the decision was not to
// page at all because the server accepts and ignores ?page. GitLab is the
// opposite: list endpoints page by default at 20 items, and every paged
// response carries X-Next-Page and X-Total-Pages headers describing exactly
// where the caller is.
//
// A client that ignored that would silently attest on the first 20
// repositories of a 200-repository group and present the result as complete
// — the same class of failure the Gogs package documents as its open gap,
// except here it would be guaranteed rather than hypothetical. GetJSONPaged
// therefore follows X-Next-Page to exhaustion, and bounds the walk with
// maxPages so a server that never stops advertising a next page fails
// loudly instead of looping forever.
//
// # Half its security surface is behind a paywall
//
// Secret Detection, SAST, Dependency Scanning and several approval rules are
// Premium or Ultimate features. On a free-tier project the corresponding API
// either 403s or returns an empty set that is indistinguishable, at the
// transport layer, from a genuinely clean project.
//
// That distinction is the whole correctness question for this platform. A
// collector that read an empty Secret Detection report as "no secrets
// found" would emit verified-pass for a project that has never had the
// feature enabled, and a collector that read a 403 as a failing control
// would emit verified-fail for a project that is not entitled to the
// control at all. Both are worse than declining to answer: an evidence pack
// is only worth signing if a pass means something.
//
// So tier detection is a first-class concern here rather than an
// afterthought, mirroring plangate.go in the GitHub and Azure DevOps
// packages, and any check that cannot distinguish "clean" from "not
// entitled" must report not-checkable with the tier as the reason. See
// ErrTierGated and the unsupported package.
//
// # What this package deliberately does not record
//
// model.Provenance entries carry the request path only, never the instance
// hostname, and never the token. A self-managed GitLab URL can itself be
// sensitive — it may name an internal host, a customer, or an acquisition
// that has not been announced — and an evidence pack is a document intended
// to be shared with an auditor. The base URL is a scan input, recorded once
// in the pack's scope, not smeared across every provenance entry.
package gitlab
