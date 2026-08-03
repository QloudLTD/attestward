package github

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/go-github/v75/github"
	"github.com/shurcooL/githubv4"

	"gitlab.com/sioakeim/attestward/internal/model"
)

// Client wraps the go-github REST client and the githubv4 GraphQL client
// with the plumbing every collector needs: bearer auth from a token that is
// never logged or persisted (docs/threat-model.md), provenance capture on
// every call, and rate-limit/backoff handling. Both clients share the same
// underlying *http.Client, so both contribute to the same Provenance()
// history.
type Client struct {
	REST    *github.Client
	GraphQL *githubv4.Client

	prov *provenanceTransport
}

// sameHostRedirectPolicy returns an http.Client CheckRedirect that follows
// a redirect only while it stays on the same host as base (api.github.com
// when base is nil, i.e. an unconfigured github.com scan), and refuses any
// hop that would change host.
//
// Comparing Host rather than the full URL is deliberate: a rename redirect
// changes the path, which is exactly the case that must keep working. Scheme
// is compared too, so an https -> http downgrade on the same host is refused
// — that would put the token on the wire in plaintext, which is the same
// harm by a quieter route.
func sameHostRedirectPolicy(base *url.URL) func(*http.Request, []*http.Request) error {
	wantHost := "api.github.com"
	wantScheme := "https"
	if base != nil {
		wantHost = base.Host
		wantScheme = base.Scheme
	}
	return func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != wantHost || req.URL.Scheme != wantScheme {
			return fmt.Errorf("collect/github: refusing a redirect from %s://%s to %s://%s — following it would re-send the token to a host the scan did not target",
				wantScheme, wantHost, req.URL.Scheme, req.URL.Host)
		}
		if len(via) >= 10 {
			return fmt.Errorf("collect/github: refusing to follow more than %d redirects", len(via))
		}
		return nil
	}
}

// NewClient builds a Client authenticated with token (typically read from
// the GITHUB_TOKEN environment variable by the caller — this package never
// reads the environment itself, keeping token sourcing the orchestrator's
// responsibility per the threat model), targeting cfg's host — github.com
// with the system trust store for the zero value, or a GitHub Enterprise
// Server install when cfg was built from ResolveHostConfig with a non-empty
// URL/CA cert (issue #11).
//
// cfg.RESTBaseURL and cfg.GraphQLURL are assigned directly rather than
// re-derived via github.Client.WithEnterpriseURLs here: that call already
// ran once, in ResolveHostConfig, at preflight — re-running it per Client
// (several collectors build one per repo) would mean re-validating and
// re-parsing the exact same already-normalized URL on every call for no
// benefit, and would reintroduce an error return this constructor is
// deliberately free of.
func NewClient(token string, cfg ClientConfig) *Client {
	base := http.RoundTripper(http.DefaultTransport)
	if cfg.CACertPool != nil {
		// http.DefaultTransport is a shared global — clone it rather than
		// mutating its TLSClientConfig in place, which would silently
		// affect every other user of http.DefaultTransport in the process.
		// Clone() preserves DefaultTransport's own Proxy:
		// http.ProxyFromEnvironment, so HTTPS_PROXY still applies here too.
		custom := http.DefaultTransport.(*http.Transport).Clone()
		custom.TLSClientConfig = &tls.Config{RootCAs: cfg.CACertPool}
		base = custom
	}

	prov := newProvenanceTransport(token, base)
	rl := newRateLimitTransport(prov)
	httpClient := &http.Client{
		Transport: rl,
		// Redirects are followed only when they stay on the host the
		// caller configured. Both halves matter.
		//
		// Refusing cross-host hops is a security boundary: auth is
		// injected inside provenanceTransport, which sits BELOW this
		// machinery, so Go's cross-domain header stripping never sees it.
		// Before this policy existed, a --github-url answering
		// 302 -> http://attacker/ handed that host a valid PAT and its
		// body came back as the API's answer with a nil error — a
		// verified-pass in a signed pack, sourced from a machine nobody
		// chose. Reproduced before the fix.
		//
		// Following same-host hops is a correctness requirement, and
		// refusing them outright was a regression found in review:
		// GitHub documents 301 for renamed or transferred repositories
		// and organizations, which net/http had always followed
		// transparently. A flat refusal broke every scan naming a repo by
		// its old name — on github.com, where nothing about GHES applies.
		// The sibling Gogs client does refuse outright, and that remains
		// right there: Gogs has no rename-redirect semantics to preserve.
		//
		// The GraphQL client shares this http.Client and is covered too.
		CheckRedirect: sameHostRedirectPolicy(cfg.RESTBaseURL),
	}

	rest := github.NewClient(httpClient)
	// go-github has its own built-in rate-limit tracking/blocking, but
	// githubv4 (used for GraphQL) has none — rather than half-rely on
	// go-github's REST-specific behavior and half on our own for GraphQL,
	// rateLimitTransport handles both uniformly, so go-github's is disabled.
	rest.DisableRateLimitCheck = true

	graphQL := githubv4.NewClient(httpClient)
	if cfg.RESTBaseURL != nil {
		rest.BaseURL = cfg.RESTBaseURL
		// UploadURL is deliberately left at its default. It was previously
		// set to RESTBaseURL, which is both the wrong value (go-github's
		// own WithEnterpriseURLs derives /api/uploads/) and a pointer
		// shared across every concurrently-constructed per-repo client.
		// Nothing in this tool uploads — the transport refuses any method
		// other than GET or HEAD — so the honest choice is not to set a
		// value at all rather than set a wrong one that happens never to
		// be dereferenced.
	}
	if cfg.GraphQLURL != "" {
		graphQL = githubv4.NewEnterpriseClient(cfg.GraphQLURL, httpClient)
	}

	return &Client{
		REST:    rest,
		GraphQL: graphQL,
		prov:    prov,
	}
}

// Provenance returns a copy of every API call's provenance entry recorded
// so far (across both REST and GraphQL calls made through this Client),
// including retried attempts — each retry is a distinct real call and gets
// its own entry.
func (c *Client) Provenance() []model.Provenance {
	return c.prov.Provenance()
}

// Scopes returns the OAuth scopes GitHub reported for the token in use, or
// nil if no authenticated request has completed yet or the token is a
// fine-grained PAT (which GitHub doesn't expose via response-header
// introspection — see scopeTracker).
func (c *Client) Scopes() []string {
	return c.prov.scopes.Scopes()
}

// HasWriteScope is a best-effort least-privilege signal — see
// scopeTracker.HasWriteScope — for the CLI to warn on, never a hard block.
func (c *Client) HasWriteScope() bool {
	return c.prov.scopes.HasWriteScope()
}

// GHESVersion returns the GitHub Enterprise Server version this Client's
// target reported on its first authenticated response, or "" if either no
// authenticated response has completed yet or the target is github.com
// (which never sends the X-GitHub-Enterprise-Version header — see
// hostVersionTracker). Resolved once and meant to be carried the way
// collect.Scope.AccountType already is (issue #12's GHES epic) — a
// collector should read it from collect.Scope, not call this directly.
func (c *Client) GHESVersion() string {
	return c.prov.hostVersion.Version()
}
