package github

import (
	"net/http"

	"github.com/google/go-github/v75/github"
	"github.com/shurcooL/githubv4"

	"github.com/sioakim/attestward/internal/model"
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

// NewClient builds a Client authenticated with token (typically read from
// the GITHUB_TOKEN environment variable by the caller — this package never
// reads the environment itself, keeping token sourcing the orchestrator's
// responsibility per the threat model).
func NewClient(token string) *Client {
	prov := newProvenanceTransport(token, http.DefaultTransport)
	rl := newRateLimitTransport(prov)
	httpClient := &http.Client{Transport: rl}

	rest := github.NewClient(httpClient)
	// go-github has its own built-in rate-limit tracking/blocking, but
	// githubv4 (used for GraphQL) has none — rather than half-rely on
	// go-github's REST-specific behavior and half on our own for GraphQL,
	// rateLimitTransport handles both uniformly, so go-github's is disabled.
	rest.DisableRateLimitCheck = true

	return &Client{
		REST:    rest,
		GraphQL: githubv4.NewClient(httpClient),
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
