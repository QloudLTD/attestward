package github

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/google/go-github/v75/github"
)

// ClientConfig configures NewClient's target host and TLS trust for a
// GitHub Enterprise Server (GHES) install (issue #11's GHES epic). The zero
// value targets github.com with the system trust store — exactly today's
// behavior — so every existing call site keeps compiling and behaving
// unchanged; only a caller that actually resolved a non-empty GHES URL or CA
// cert (via ResolveHostConfig) carries a non-zero ClientConfig.
type ClientConfig struct {
	// RESTBaseURL, when non-nil, points the REST client at a GHES host
	// instead of api.github.com. Already normalized by ResolveHostConfig to
	// include the "/api/v3/" suffix go-github's request builder needs —
	// NewClient never re-derives or re-validates it.
	RESTBaseURL *url.URL

	// GraphQLURL, when non-empty, is the resolved GraphQL endpoint
	// ("{host}/api/graphql") for the same GHES install.
	GraphQLURL string

	// CACertPool, when non-nil, replaces the shared http.Client's TLS trust
	// store — for GHES installs behind a private CA (GITHUB_CA_CERT). It
	// starts from the system pool (falling back to an empty one only if the
	// system pool can't be loaded) plus the configured PEM, so a GHES
	// install using a publicly-trusted cert alongside GITHUB_CA_CERT still
	// verifies.
	CACertPool *x509.CertPool
}

// ResolveHostConfig turns a raw --github-url/github_url:/GITHUB_URL value
// and an optional GITHUB_CA_CERT PEM path into a ClientConfig. It is meant
// to run once at preflight (cmd/attestward) and be carried into every
// ghcollect.NewClient call from there — the same "resolve once, carry it"
// pattern collect.AccountType already follows. rawURL == "" and
// caCertPath == "" both keep today's behavior unchanged (github.com, system
// trust store).
//
// rawURL accepts either a GHES install's browser-facing URL
// ("https://ghe.example.com") or an already-API URL
// ("https://ghe.example.com/api/v3/") without double-appending "/api/v3" —
// go-github's own Client.WithEnterpriseURLs distinguishes the two by
// checking the suffix, so this never string-mangles the REST path itself.
// Only the GraphQL endpoint is derived here (see deriveGraphQLURL's doc
// comment for why: neither go-github nor githubv4 exposes an
// enterprise-URL helper for GraphQL the way go-github does for REST).
func ResolveHostConfig(rawURL, caCertPath string) (ClientConfig, error) {
	var cfg ClientConfig

	if caCertPath != "" {
		pool, err := loadCACertPool(caCertPath)
		if err != nil {
			return ClientConfig{}, err
		}
		cfg.CACertPool = pool
	}

	if rawURL == "" {
		return cfg, nil
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ClientConfig{}, fmt.Errorf("--github-url %q: not a valid absolute URL (need a scheme and host, e.g. https://ghe.example.com)", rawURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ClientConfig{}, fmt.Errorf("--github-url %q: scheme must be http or https, got %q", rawURL, parsed.Scheme)
	}

	// WithEnterpriseURLs both re-validates the URL and applies go-github's
	// own "/api/v3/" suffixing rule (a no-op when the suffix is already
	// present) — reused via a throwaway client rather than reimplemented.
	enterprise, err := github.NewClient(nil).WithEnterpriseURLs(rawURL, rawURL)
	if err != nil {
		return ClientConfig{}, fmt.Errorf("--github-url %q: %w", rawURL, err)
	}
	cfg.RESTBaseURL = enterprise.BaseURL
	cfg.GraphQLURL = deriveGraphQLURL(enterprise.BaseURL)

	return cfg, nil
}

// deriveGraphQLURL builds "{scheme}://{host}[/subpath/]api/graphql" from an
// already-normalized REST base URL (ending in ".../api/v3/", optionally
// under a subpath some GHES installs are mounted at) by trimming the
// "api/v3/" REST suffix and appending "api/graphql".
func deriveGraphQLURL(restBase *url.URL) string {
	graphQL := *restBase
	graphQL.Path = strings.TrimSuffix(graphQL.Path, "api/v3/") + "api/graphql"
	return graphQL.String()
}

// loadCACertPool reads pemPath and returns the system trust store (or an
// empty pool if the system store can't be loaded) with that PEM appended —
// for GHES installs behind a private/self-signed CA, where the default
// trust store alone would reject every request.
func loadCACertPool(pemPath string) (*x509.CertPool, error) {
	data, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, fmt.Errorf("GITHUB_CA_CERT %s: %w", pemPath, err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if ok := pool.AppendCertsFromPEM(data); !ok {
		return nil, fmt.Errorf("GITHUB_CA_CERT %s: no PEM certificate found", pemPath)
	}
	return pool, nil
}
