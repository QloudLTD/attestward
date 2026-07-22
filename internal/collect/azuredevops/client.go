package azuredevops

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"unicode/utf8"

	"github.com/sioakim/attestward/internal/model"
)

// Per-service base hosts a single ADO scan calls against — see
// provenanceTransport's doc comment for why Endpoint (and adofixture's key)
// carry host, not just path.
const (
	// HostCore is dev.azure.com: projects, repositories, pipelines, builds,
	// and most other collector-facing APIs.
	HostCore = "dev.azure.com"
	// HostGraph is vssps.dev.azure.com: the Graph API (org membership,
	// group descriptors). No scope-introspection analog exists here to
	// GitHub's X-OAuth-Scopes — see the package doc comment.
	HostGraph = "vssps.dev.azure.com"
	// HostAdvSec is advsec.dev.azure.com: GitHub Advanced Security for Azure
	// DevOps (GHAzDO), licensed per active committer with no free tier —
	// see IsAdvSecGated in plangate.go.
	HostAdvSec = "advsec.dev.azure.com"
	// HostAudit is auditservice.dev.azure.com: the Audit Log API, available
	// only for Azure AD (Entra)-backed organizations — see IsAuditGated in
	// plangate.go.
	HostAudit = "auditservice.dev.azure.com"
)

// Client wraps the plumbing every ADO collector needs: Basic-auth PAT
// injection, provenance capture on every call (including retries — each
// retry is a distinct real call and gets its own entry), and TSTU
// delay/block handling. The transport chain is composed in the same order
// the GitHub client uses its own — rateLimitTransport wraps
// provenanceTransport, which wraps the real network transport — so a
// retried request produces one provenance entry per attempt here too, not
// just for the final one.
type Client struct {
	org  string
	prov *provenanceTransport

	httpClient *http.Client
}

// NewClient builds a Client scoped to org, authenticated with pat
// (typically read from the AZURE_DEVOPS_EXT_PAT environment variable by the
// caller — this package never reads the environment itself, the same
// token-sourcing convention as the GitHub client).
//
// PAT is the only credential this package supports today. Entra ID /
// Microsoft Graph OAuth tokens are explicitly out of scope for v0.2 (issue
// #34) and are noted here as future work, not merely unimplemented: Entra
// tokens are bearer tokens sent as "Authorization: Bearer <token>", a
// different auth scheme than a PAT's "Authorization: Basic
// base64(\":\"+pat)", so adding them later means extending this
// constructor and provenanceTransport's auth injection to support a second
// scheme, not just swapping in a different header value.
func NewClient(org, pat string) *Client {
	prov := newProvenanceTransport(pat, http.DefaultTransport)
	rl := newRateLimitTransport(prov)
	return &Client{
		org:        org,
		prov:       prov,
		httpClient: &http.Client{Transport: rl},
	}
}

// NewClientForTest builds a Client whose transport chain terminates in
// transport instead of a real network round-tripper (typically
// adofixture.New()), reusing this package's real auth+provenance+rate-limit
// layers unmodified — the cross-package testing seam every external
// consumer of Client needs (starting with pipelinehistory, issue #152, and
// every C05-C10-parity collector package after it). This package's own
// tests use an unexported equivalent (client_test.go's newTestClient,
// identical logic) directly against Client's unexported fields; a package
// outside azuredevops has no such access, and — unlike the GitHub client,
// whose REST field wraps a third-party client with its own public,
// test-server-redirectable BaseURL — this Client has no field a caller can
// swap after construction, since it's a from-scratch implementation with
// the transport chain fully assembled inside the constructor. This is that
// missing seam, exported.
func NewClientForTest(org, pat string, transport http.RoundTripper) *Client {
	prov := newProvenanceTransport(pat, transport)
	rl := newRateLimitTransport(prov)
	return &Client{
		org:        org,
		prov:       prov,
		httpClient: &http.Client{Transport: rl},
	}
}

// Org returns the organization this Client is scoped to, for collectors
// building ADO's org-scoped request paths (e.g. "/{org}/_apis/projects").
func (c *Client) Org() string {
	return c.org
}

// Provenance returns a copy of every request's provenance entry recorded so
// far, including retried attempts.
func (c *Client) Provenance() []model.Provenance {
	return c.prov.Provenance()
}

// page is the response envelope Azure DevOps's documented "List" endpoints
// use: {"count": N, "value": [...]}. Count is otherwise unused, but GetJSON
// treats count > 0 alongside an empty Value as a wrong-envelope sanity
// check — see its doc comment. ContinuationToken is a defensive fallback
// for a body-level continuation signal: every documented list host this
// project has verified (dev.azure.com core and vssps.dev.azure.com Graph)
// signals pagination via the X-MS-ContinuationToken response header
// instead, not a body field, and the audit-service family doesn't even
// share this {count,value} shape — it gets its own decode logic when S8
// (issue #154) needs it, not this generic path.
type page[T any] struct {
	Count             int    `json:"count"`
	Value             []T    `json:"value"`
	ContinuationToken string `json:"continuationToken"`
}

// continuationTokenParam is the query-parameter name Azure DevOps expects a
// continuation token echoed back as on the next request, regardless of
// which of the two places (see page's doc comment) the previous response
// carried it in.
const continuationTokenParam = "continuationToken"

// maxPages bounds how many pages GetJSON follows before giving up. This is
// a generous ceiling, not a normal limit — every list endpoint this project
// expects to call paginates in the tens of pages at most — but nothing
// upstream of GetJSON enforces a request timeout, so without a hard cap a
// misbehaving or misunderstood endpoint that keeps emitting a fresh
// continuation token forever would hang a scan indefinitely.
const maxPages = 1000

// maxErrorBodyPreview bounds how much of a non-2xx response body
// StatusError quotes when it can't parse Azure DevOps's own error envelope,
// so one huge error page doesn't blow up a log line.
const maxErrorBodyPreview = 500

// StatusError is returned when a response's status falls outside 2xx. It
// carries the status code so a collector can apply a plan-gating predicate
// (plangate.go) without string-matching this error's message.
type StatusError struct {
	Method     string
	Endpoint   string // host + path, mirrors model.Provenance.Endpoint
	StatusCode int
	// Body is the "message" field from Azure DevOps's own JSON error
	// envelope when the response body parses as that shape — the same
	// preference the GitHub side gives a parsed error message over a raw
	// body when it becomes a Reason in signed evidence.json — or otherwise
	// a bounded, rune-safe preview of the raw response bytes. Never a
	// request header, so a PAT can never reach this error's text.
	Body string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("collect/azuredevops: %s %s: unexpected status %d: %s", e.Method, e.Endpoint, e.StatusCode, e.Body)
}

// adoErrorEnvelope is Azure DevOps's typical JSON error response shape: a
// human-readable "message" alongside implementation details (typeKey,
// errorCode, ...) this project has no use for.
type adoErrorEnvelope struct {
	Message string `json:"message"`
}

// newStatusError prefers Azure DevOps's own parsed error message over the
// raw response body — see StatusError.Body's doc comment for why.
func newStatusError(method, endpoint string, statusCode int, body []byte) *StatusError {
	var env adoErrorEnvelope
	if err := json.Unmarshal(body, &env); err == nil && env.Message != "" {
		return &StatusError{Method: method, Endpoint: endpoint, StatusCode: statusCode, Body: env.Message}
	}
	return &StatusError{Method: method, Endpoint: endpoint, StatusCode: statusCode, Body: previewBody(body)}
}

// fetchOnce issues a single GET to https://host+path (query encoded)
// through c's full transport chain, returning the response's status code,
// header, and body. A non-2xx status is not itself an error here — GetJSON
// and GetJSONObject each decide what a non-2xx response means for their
// own shape — so this only reports transport/read failures.
func (c *Client) fetchOnce(ctx context.Context, host, path string, query url.Values) (statusCode int, header http.Header, body []byte, err error) {
	u := url.URL{Scheme: "https", Host: host, Path: path, RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("collect/azuredevops: build request for %s%s: %w", host, path, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("collect/azuredevops: request %s%s: %w", host, path, err)
	}

	b, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		return 0, nil, nil, fmt.Errorf("collect/azuredevops: read response body for %s%s: %w", host, path, readErr)
	}
	return resp.StatusCode, resp.Header, b, nil
}

// GetJSON issues a GET to https://host+path (query encoded; the caller
// supplies api-version and any endpoint-specific parameters) through c's
// full transport chain, decodes each page's Azure DevOps list envelope, and
// follows pagination to exhaustion — appending every page's Value into
// *out — before returning. Nothing is written to *out unless every page is
// fetched and decoded successfully, so a caller can't be left processing a
// partial result under an error it might not notice.
//
// GetJSON is a package-level generic function rather than a method on
// Client because Go does not support type parameters on methods; c is
// passed explicitly instead.
//
// Every documented list-pagination host this project has verified —
// dev.azure.com core APIs and vssps.dev.azure.com's Graph API (e.g. its
// Users List endpoint) — signals the next page via the
// X-MS-ContinuationToken response header. GetJSON also checks
// page.ContinuationToken, a body-level field, as a defensive fallback for
// an endpoint that might carry the token there instead; no currently
// verified endpoint does (see page's doc comment). Whichever is present is
// echoed back as the continuationToken query parameter on the next
// request; neither present means the caller has reached the last page.
//
// Two guards exist because nothing upstream of GetJSON enforces a request
// timeout, so a misbehaving or misunderstood endpoint must not be able to
// hang a scan forever: the same continuation token echoed back twice in a
// row is treated as a stuck loop, not slow progress, and is an immediate
// error; and a scan that still hasn't exhausted pagination after maxPages
// pages errors rather than silently truncating the result.
func GetJSON[T any](ctx context.Context, c *Client, host, path string, query url.Values, out *[]T) error {
	next := url.Values{}
	for k, v := range query {
		next[k] = append([]string(nil), v...)
	}
	prevToken := next.Get(continuationTokenParam)

	var pages []T
	for pageNum := 0; ; pageNum++ {
		if pageNum >= maxPages {
			return fmt.Errorf("collect/azuredevops: %s%s: exceeded %d pages without exhausting pagination — refusing to page forever", host, path, maxPages)
		}

		statusCode, header, body, err := c.fetchOnce(ctx, host, path, next)
		if err != nil {
			return err
		}
		if statusCode < 200 || statusCode >= 300 {
			return newStatusError(http.MethodGet, host+path, statusCode, body)
		}

		var pg page[T]
		if err := json.Unmarshal(body, &pg); err != nil {
			return fmt.Errorf("collect/azuredevops: decode response for %s%s: %w", host, path, err)
		}
		if pg.Count > 0 && len(pg.Value) == 0 {
			return fmt.Errorf("collect/azuredevops: %s%s: response reported count %d but an empty value array — wrong envelope shape for this endpoint", host, path, pg.Count)
		}
		pages = append(pages, pg.Value...)

		token := header.Get("X-MS-ContinuationToken")
		if token == "" {
			token = pg.ContinuationToken
		}
		if token == "" {
			*out = append(*out, pages...)
			return nil
		}
		if token == prevToken {
			return fmt.Errorf("collect/azuredevops: %s%s: server echoed the same continuation token (%q) twice in a row — refusing to loop forever", host, path, token)
		}
		next.Set(continuationTokenParam, token)
		prevToken = token
	}
}

// GetJSONObject issues a GET to https://host+path (query encoded) through
// c's full transport chain and decodes the response body directly into
// *out — for the non-paginated, single-object endpoints this project
// already knows it needs (e.g. Advanced Security enablement status, a
// build definition's generalsettings), which don't share GetJSON's
// {"count","value"} list envelope. Pointing GetJSON at one of these would
// decode silently empty rather than error — encoding/json ignores unknown
// fields, so a caller would misreport "verified" against zero evidence
// instead of getting a decode failure — which is exactly the misreport
// shape this codebase's provenance model exists to prevent.
//
// Like GetJSON, this is a package-level generic function rather than a
// method because Go has no type parameters on methods, and a non-2xx
// response comes back as a *StatusError.
func GetJSONObject[T any](ctx context.Context, c *Client, host, path string, query url.Values, out *T) error {
	statusCode, _, body, err := c.fetchOnce(ctx, host, path, query)
	if err != nil {
		return err
	}
	if statusCode < 200 || statusCode >= 300 {
		return newStatusError(http.MethodGet, host+path, statusCode, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("collect/azuredevops: decode response for %s%s: %w", host, path, err)
	}
	return nil
}

// previewBody bounds how much of a raw response body StatusError quotes
// when it isn't Azure DevOps's parsed error envelope, so one huge error
// page doesn't blow up a log line. Truncation is rune-safe: cutting at a
// byte offset that lands mid-UTF-8-sequence would produce invalid text in
// an error that can end up in a signed evidence pack.
func previewBody(body []byte) string {
	if len(body) <= maxErrorBodyPreview {
		return string(body)
	}
	cut := maxErrorBodyPreview
	for cut > 0 && !utf8.RuneStart(body[cut]) {
		cut--
	}
	return string(body[:cut]) + "…(truncated)"
}
