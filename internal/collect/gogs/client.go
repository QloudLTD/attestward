package gogs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"gitlab.com/sioakeim/attestward/internal/model"
)

// apiPrefix is the path every Gogs REST call sits under, appended to the
// instance base URL the caller supplied. Kept as a constant rather than
// asked of the user: --gogs-url takes the browser-facing root (what's in
// the address bar), so a user never has to know this.
const apiPrefix = "/api/v1"

// maxErrorBodyPreview bounds how much of a non-2xx response body
// StatusError quotes, so one huge error page — a Cloudflare block page, an
// instance's HTML 404 — doesn't blow up a log line or a Reason string.
const maxErrorBodyPreview = 500

// Client is the plumbing every Gogs collector needs: base-URL resolution,
// token auth, provenance capture on every call (including retried
// attempts, each of which is a distinct real call and gets its own entry),
// and transient-5xx retry.
type Client struct {
	baseURL *url.URL
	prov    *provenanceTransport

	httpClient *http.Client
}

// NewClient builds a Client against the Gogs instance rooted at baseURL
// (the browser-facing root, e.g. https://gogs.example.com, optionally with
// a suburl path prefix), authenticated with token — typically read from
// GOGS_TOKEN by the caller, since this package never reads the environment
// itself, matching the token-sourcing convention of both other platform
// packages.
//
// An unparseable baseURL is an error rather than a panic or a silent
// fallback to some default host: there is no sensible default Gogs
// instance to fall back to, and a scan that quietly targeted the wrong
// server would produce an evidence pack that is wrong in the most
// dangerous way — confidently attributed to the wrong subject.
func NewClient(baseURL, token string) (*Client, error) {
	return newClient(baseURL, token, http.DefaultTransport)
}

// newClient is the single place the transport chain and the http.Client's
// policy are assembled. Both exported constructors delegate here so the test
// seam can never quietly stop exercising what production runs: adding a
// layer in one place used to mean remembering to add it in the other, and a
// forgotten layer would leave every collector's tests passing against a
// chain the shipped binary does not use.
func newClient(baseURL, token string, base http.RoundTripper) (*Client, error) {
	u, err := url.Parse(strings.TrimSuffix(baseURL, "/"))
	if err != nil {
		// Neither the value nor the wrapped url.Error is included: the
		// base URL may carry credentials, and url.Error embeds the
		// original string, so %q and %w would each leak it. The same
		// reasoning applies to every error below, none of which quotes
		// the input either.
		//
		// The credential check further down cannot be relied on to make
		// this safe, because it does not catch every shape: a scheme-less
		// paste like "admin:s3cr3t@gogs.example.com" parses with Scheme
		// "admin" and User nil, so it would reach the scheme rule with the
		// secret intact. Refusing to quote the input at all is what closes
		// the class. cmd/attestward's validateGogsURL learned this the
		// same way; this layer needs it independently, because NewClient
		// is exported and has direct library callers that never pass
		// through the CLI's validation.
		return nil, fmt.Errorf("collect/gogs: base URL is not a valid URL")
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("collect/gogs: base URL needs a scheme and host (e.g. https://gogs.example.com)")
	}
	// Credentials in the base URL are refused outright rather than
	// stripped. They cannot possibly work — the Gogs API rejects HTTP basic
	// auth even with a correct password — and BaseURL() is documented for
	// collectors to record as a Fact, where url.URL.String() prints the
	// password verbatim into a signed evidence pack. A user who reaches for
	// https://user:pass@host (a natural thing to try, precisely because this
	// package documents that basic auth fails) would otherwise get 401s AND
	// their password baked into the attestation artifact. Erroring tells
	// them what to do instead; silently stripping would leave them
	// wondering why auth still failed.
	if u.User != nil {
		return nil, fmt.Errorf("collect/gogs: base URL must not contain credentials — the Gogs API rejects basic auth, and this URL is recorded in the evidence pack; supply the token separately")
	}

	prov := newProvenanceTransport(token, base)
	return &Client{
		baseURL: u,
		prov:    prov,
		httpClient: &http.Client{
			Transport: newRetryTransport(prov),
			// Redirects are never followed, and this is a security
			// boundary rather than a preference.
			//
			// Auth is injected inside provenanceTransport, which sits
			// BELOW the redirect machinery. Go strips sensitive headers on
			// a cross-domain redirect only for headers set on the original
			// request, so it never sees ours: every hop gets a freshly
			// minted "Authorization: token <t>" for whatever host the
			// redirect names. Verified empirically before this guard
			// existed — a server answering 302 -> http://attacker/ handed
			// the attacker the token, and GetJSON decoded the attacker's
			// body and returned it as the API's answer with a nil error.
			// Because provenance records the path only (deliberately — see
			// the package doc), nothing in the resulting signed pack could
			// reveal the evidence came from a different server.
			//
			// The sibling GitHub and Azure DevOps packages do not do this
			// and do not need to: they talk to compile-time-constant hosts.
			// This is the first platform package whose base URL comes from
			// the user, which is what makes the hole reachable.
			//
			// Not following means a redirecting instance surfaces as a
			// *StatusError carrying the 3xx — see newRedirectError — so a
			// collector branches on the status through StatusCodeOf like
			// any other non-2xx, rather than string-matching a message.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// immediately is NewClientForTest's stand-in for the backoff timer: it
// fires at once, so retry logic runs unchanged while the wall-clock wait —
// which proves nothing — is skipped.
func immediately(time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	ch <- time.Time{}
	return ch
}

// NewClientForTest builds a Client whose transport chain terminates in
// transport (typically gogsfixture.New()) instead of a real network
// round-tripper, reusing this package's real auth, provenance and retry
// layers — and its redirect policy — by delegating to the same private
// constructor production uses. It is the cross-package testing seam every
// collector package outside this one needs, mirroring
// azuredevops.NewClientForTest.
func NewClientForTest(baseURL, token string, transport http.RoundTripper) (*Client, error) {
	c, err := newClient(baseURL, token, transport)
	if err != nil {
		return nil, err
	}
	// The one deliberate divergence from production: retries do not sleep.
	// The retry logic itself — how many attempts, when it gives up, what it
	// returns — is exercised unchanged; only the wall-clock wait is skipped,
	// because a collector test covering a 5xx would otherwise pay the full
	// backoff for a delay that proves nothing. backoff() has its own direct
	// test in this package.
	rt, ok := c.httpClient.Transport.(*retryTransport)
	if !ok {
		// Checked rather than asserted bare: this line hard-codes the
		// chain shape that delegating to newClient just removed the
		// duplication of. Adding a layer above retryTransport would
		// otherwise panic every downstream package's tests with an opaque
		// interface-conversion message instead of naming the cause here.
		return nil, fmt.Errorf("collect/gogs: test client's transport is %T, not *retryTransport — the chain shape changed and this seam needs updating", c.httpClient.Transport)
	}
	rt.after = immediately
	return c, nil
}

// BaseURL returns the instance root this Client is scoped to. Collectors
// use it to record which instance a scan actually ran against as a fact —
// the provenance entries deliberately don't carry it (see the package doc
// comment), so this is the single place that identity comes from.
func (c *Client) BaseURL() string {
	return c.baseURL.String()
}

// Provenance returns a copy of every request's provenance entry recorded so
// far, including retried attempts.
func (c *Client) Provenance() []model.Provenance {
	return c.prov.Provenance()
}

// StatusError is returned when a response's status falls outside 2xx. It
// carries the status code so a collector can decide what that code means
// for its own check — "this Gogs version has no such endpoint" and "this
// repo does not exist" are both 404 here, and telling them apart is a
// semantic judgment belonging to the caller, not to this transport layer.
type StatusError struct {
	Method     string
	Endpoint   string // path only, mirroring model.Provenance.Endpoint
	StatusCode int
	// Body is Gogs' own JSON error message when the response parses as
	// its error envelope, or otherwise a bounded, rune-safe preview of
	// the raw bytes. Never a request header, so the token can never
	// reach this error's text — which matters because a Reason built
	// from it renders verbatim into a signed evidence pack.
	Body string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("collect/gogs: %s %s: unexpected status %d: %s", e.Method, e.Endpoint, e.StatusCode, e.Body)
}

// StatusCodeOf reports the HTTP status carried by err if it is (or wraps) a
// *StatusError, and whether it was one. Collectors use it instead of
// string-matching an error message when deciding what a specific status
// means for their check.
func StatusCodeOf(err error) (int, bool) {
	var se *StatusError
	if !errors.As(err, &se) {
		return 0, false
	}
	return se.StatusCode, true
}

// gogsErrorEnvelope is the shape Gogs uses for API errors that aren't a raw
// HTML page: {"message": "...", "url": "..."}. The url field is the
// documentation link and is deliberately not carried into StatusError —
// it's constant per error class and adds nothing to an evidence pack.
type gogsErrorEnvelope struct {
	Message string `json:"message"`
}

func newStatusError(method, endpoint string, statusCode int, body []byte) *StatusError {
	var env gogsErrorEnvelope
	if err := json.Unmarshal(body, &env); err == nil && env.Message != "" {
		// Bounded like the raw path below. An unbounded message defeats
		// maxErrorBodyPreview's whole purpose, and this string renders
		// verbatim into a signed pack's Reason.
		return &StatusError{Method: method, Endpoint: endpoint, StatusCode: statusCode, Body: previewBody([]byte(env.Message))}
	}
	return &StatusError{Method: method, Endpoint: endpoint, StatusCode: statusCode, Body: previewBody(body)}
}

// GetJSON issues a GET to the instance's apiPrefix+path and decodes the
// response body into *out.
//
// It does not paginate. The evidence for that is narrower than the habit it
// establishes, so state it precisely: against Gogs 0.15 on 2026-08-03,
// GET /user/repos returned all 48 repositories in a single response and the
// identical 48 for ?page=1 and ?page=2 — the parameter is accepted and
// ignored. That is one endpoint on one version, not a proven property of
// every list endpoint. checkNoPagination catches a server that advertises
// pagination; it cannot catch one that silently truncates, which is the
// likelier evolution — see the package doc comment for why, and for what
// closing it properly would take. A pagination loop keyed on "a full page means there may be more"
// would, against that observed behaviour, either loop forever or duplicate
// every result — which is why none is written here.
//
// path must begin with "/" and must not contain ".." segments
// (validatePath), and is expected already decoded: it is escaped once on
// the way out, so a pre-escaped "feat%2Fx" would reach the server as
// "feat%252Fx".
//
// A non-2xx response comes back as a *StatusError. Note what this does NOT
// catch: a 200 whose body is valid JSON of the wrong shape decodes into the
// zero value of *out with a nil error, exactly as the Azure DevOps twin's
// GetJSONObject warns. A caller that then reads a field would report
// "verified" against zero evidence. Where that matters, check a field the
// real response always populates rather than trusting a nil error alone.
func GetJSON[T any](ctx context.Context, c *Client, path string, query url.Values, out *T) error {
	statusCode, body, err := c.fetch(ctx, path, query)
	if err != nil {
		return err
	}
	if statusCode < 200 || statusCode >= 300 {
		return newStatusError(http.MethodGet, apiPrefix+path, statusCode, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("collect/gogs: decode response for %s: %w", path, err)
	}
	return nil
}

// GetRaw issues a GET to the instance's apiPrefix+path and returns the
// response body unparsed — for the raw-file endpoint, whose response is
// file content rather than JSON. A non-2xx response comes back as a
// *StatusError, so "this file does not exist" reaches the caller as a 404
// it can interpret, not as an empty body indistinguishable from an empty
// file.
func (c *Client) GetRaw(ctx context.Context, path string) ([]byte, error) {
	statusCode, body, err := c.fetch(ctx, path, nil)
	if err != nil {
		return nil, err
	}
	if statusCode < 200 || statusCode >= 300 {
		return nil, newStatusError(http.MethodGet, apiPrefix+path, statusCode, body)
	}
	return body, nil
}

// fetch issues a single GET through the full transport chain and returns
// the status and body. A non-2xx status is not an error here — each caller
// decides what one means for its own shape — so this only reports
// transport and read failures.
func (c *Client) fetch(ctx context.Context, path string, query url.Values) (int, []byte, error) {
	if err := validatePath(path); err != nil {
		return 0, nil, err
	}

	u := *c.baseURL
	// Join rather than concatenate: the base URL may legitimately carry a
	// suburl path prefix, which a bare Path assignment would discard —
	// silently scanning the wrong location on instances served under one.
	u.Path = strings.TrimSuffix(u.Path, "/") + apiPrefix + path
	if query != nil {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, fmt.Errorf("collect/gogs: build request for %s: %w", path, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("collect/gogs: request %s: %w", path, err)
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		return 0, nil, fmt.Errorf("collect/gogs: read response body for %s: %w", path, readErr)
	}

	if isRedirect(resp.StatusCode) {
		return 0, nil, newRedirectError(path, resp.StatusCode, resp.Header.Get("Location"))
	}
	if err := checkNoPagination(resp.Header, path); err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

// redirectStatuses are the codes that actually mean "go somewhere else".
// 3xx is not synonymous with that: 304 Not Modified and 305 Use Proxy live
// in the same range and are not redirects, and telling a user their 304
// means they should have used https:// would send them somewhere useless.
// Nothing in this package sends conditional request headers today, so a 304
// is unreachable — the point is that the advice stays correct if that ever
// changes.
var redirectStatuses = map[int]bool{
	http.StatusMovedPermanently:  true, // 301
	http.StatusFound:             true, // 302
	http.StatusSeeOther:          true, // 303
	http.StatusTemporaryRedirect: true, // 307
	http.StatusPermanentRedirect: true, // 308
}

func isRedirect(statusCode int) bool { return redirectStatuses[statusCode] }

// maxLocationPreview bounds how much of a redirect target reaches an error
// message, and through it a signed pack.
const maxLocationPreview = 200

// newRedirectError explains a refused redirect as a *StatusError, so a
// collector can branch on the status code the same way it does for any
// other non-2xx rather than matching on message text.
//
// The Location value is bounded and carried as the error body: it is a
// third party's host and path, chosen by whoever configured the redirect,
// and it renders verbatim into a signed pack's Reason. That is the same
// class of exposure previewBody exists for — bounded harder here, since a
// redirect target only needs to be recognisable, not reproduced, and the
// rest of this message is already several hundred characters of fixed
// explanation.
//
// The message distinguishes two cases, because the fix differs. A redirect
// on every endpoint usually means the base URL itself is wrong — commonly
// http:// against an instance that redirects to https://, or an SSO
// front-end sending the client to a login page. A redirect on one endpoint
// cannot be fixed by changing --gogs-url at all, and telling someone to do
// so would waste their time; that case is a genuine incompatibility worth
// reporting.
func newRedirectError(path string, statusCode int, location string) *StatusError {
	body := fmt.Sprintf("instance redirected to %s and redirects are never followed, because a redirect would re-send the token to whatever host it names. "+
		"If every endpoint redirects, --gogs-url is pointing at the wrong URL — most often http:// against an instance that redirects to https://, or an SSO front-end redirecting to a login page. "+
		"If only this endpoint redirects, changing --gogs-url will not help: report it, since this client cannot read that endpoint on this instance.",
		truncate(location, maxLocationPreview))
	return &StatusError{Method: http.MethodGet, Endpoint: apiPrefix + path, StatusCode: statusCode, Body: body}
}

// paginationHeaders are the response headers that would indicate this API
// had started paginating. See checkNoPagination.
var paginationHeaders = []string{"Link", "X-Total-Count", "X-Total", "X-Page-Count", "X-Has-More"}

// checkNoPagination fails the call if the server advertises pagination.
//
// This package does not page (see GetJSON), on the strength of a verified
// observation about Gogs 0.15. A verified observation about one version is
// not a guarantee about the next one, and the failure mode if it changes is
// the worst kind available here: page one decodes cleanly, the call returns
// a nil error, and a collector reports a partial result as the complete set
// — a silent truncation landing in signed evidence. That is precisely the
// defect class this codebase keeps finding.
//
// This catches the advertising case only. A server that silently truncates
// sends no such header and is not caught — see the package doc comment,
// which states that gap rather than implying this closes it. Gogs sends
// none of these headers today (verified: the only response headers are
// Content-Type, Set-Cookie and two security headers), so this costs
// nothing until something changes.
func checkNoPagination(header http.Header, path string) error {
	for _, h := range paginationHeaders {
		if v := header.Get(h); v != "" {
			return fmt.Errorf("collect/gogs: %s: response carries a %s header (%q), so this endpoint paginates — this client does not page and would silently return a partial result as if it were complete; add paging deliberately, with its terminating condition proven against this server version", path, h, v)
		}
	}
	return nil
}

// validatePath rejects a request path that could escape the API prefix.
//
// Go does not normalize dot segments in a URL path, but nginx and most
// reverse proxies do — so a ".." reaching the wire in an owner, repo, ref
// or file name can climb out of /api/v1 and into the Gogs web routes on the
// way through a proxy. Every path in this package is built from
// caller-supplied identifiers, so this is reachable from any collector that
// interpolates a repo or file name without thinking about it.
//
// The leading-slash requirement is the same class of quiet bug: without it,
// "user" joins to "/api/v1user", which is a valid request to a route nobody
// intended.
func validatePath(path string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("collect/gogs: request path %q must begin with a slash", path)
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == ".." {
			return fmt.Errorf("collect/gogs: request path %q contains a %q segment, which a reverse proxy may resolve outside the API prefix", path, "..")
		}
	}
	return nil
}

// truncate bounds s to limit bytes, rune-safely, appending an ellipsis marker
// when it cuts. Shared by previewBody and newRedirectError so both bound
// the same way — cutting at a byte offset mid-UTF-8-sequence would produce
// invalid text in a string destined for a signed pack.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…(truncated)"
}

// previewBody bounds how much of a raw response body StatusError quotes,
// rune-safely: cutting at a byte offset mid-UTF-8-sequence would produce
// invalid text in an error that can end up in a signed evidence pack.
func previewBody(body []byte) string {
	return truncate(string(body), maxErrorBodyPreview)
}
