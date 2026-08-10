package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"gitlab.com/sioakeim/attestward/internal/model"
)

// apiPrefix is the path every GitLab REST call sits under, appended to the
// instance base URL. Kept as a constant rather than asked of the user:
// --gitlab-url takes the browser-facing root, so nobody has to know this.
const apiPrefix = "/api/v4"

// defaultBaseURL is where a scan goes when the caller names no instance.
// Unlike Gogs — where defaulting would silently target the wrong server —
// GitLab genuinely has a canonical hosted instance, so this default is safe
// and saves every gitlab.com user a flag.
const defaultBaseURL = "https://gitlab.com"

// maxErrorBodyPreview bounds how much of a non-2xx body StatusError quotes,
// so one huge error page does not blow up a log line or a Reason string.
const maxErrorBodyPreview = 500

// perPage is the page size requested on every list call. GitLab's default is
// 20 and its maximum is 100; asking for the maximum cuts the number of round
// trips by 5x on any group of consequence, and a scan of a large group is
// otherwise dominated by pagination latency.
const perPage = 100

// maxPages bounds the pagination walk. GitLab tells us where we are via
// X-Next-Page, and a well-behaved server terminates. A server that does not
// — a proxy rewriting headers, a version with a bug — would otherwise spin
// forever against a customer's instance. Failing loudly at a bound beats
// looping, and 10,000 items is far past any real group.
const maxPages = 100

// ErrTierGated reports that an endpoint exists but this project's GitLab tier
// does not include the feature behind it.
//
// This is the single most important error in the package. GitLab returns 403
// for a Premium/Ultimate feature on a Free project, and a collector that read
// that as "the control is absent" would emit verified-fail for a project that
// was never entitled to the control. That is an actively harmful false
// negative: it tells a producer to fix something they cannot fix, and it puts
// a failure into a signed attestation that the evidence does not support.
//
// Collectors must translate this into not-checkable with the tier as the
// reason — never into a fail.
var ErrTierGated = errors.New("collect/gitlab: feature requires a paid GitLab tier")

// Client is the plumbing every GitLab collector needs: base-URL resolution,
// token auth, provenance capture on every call (including each retried
// attempt), rate-limit backoff and transient-5xx retry.
type Client struct {
	baseURL *url.URL
	prov    *provenanceTransport

	httpClient *http.Client
}

// NewClient builds a Client against the GitLab instance rooted at baseURL
// (the browser-facing root, e.g. https://gitlab.com or
// https://gitlab.example.com, optionally with a path prefix). An empty
// baseURL means gitlab.com.
//
// token is typically read from GITLAB_TOKEN by the caller; this package never
// reads the environment itself, matching the token-sourcing convention of the
// other three platform packages.
func NewClient(baseURL, token string) (*Client, error) {
	return newClient(baseURL, token, http.DefaultTransport)
}

// NewClientForTest is the seam tests use to supply a stub round-tripper. It
// assembles the identical transport chain as NewClient, deliberately: when
// the two were built separately, adding a layer to one and forgetting the
// other left every collector's tests passing against a client that was not
// what production ran.
func NewClientForTest(baseURL, token string, transport http.RoundTripper) (*Client, error) {
	return newClient(baseURL, token, transport)
}

func newClient(baseURL, token string, base http.RoundTripper) (*Client, error) {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultBaseURL
	}
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("collect/gitlab: parse base URL %q: %w", baseURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("collect/gitlab: base URL %q needs a scheme and host", baseURL)
	}

	// Order matters. Provenance is outermost so it records every attempt the
	// retry and rate-limit layers make; each is a real call that really
	// happened, and a pack that showed only the last one would understate
	// what the tool did to the instance.
	prov := newProvenanceTransport(token, newRateLimitTransport(newRetryTransport(base)))
	return &Client{
		baseURL:    u,
		prov:       prov,
		httpClient: &http.Client{Transport: prov},
	}, nil
}

// BaseURL returns the instance root this client targets.
func (c *Client) BaseURL() string { return c.baseURL.String() }

// Provenance returns every recorded call.
func (c *Client) Provenance() []model.Provenance { return c.prov.Provenance() }

// StatusError is a non-2xx response, carrying enough of the body to diagnose
// it without carrying so much that a log line becomes unreadable.
type StatusError struct {
	StatusCode int
	Endpoint   string
	Body       string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("collect/gitlab: %s returned HTTP %d: %s", e.Endpoint, e.StatusCode, e.Body)
}

// StatusCodeOf extracts the HTTP status from an error returned by this
// package, so a collector can distinguish 404 (no such thing) from 403 (not
// entitled) without string-matching.
func StatusCodeOf(err error) (int, bool) {
	var se *StatusError
	if errors.As(err, &se) {
		return se.StatusCode, true
	}
	return 0, false
}

// IsTierGated reports whether err indicates a paid-tier feature. GitLab is
// not consistent here — some Premium endpoints 403, some 404 to hide their
// existence — so callers should treat this as a strong hint and still prefer
// not-checkable over fail whenever they cannot positively confirm a control
// is absent.
func IsTierGated(err error) bool {
	if errors.Is(err, ErrTierGated) {
		return true
	}
	code, ok := StatusCodeOf(err)
	return ok && code == http.StatusForbidden
}

// resolve joins path onto the instance base URL, preserving any path prefix a
// self-managed instance is served under.
// ⚠ The URL is assembled as a string rather than through url.URL.Path.
//
// GitLab addresses a project by its URL-encoded full path — "group/project"
// becomes "group%2Fproject" — and that %2F must survive to the wire. Setting
// url.URL.Path and calling String() re-encodes the percent sign, turning
// %2F into %252F, and GitLab answers 404. A live scan hit exactly that: every
// C02 result came back "project not found" for a project that plainly exists.
//
// Building the string directly keeps the caller's encoding intact. The base
// URL is already validated in newClient, so there is nothing url.URL would
// normalise here that matters.
func (c *Client) resolve(path string, query url.Values) string {
	base := strings.TrimRight(c.baseURL.String(), "/")
	out := base + apiPrefix + "/" + strings.TrimLeft(path, "/")
	if query != nil && len(query) > 0 {
		out += "?" + query.Encode()
	}
	return out
}

// get performs one request and returns the body plus the response, leaving
// status interpretation to the caller.
func (c *Client) get(ctx context.Context, rawURL string) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview := string(body)
		if len(preview) > maxErrorBodyPreview {
			preview = preview[:maxErrorBodyPreview] + "…"
		}
		return nil, resp, &StatusError{StatusCode: resp.StatusCode, Endpoint: req.URL.Path, Body: preview}
	}
	return body, resp, nil
}

// GetJSON fetches one resource and decodes it into out.
func GetJSON[T any](ctx context.Context, c *Client, path string, query url.Values, out *T) error {
	body, _, err := c.get(ctx, c.resolve(path, query))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("collect/gitlab: decode %s: %w", path, err)
	}
	return nil
}

// GetJSONPaged fetches every page of a list endpoint and returns the
// concatenation.
//
// This is the function that makes GitLab evidence trustworthy. GitLab pages
// list endpoints by default, so a caller that fetched once would attest on
// the first 100 repositories of a larger group and present it as complete —
// silently, with no error and a clean-looking pack. Following X-Next-Page to
// exhaustion is therefore not an optimisation, it is a correctness
// requirement.
//
// A server that never stops advertising a next page fails at maxPages rather
// than looping, and the error says which endpoint did it.
func GetJSONPaged[T any](ctx context.Context, c *Client, path string, query url.Values) ([]T, error) {
	if query == nil {
		query = url.Values{}
	}
	query.Set("per_page", strconv.Itoa(perPage))

	var all []T
	page := 1
	for {
		if page > maxPages {
			return nil, fmt.Errorf("collect/gitlab: %s still advertised a next page after %d pages; refusing to keep paging", path, maxPages)
		}
		query.Set("page", strconv.Itoa(page))

		body, resp, err := c.get(ctx, c.resolve(path, query))
		if err != nil {
			return nil, err
		}
		var batch []T
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, fmt.Errorf("collect/gitlab: decode %s page %d: %w", path, page, err)
		}
		all = append(all, batch...)

		next := strings.TrimSpace(resp.Header.Get("X-Next-Page"))
		if next == "" {
			return all, nil
		}
		n, convErr := strconv.Atoi(next)
		if convErr != nil || n <= page {
			// A next-page header that does not advance is a server bug or a
			// proxy rewriting headers. Stop rather than loop, and return
			// what was actually read rather than pretending it is complete.
			return all, fmt.Errorf("collect/gitlab: %s returned X-Next-Page=%q after page %d; stopping with a partial result", path, next, page)
		}
		page = n
	}
}
