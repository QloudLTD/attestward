package gogs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"gitlab.com/sioakeim/attestward/internal/collect/gogs/gogsfixture"
)

// TestProvenanceTransport_RejectsWriteMethods is ADR-0004 ("read-only,
// forever") enforced structurally rather than by code review. It matters
// more on this platform than on the hosted ones: the same Gogs token that
// reads a repo can create repos, issues and webhooks, and the API is small
// enough that a future collector could reach a write endpoint by a
// one-character mistake. The guard must fire before auth injection and
// before the network call, so a rejected request cannot even carry the
// token off the machine.
func TestProvenanceTransport_RejectsWriteMethods(t *testing.T) {
	fx := gogsfixture.New()
	tr := newProvenanceTransport("secret-token", fx)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req, err := http.NewRequest(method, "https://gogs.example.com/api/v1/repos/o/r", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			resp, err := tr.RoundTrip(req)
			if err == nil {
				t.Fatalf("RoundTrip(%s) = nil error, want a refusal", method)
			}
			if resp != nil {
				t.Errorf("RoundTrip(%s) returned a response alongside the refusal", method)
			}
			if !errors.Is(err, ErrWriteMethodRejected) {
				t.Errorf("error = %v, want it to wrap ErrWriteMethodRejected", err)
			}
		})
	}

	if calls := fx.Calls(); len(calls) != 0 {
		t.Errorf("a rejected write reached the underlying transport: %v", calls)
	}
	if len(tr.Provenance()) != 0 {
		t.Error("a rejected write recorded a provenance entry, which would claim a call that never happened")
	}
}

// TestProvenanceTransport_RecordsPathOnlyAndNeverTheToken pins what does and does not reach
// an evidence pack. The host is omitted because a self-hosted instance is
// routinely on a private address, and a pack is a document handed to a
// customer or a regulator; the query string is omitted so a secret
// accidentally placed in a parameter cannot leak through provenance. Both
// omissions are load-bearing, not incidental — a future refactor that
// "helpfully" recorded req.URL.String() would break both at once.
func TestProvenanceTransport_RecordsPathOnlyAndNeverTheToken(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", "/api/v1/repos/o/r", gogsfixture.Response{Status: 200, Body: map[string]any{"name": "r"}})
	tr := newProvenanceTransport("secret-token", fx)

	u := "https://gogs.internal.example.com/api/v1/repos/o/r?token=leaked&page=2"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	prov := tr.Provenance()
	if len(prov) != 1 {
		t.Fatalf("recorded %d provenance entries, want 1", len(prov))
	}
	got := prov[0]
	if got.Endpoint != "/api/v1/repos/o/r" {
		t.Errorf("Endpoint = %q, want the path only (no host, no query string)", got.Endpoint)
	}
	if got.HTTPStatus != 200 || got.Method != http.MethodGet {
		t.Errorf("Method/HTTPStatus = %s/%d, want GET/200", got.Method, got.HTTPStatus)
	}
	if got.ResponseSHA256 == "" {
		t.Error("ResponseSHA256 is empty, so the recorded call proves nothing about what was returned")
	}
	if got.Timestamp.IsZero() || got.Timestamp.Location() != time.UTC {
		t.Errorf("Timestamp = %v, want a UTC instant", got.Timestamp)
	}
}

// TestProvenanceTransport_SendsGogsTokenSchemeAndUserAgent pins the auth header shape.
// Gogs ignores a Bearer header rather than rejecting it, so getting this
// wrong does not surface as a 401 — it surfaces as a 404 on a private
// repo, i.e. as "this repo does not exist", which a collector could
// reasonably record as an observation about the customer's estate.
func TestProvenanceTransport_SendsGogsTokenSchemeAndUserAgent(t *testing.T) {
	var gotAuth, gotUA string
	spy := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotAuth = req.Header.Get("Authorization")
		gotUA = req.Header.Get("User-Agent")
		return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{}, Request: req}, nil
	})
	tr := newProvenanceTransport("secret-token", spy)

	req, _ := http.NewRequest(http.MethodGet, "https://gogs.example.com/api/v1/user", nil)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	if gotAuth != "token secret-token" {
		t.Errorf("Authorization = %q, want Gogs' own \"token <t>\" scheme", gotAuth)
	}
	if gotUA != userAgent {
		t.Errorf("User-Agent = %q, want %q — a default library agent is 403'd by a Cloudflare browser-integrity check before it reaches Gogs", gotUA, userAgent)
	}
}

// TestRetryTransport_RetriesServerErrorsNotClientErrors pins the retry
// policy against the two ways it could be wrong: giving up on a transient
// 5xx (losing a scan to a blip) and hammering a settled 4xx (turning a
// fast, honest failure into a slow one).
func TestRetryTransport_RetriesServerErrorsNotClientErrors(t *testing.T) {
	t.Run("5xx then success", func(t *testing.T) {
		fx := gogsfixture.New()
		fx.SetSequence("GET", "/api/v1/user",
			gogsfixture.Response{Status: 502, Body: map[string]any{"message": "bad gateway"}},
			gogsfixture.Response{Status: 200, Body: map[string]any{"username": "someone"}},
		)
		tr := newRetryTransport(fx)
		tr.after = immediately

		req, _ := http.NewRequest(http.MethodGet, "https://gogs.example.com/api/v1/user", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("status = %d, want the retry to have reached the 200", resp.StatusCode)
		}
		if got := len(fx.Calls()); got != 2 {
			t.Errorf("made %d calls, want 2 (one failure, one retry)", got)
		}
	})

	t.Run("4xx is never retried", func(t *testing.T) {
		fx := gogsfixture.New()
		fx.Set("GET", "/api/v1/user", gogsfixture.Response{Status: 404, Body: map[string]any{"message": "not found"}})
		tr := newRetryTransport(fx)
		tr.after = func(time.Duration) <-chan time.Time { t.Error("waited before retrying a 4xx"); return immediately(0) }

		req, _ := http.NewRequest(http.MethodGet, "https://gogs.example.com/api/v1/user", nil)
		if _, err := tr.RoundTrip(req); err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if got := len(fx.Calls()); got != 1 {
			t.Errorf("made %d calls, want exactly 1 — a 404 is a settled answer", got)
		}
	})

	t.Run("persistent 5xx gives up and returns the failure", func(t *testing.T) {
		fx := gogsfixture.New()
		fx.Set("GET", "/api/v1/user", gogsfixture.Response{Status: 500, Body: map[string]any{"message": "boom"}})
		tr := newRetryTransport(fx)
		tr.after = immediately

		req, _ := http.NewRequest(http.MethodGet, "https://gogs.example.com/api/v1/user", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if resp.StatusCode != 500 {
			t.Errorf("status = %d, want the exhausted retry to surface the real 500 rather than an invented success", resp.StatusCode)
		}
		if got := len(fx.Calls()); got != maxRetries+1 {
			t.Errorf("made %d calls, want %d (initial + %d retries)", got, maxRetries+1, maxRetries)
		}
	})
}

// TestBackoffGrowsAndStaysBounded keeps the jitter from silently becoming
// the whole delay, and the shift from overflowing into a negative duration
// if maxRetries ever grows.
func TestBackoffGrowsAndStaysBounded(t *testing.T) {
	var prev time.Duration
	for attempt := 0; attempt <= maxRetries; attempt++ {
		got := backoff(attempt)
		if got <= 0 {
			t.Fatalf("backoff(%d) = %v, want a positive duration", attempt, got)
		}
		if got <= prev {
			t.Errorf("backoff(%d) = %v, not greater than backoff(%d) = %v", attempt, got, attempt-1, prev)
		}
		prev = got
	}
	if prev > 30*time.Second {
		t.Errorf("backoff grew to %v, longer than any scan should wait on one call", prev)
	}
}

// TestClient_JoinsSuburlBase proves the base URL's path prefix survives
// into the request. Gogs genuinely supports being served under a suburl,
// and the failure mode of getting this wrong is silent: requests go to a
// path that may well exist on the same host, so the scan appears to work
// while describing something other than the intended instance.
func TestClient_JoinsSuburlBase(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", "/gogs/api/v1/repos/o/r", gogsfixture.Response{Status: 200, Body: map[string]any{"name": "r"}})

	c, err := NewClientForTest("https://example.com/gogs", "t", fx)
	if err != nil {
		t.Fatalf("NewClientForTest: %v", err)
	}
	var out map[string]any
	if err := GetJSON(context.Background(), c, "/repos/o/r", nil, &out); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if out["name"] != "r" {
		t.Errorf("decoded %v, want the fixture body", out)
	}
}

// TestNewClient_RejectsUnusableBaseURL: there is no default Gogs instance
// to fall back to, so an unusable base URL must fail loudly at construction
// rather than produce a scan attributed to the wrong subject.
func TestNewClient_RejectsUnusableBaseURL(t *testing.T) {
	// Every one of these must be refused, and — for the ones carrying a
	// secret — refused without quoting it back. NewClient is exported and
	// has direct library callers (attestward-cloud is one) that never pass
	// through the CLI's own validation, so this layer cannot lean on it.
	// Note "admin:hunter2@host" parses with Scheme "admin" and User nil,
	// so the credential rule never sees it: it is the scheme rule that
	// must also refrain from echoing.
	for _, raw := range []string{
		"", "gogs.example.com", "https://", "://nope",
		"https://admin:hunter2@gogs.example.com:notaport",
		"admin:hunter2@gogs.example.com",
		"ftp://admin:hunter2@gogs.example.com",
	} {
		_, err := NewClient(raw, "t")
		if err == nil {
			t.Errorf("NewClient(%q) = nil error, want a refusal", raw)
			continue
		}
		for _, secret := range []string{"hunter2", "notaport"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("NewClient(%q) echoed %q back in its error: %v", raw, secret, err)
			}
		}
	}
	if _, err := NewClient("https://gogs.example.com/", "t"); err != nil {
		t.Errorf("NewClient with a trailing slash = %v, want it accepted", err)
	}
}

// TestGetJSON_NonSuccessBecomesStatusError pins that a caller can tell 404
// ("no such repo") from 501-and-friends by status code rather than by
// string-matching a message — the distinction every Gogs collector has to
// make, since this API answers 404 both for a missing resource and for an
// endpoint the version does not implement.
func TestGetJSON_NonSuccessBecomesStatusError(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", "/api/v1/repos/o/missing", gogsfixture.Response{
		Status: 404,
		Body:   map[string]any{"message": "repository does not exist"},
	})

	c, err := NewClientForTest("https://gogs.example.com", "t", fx)
	if err != nil {
		t.Fatalf("NewClientForTest: %v", err)
	}
	var out map[string]any
	err = GetJSON(context.Background(), c, "/repos/o/missing", nil, &out)
	if err == nil {
		t.Fatal("GetJSON on a 404 = nil error")
	}
	code, ok := StatusCodeOf(err)
	if !ok || code != 404 {
		t.Fatalf("StatusCodeOf(%v) = %d, %v; want 404, true", err, code, ok)
	}
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error %v is not a *StatusError, so a collector could not branch on its status", err)
	}
	if se.Body != "repository does not exist" {
		t.Errorf("StatusError.Body = %q, want Gogs' own message rather than the raw envelope", se.Body)
	}
}

// TestGetRaw_ReturnsBytesAndDistinguishesMissingFromEmpty is the property
// C10 vdp depends on: an empty SECURITY.md and an absent one must not look
// the same to a collector, or "no policy" and "an empty policy file" would
// produce the same evidence.
func TestGetRaw_ReturnsBytesAndDistinguishesMissingFromEmpty(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", "/api/v1/repos/o/r/raw/main/SECURITY.md", gogsfixture.Response{Status: 200, RawBody: []byte("# Security Policy\n")})
	fx.Set("GET", "/api/v1/repos/o/r/raw/main/EMPTY.md", gogsfixture.Response{Status: 200, RawBody: []byte{}})
	fx.Set("GET", "/api/v1/repos/o/r/raw/main/GONE.md", gogsfixture.Response{Status: 404, Body: map[string]any{"message": "object does not exist"}})

	c, err := NewClientForTest("https://gogs.example.com", "t", fx)
	if err != nil {
		t.Fatalf("NewClientForTest: %v", err)
	}
	ctx := context.Background()

	got, err := c.GetRaw(ctx, "/repos/o/r/raw/main/SECURITY.md")
	if err != nil || string(got) != "# Security Policy\n" {
		t.Fatalf("GetRaw(present) = %q, %v", got, err)
	}

	got, err = c.GetRaw(ctx, "/repos/o/r/raw/main/EMPTY.md")
	if err != nil || len(got) != 0 {
		t.Fatalf("GetRaw(empty) = %q, %v; want empty content and no error", got, err)
	}

	if _, err := c.GetRaw(ctx, "/repos/o/r/raw/main/GONE.md"); err == nil {
		t.Fatal("GetRaw(missing) = nil error, so an absent file is indistinguishable from an empty one")
	}
}

// TestClient_ProvenanceCountsEveryAttempt: a retried call is two real
// requests, and a pack that recorded one would understate what the scan
// actually did to the instance.
func TestClient_ProvenanceCountsEveryAttempt(t *testing.T) {
	fx := gogsfixture.New()
	fx.SetSequence("GET", "/api/v1/user",
		gogsfixture.Response{Status: 503, Body: map[string]any{"message": "unavailable"}},
		gogsfixture.Response{Status: 200, Body: map[string]any{"username": "someone"}},
	)
	c, err := NewClientForTest("https://gogs.example.com", "t", fx)
	if err != nil {
		t.Fatalf("NewClientForTest: %v", err)
	}
	// NewClientForTest already replaces the backoff timer — see its doc
	// comment. Asserting the chain's shape here keeps that seam honest: if
	// the retry layer were ever dropped from the test constructor, this
	// test would still pass on provenance count while silently no longer
	// exercising a retry at all.
	if _, ok := c.httpClient.Transport.(*retryTransport); !ok {
		t.Fatalf("client transport is %T, want *retryTransport", c.httpClient.Transport)
	}

	var out map[string]any
	if err := GetJSON(context.Background(), c, "/user", url.Values{}, &out); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if got := len(c.Provenance()); got != 2 {
		t.Errorf("recorded %d provenance entries, want 2 — each attempt is a distinct real call", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestClient_NeverFollowsRedirects is the regression test for the most
// serious defect this package has had. Before the CheckRedirect policy
// existed, a Gogs instance answering 302 -> http://attacker/ handed that
// third party a freshly minted "Authorization: token <t>" header — because
// auth is injected inside the transport, below the redirect machinery,
// where Go's cross-domain header stripping cannot see it — and GetJSON
// then decoded the attacker's body and returned it as the API's answer with
// a nil error. Nothing in the resulting pack could have revealed it, since
// provenance records the path only.
//
// Both halves are asserted: the token must not leave, and the attacker's
// body must never become the answer.
func TestClient_NeverFollowsRedirects(t *testing.T) {
	// Guarded: the handler runs on the server's goroutine, and -race would
	// otherwise flag exactly the failing case this test exists to catch.
	var mu sync.Mutex
	var thirdPartyAuth string
	var thirdPartyHits int
	thirdParty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		thirdPartyHits++
		thirdPartyAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"pwned"}`))
	}))
	defer thirdParty.Close()

	instance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, thirdParty.URL+"/evil", http.StatusFound)
	}))
	defer instance.Close()

	c, err := NewClient(instance.URL, "super-secret-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	var out map[string]any
	err = GetJSON(context.Background(), c, "/repos/o/r", nil, &out)
	if err == nil {
		t.Fatal("GetJSON followed a redirect and returned no error")
	}
	mu.Lock()
	defer mu.Unlock()
	if thirdPartyHits != 0 {
		t.Errorf("the redirect target was contacted %d times, want 0", thirdPartyHits)
	}
	if thirdPartyAuth != "" {
		t.Errorf("the token was sent to the redirect target: %q", thirdPartyAuth)
	}
	if out["name"] == "pwned" {
		t.Error("the redirect target's body was returned as the API answer")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("error = %v, want it to explain that redirects are not followed", err)
	}
}

// TestNewClient_RejectsCredentialsInBaseURL: url.URL.String() prints a
// password verbatim, and BaseURL() is documented for collectors to record
// as a Fact — so accepting userinfo would bake the password into a signed
// evidence pack. Rejecting is right rather than stripping: basic auth
// cannot work against this API at all, so a user who tried it needs to be
// told, not silently half-helped.
func TestNewClient_RejectsCredentialsInBaseURL(t *testing.T) {
	for _, raw := range []string{
		"https://user:hunter2@gogs.example.com",
		"https://user@gogs.example.com",
	} {
		c, err := NewClient(raw, "t")
		if err == nil {
			t.Errorf("NewClient(%q) = nil error; BaseURL() would be %q", raw, c.BaseURL())
			continue
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("the error message itself leaks the password: %v", err)
		}
	}
}

// TestValidatePath_RejectsTraversalAndMissingSlash: Go does not normalize
// dot segments, but reverse proxies do — so a ".." reaching the wire in a
// caller-supplied repo, ref or file name can climb out of /api/v1 into the
// Gogs web routes on the way through a proxy. gogsfixture keys on the same
// un-normalized path, so no collector test would ever notice.
func TestValidatePath_RejectsTraversalAndMissingSlash(t *testing.T) {
	bad := []string{
		"/repos/../../admin/users",
		"/repos/o/../../../etc",
		"repos/o/r",
		"",
	}
	for _, path := range bad {
		if err := validatePath(path); err == nil {
			t.Errorf("validatePath(%q) = nil error, want a refusal", path)
		}
	}
	for _, path := range []string{"/repos/o/r", "/repos/o/r/contents/.github/SECURITY.md", "/user"} {
		if err := validatePath(path); err != nil {
			t.Errorf("validatePath(%q) = %v, want nil", path, err)
		}
	}
}

// TestFetch_RefusesWhenTheServerAdvertisesPagination pins the tripwire. The
// no-pagination decision rests on one endpoint on one Gogs version; if that
// ever changes, the failure mode is a silent partial result presented as
// complete, inside signed evidence. This makes it loud instead.
func TestFetch_RefusesWhenTheServerAdvertisesPagination(t *testing.T) {
	for _, h := range paginationHeaders {
		t.Run(h, func(t *testing.T) {
			fx := gogsfixture.New()
			fx.Set("GET", "/api/v1/user/repos", gogsfixture.Response{
				Status:  200,
				Headers: map[string]string{h: `<https://gogs.example.com/api/v1/user/repos?page=2>; rel="next"`},
				Body:    []map[string]any{{"name": "one"}},
			})
			c, err := NewClientForTest("https://gogs.example.com", "t", fx)
			if err != nil {
				t.Fatalf("NewClientForTest: %v", err)
			}
			var out []map[string]any
			err = GetJSON(context.Background(), c, "/user/repos", nil, &out)
			if err == nil {
				t.Fatalf("GetJSON returned nil error for a paginating response, silently treating page 1 as the whole set (%d items)", len(out))
			}
			if !strings.Contains(err.Error(), "paginate") {
				t.Errorf("error = %v, want it to name pagination as the cause", err)
			}
		})
	}
}

// TestRetryTransport_StopsSleepingOnceTheContextIsDone: without this, a
// cancelled scan burns the full backoff on every in-flight call before
// anyone notices, which reads as a hang rather than a cancellation.
func TestRetryTransport_StopsSleepingOnceTheContextIsDone(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", "/api/v1/user", gogsfixture.Response{Status: 500, Body: map[string]any{"message": "boom"}})

	waits := 0
	tr := newRetryTransport(fx)
	tr.after = func(d time.Duration) <-chan time.Time { waits++; return immediately(d) }

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://gogs.example.com/api/v1/user", nil)

	if _, err := tr.RoundTrip(req); err == nil {
		t.Error("RoundTrip = nil error for a cancelled context")
	}
	if waits != 0 {
		t.Errorf("waited %d times after the context was already done", waits)
	}
}

// TestProvenanceNeverContainsTheToken checks what the path-only test's name
// promises but only implied: no field of a recorded entry contains the
// token, whatever fields model.Provenance grows later.
func TestProvenanceNeverContainsTheToken(t *testing.T) {
	const token = "super-secret-token"
	fx := gogsfixture.New()
	fx.Set("GET", "/api/v1/user", gogsfixture.Response{Status: 200, Body: map[string]any{"username": "someone"}})
	c, err := NewClientForTest("https://gogs.example.com", token, fx)
	if err != nil {
		t.Fatalf("NewClientForTest: %v", err)
	}
	var out map[string]any
	if err := GetJSON(context.Background(), c, "/user", nil, &out); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}

	for _, entry := range c.Provenance() {
		rendered, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("marshal provenance: %v", err)
		}
		if strings.Contains(string(rendered), token) {
			t.Errorf("a provenance entry contains the token: %s", rendered)
		}
	}
}

// TestStatusErrorBodyIsBoundedOnBothPaths: StatusError.Body renders verbatim
// into a signed pack's Reason, and the JSON-envelope path used to bypass the
// bound that exists for exactly that reason.
func TestStatusErrorBodyIsBoundedOnBothPaths(t *testing.T) {
	huge := strings.Repeat("é", 2000) // multibyte, to also exercise rune-safe truncation

	envelope := newStatusError(http.MethodGet, "/api/v1/user", 500, mustJSON(t, map[string]any{"message": huge}))
	raw := newStatusError(http.MethodGet, "/api/v1/user", 500, []byte(huge))

	for name, e := range map[string]*StatusError{"envelope": envelope, "raw": raw} {
		if len(e.Body) > maxErrorBodyPreview+len("…(truncated)") {
			t.Errorf("%s path: Body is %d bytes, want it bounded near %d", name, len(e.Body), maxErrorBodyPreview)
		}
		if !utf8.ValidString(e.Body) {
			t.Errorf("%s path: Body is not valid UTF-8, so it would corrupt a signed pack", name)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestRedirectIsAStatusErrorWithABoundedLocation covers three things the
// re-review found in the redirect path: a collector must be able to branch
// on the status through StatusCodeOf rather than string-matching, the
// third-party Location must not reach a pack unbounded, and only genuine
// redirects should get redirect advice.
func TestRedirectIsAStatusErrorWithABoundedLocation(t *testing.T) {
	huge := "https://elsewhere.example.com/" + strings.Repeat("a", 3000)
	fx := gogsfixture.New()
	fx.Set("GET", "/api/v1/user", gogsfixture.Response{
		Status:  http.StatusFound,
		Headers: map[string]string{"Location": huge},
	})
	c, err := NewClientForTest("https://gogs.example.com", "t", fx)
	if err != nil {
		t.Fatalf("NewClientForTest: %v", err)
	}

	var out map[string]any
	err = GetJSON(context.Background(), c, "/user", nil, &out)
	if err == nil {
		t.Fatal("GetJSON = nil error for a 302")
	}
	code, ok := StatusCodeOf(err)
	if !ok || code != http.StatusFound {
		t.Fatalf("StatusCodeOf = %d, %v; want 302, true — a collector must branch on the status, not on message text", code, ok)
	}
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatal("redirect error is not a *StatusError")
	}

	// Asserted as a property rather than against a magic number: the
	// message's fixed explanation is long, so what matters is that the
	// body does not GROW with the attacker-controlled part. A 3000-byte
	// Location and a 6000-byte one must produce the same length.
	longer := huge + strings.Repeat("b", 3000)
	fx2 := gogsfixture.New()
	fx2.Set("GET", "/api/v1/user", gogsfixture.Response{
		Status:  http.StatusFound,
		Headers: map[string]string{"Location": longer},
	})
	c2, err := NewClientForTest("https://gogs.example.com", "t", fx2)
	if err != nil {
		t.Fatalf("NewClientForTest: %v", err)
	}
	err2 := GetJSON(context.Background(), c2, "/user", nil, &out)
	var se2 *StatusError
	if !errors.As(err2, &se2) {
		t.Fatal("second redirect error is not a *StatusError")
	}
	if len(se.Body) != len(se2.Body) {
		t.Errorf("body length tracks the Location length (%d vs %d bytes) — the third party controls how much reaches a signed pack", len(se.Body), len(se2.Body))
	}
	if !utf8.ValidString(se.Body) {
		t.Error("redirect error body is not valid UTF-8")
	}
}

// TestIsRedirect_OnlyRealRedirects: 304 and 305 share the 3xx range and are
// not redirects. Unreachable today (nothing sends conditional headers), but
// telling a user their 304 means they should have used https:// would send
// them somewhere useless.
func TestIsRedirect_OnlyRealRedirects(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		if !isRedirect(code) {
			t.Errorf("isRedirect(%d) = false, want true", code)
		}
	}
	for _, code := range []int{300, 304, 305, 200, 404} {
		if isRedirect(code) {
			t.Errorf("isRedirect(%d) = true, want false", code)
		}
	}
}

// TestRetryTransport_BackoffIsInterruptible pins the half-fix the re-review
// measured: checking the context before sleeping is not enough, because a
// deadline that expires *during* the wait went unnoticed until the next
// attempt. The wait itself must lose the race to cancellation.
func TestRetryTransport_BackoffIsInterruptible(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", "/api/v1/user", gogsfixture.Response{Status: 500, Body: map[string]any{"message": "boom"}})

	tr := newRetryTransport(fx)
	// A wait that never fires: only cancellation can end it, so the test
	// fails by hanging rather than passing for the wrong reason.
	tr.after = func(time.Duration) <-chan time.Time { return make(chan time.Time) }

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://gogs.example.com/api/v1/user", nil)

	done := make(chan error, 1)
	go func() {
		_, err := tr.RoundTrip(req)
		done <- err
	}()

	// Cancel while the transport is inside the backoff wait.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RoundTrip did not return after cancellation — the backoff wait is not interruptible")
	}
}
