package azuredevops

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/sioakim/attestward/internal/collect/azuredevops/adofixture"
)

// demoItem is a minimal decode target used only by these tests — GetJSON is
// generic, so any collector-defined struct works the same way.
type demoItem struct {
	Name string `json:"name"`
}

// capturingTransport wraps a RoundTripper and records the continuationToken
// query parameter (empty string if absent) seen on every request that
// reaches it — used to prove GetJSON echoes a page's continuation signal
// back as the *next* request's query parameter, not just that pagination
// eventually stops.
type capturingTransport struct {
	base   http.RoundTripper
	tokens []string
}

func (c *capturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.tokens = append(c.tokens, req.URL.Query().Get(continuationTokenParam))
	return c.base.RoundTrip(req)
}

// newTestClient builds a Client whose transport chain terminates in base
// instead of a real network round-tripper, reusing the package's actual
// auth+provenance+rate-limit layers unmodified — the same pattern
// internal/collect/github/client_test.go's newTestClient uses.
func newTestClient(t *testing.T, org, pat string, base http.RoundTripper) *Client {
	t.Helper()
	prov := newProvenanceTransport(pat, base)
	rl := newRateLimitTransport(prov)
	return &Client{org: org, prov: prov, httpClient: &http.Client{Transport: rl}}
}

// TestNewClientForTest_UsableThroughGetJSON proves the exported
// cross-package testing seam actually wires the same transport chain
// newTestClient does — this package's own tests could keep using the
// unexported constructor, but external packages (pipelinehistory and
// later collector packages) need NewClientForTest itself proven, not just
// its unexported twin.
func TestNewClientForTest_UsableThroughGetJSON(t *testing.T) {
	fx := adofixture.New().Set("GET", HostCore, "/org/_apis/projects", adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"count": 1, "value": []map[string]any{{"name": "repo-a"}}},
	})
	client := NewClientForTest("org", "ado-test-pat", fx)

	var items []demoItem
	if err := GetJSON(context.Background(), client, HostCore, "/org/_apis/projects", nil, &items); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if len(items) != 1 || items[0].Name != "repo-a" {
		t.Errorf("items = %+v, want [{repo-a}]", items)
	}
	if client.Org() != "org" {
		t.Errorf("Org() = %q, want %q", client.Org(), "org")
	}
	if len(client.Provenance()) != 1 {
		t.Errorf("len(Provenance()) = %d, want 1", len(client.Provenance()))
	}
}

func TestGetJSON_DecodesSinglePage(t *testing.T) {
	fx := adofixture.New().Set("GET", HostCore, "/org/_apis/projects", adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 2,
			"value": []map[string]any{{"name": "repo-a"}, {"name": "repo-b"}},
		},
	})
	client := newTestClient(t, "org", "ado-test-pat", fx)

	var items []demoItem
	if err := GetJSON(context.Background(), client, HostCore, "/org/_apis/projects", url.Values{"api-version": {"7.1"}}, &items); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if len(items) != 2 || items[0].Name != "repo-a" || items[1].Name != "repo-b" {
		t.Errorf("items = %+v, want [{repo-a} {repo-b}]", items)
	}
	if len(fx.Calls()) != 1 {
		t.Errorf("len(Calls()) = %d, want 1 (single page, no continuation signal in the response)", len(fx.Calls()))
	}
}

// TestGetJSON_PaginatesViaHeaderContinuationTokenToExhaustion covers the
// X-MS-ContinuationToken response-header pagination mechanism used by every
// documented list host this project has verified: both dev.azure.com core
// APIs and vssps.dev.azure.com's Graph API (e.g. its Users List endpoint)
// signal the next page this way, never via a body field — exercised here
// against HostGraph specifically, since that's the family a body-token
// mechanism was previously (incorrectly) attributed to.
func TestGetJSON_PaginatesViaHeaderContinuationTokenToExhaustion(t *testing.T) {
	fx := adofixture.New().SetSequence("GET", HostGraph, "/org/_apis/graph/users",
		adofixture.Response{
			Status:  http.StatusOK,
			Headers: map[string]string{"X-MS-ContinuationToken": "page-2-token"},
			Body:    map[string]any{"count": 1, "value": []map[string]any{{"name": "user-a"}}},
		},
		adofixture.Response{
			Status:  http.StatusOK,
			Headers: map[string]string{"X-MS-ContinuationToken": "page-3-token"},
			Body:    map[string]any{"count": 1, "value": []map[string]any{{"name": "user-b"}}},
		},
		adofixture.Response{
			Status: http.StatusOK,
			Body:   map[string]any{"count": 1, "value": []map[string]any{{"name": "user-c"}}},
		},
	)
	capture := &capturingTransport{base: fx}
	client := newTestClient(t, "org", "ado-test-pat", capture)

	var items []demoItem
	if err := GetJSON(context.Background(), client, HostGraph, "/org/_apis/graph/users", nil, &items); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}

	wantNames := []string{"user-a", "user-b", "user-c"}
	assertItemNames(t, items, wantNames)

	wantTokens := []string{"", "page-2-token", "page-3-token"}
	assertCapturedTokens(t, capture.tokens, wantTokens)
}

// TestGetJSON_PaginatesViaBodyContinuationTokenAsDefensiveFallback exercises
// GetJSON's defensive fallback branch — a continuationToken field in the
// response body — which exists because no currently verified ADO list host
// actually uses it (see page's doc comment), not because it models any
// specific real endpoint family. In particular this is not a stand-in for
// the audit-service family: audit's response envelope isn't even
// {"count","value"} shaped, so it will need its own decode logic (S8,
// issue #154) rather than reusing GetJSON at all.
func TestGetJSON_PaginatesViaBodyContinuationTokenAsDefensiveFallback(t *testing.T) {
	fx := adofixture.New().SetSequence("GET", HostCore, "/org/_apis/some-hypothetical-endpoint",
		adofixture.Response{
			Status: http.StatusOK,
			Body: map[string]any{
				"count":             1,
				"value":             []map[string]any{{"name": "item-a"}},
				"continuationToken": "body-page-2",
			},
		},
		adofixture.Response{
			Status: http.StatusOK,
			Body:   map[string]any{"count": 1, "value": []map[string]any{{"name": "item-b"}}},
		},
	)
	capture := &capturingTransport{base: fx}
	client := newTestClient(t, "org", "ado-test-pat", capture)

	var items []demoItem
	if err := GetJSON(context.Background(), client, HostCore, "/org/_apis/some-hypothetical-endpoint", nil, &items); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}

	wantNames := []string{"item-a", "item-b"}
	assertItemNames(t, items, wantNames)

	wantTokens := []string{"", "body-page-2"}
	assertCapturedTokens(t, capture.tokens, wantTokens)
}

// TestGetJSON_SameContinuationTokenTwiceIsAnError pins the stuck-loop
// guard: nothing upstream of GetJSON enforces a request timeout, so a
// server that echoes back the same continuation token forever (ADO's own
// Audit Log Query sample shows a non-empty token can appear alongside
// hasMore:false — a non-empty token is not on its own proof of progress)
// must not be allowed to hang a scan indefinitely.
func TestGetJSON_SameContinuationTokenTwiceIsAnError(t *testing.T) {
	fx := adofixture.New().Set("GET", HostCore, "/org/_apis/projects", adofixture.Response{
		Status:  http.StatusOK,
		Headers: map[string]string{"X-MS-ContinuationToken": "stuck-token"},
		Body:    map[string]any{"count": 1, "value": []map[string]any{{"name": "repo-a"}}},
	})
	client := newTestClient(t, "org", "ado-test-pat", fx)

	var items []demoItem
	err := GetJSON(context.Background(), client, HostCore, "/org/_apis/projects", nil, &items)
	if err == nil {
		t.Fatal("GetJSON() = nil error, want an error when the server echoes the same continuation token twice in a row")
	}
	if !strings.Contains(err.Error(), "stuck-token") {
		t.Errorf("error = %v, want it to name the repeated token", err)
	}
	if len(items) != 0 {
		t.Errorf("items = %+v, want empty — a detected stuck loop must not leave a partial result", items)
	}
}

// TestGetJSON_ExceedingMaxPagesIsAnError pins the hard page-cap backstop: a
// server that keeps emitting a fresh (never-repeated) continuation token
// forever would defeat the same-token guard above, so a generous absolute
// ceiling exists too, erroring rather than silently truncating the result.
func TestGetJSON_ExceedingMaxPagesIsAnError(t *testing.T) {
	responses := make([]adofixture.Response, maxPages)
	for i := range responses {
		responses[i] = adofixture.Response{
			Status:  http.StatusOK,
			Headers: map[string]string{"X-MS-ContinuationToken": fmt.Sprintf("token-%d", i)},
			Body:    map[string]any{"count": 1, "value": []map[string]any{{"name": "repo"}}},
		}
	}
	fx := adofixture.New().SetSequence("GET", HostCore, "/org/_apis/projects", responses...)
	client := newTestClient(t, "org", "ado-test-pat", fx)

	var items []demoItem
	err := GetJSON(context.Background(), client, HostCore, "/org/_apis/projects", nil, &items)
	if err == nil {
		t.Fatal("GetJSON() = nil error, want an error once the page cap is exceeded")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d", maxPages)) {
		t.Errorf("error = %v, want it to mention the page cap (%d)", err, maxPages)
	}
	if got := len(fx.Calls()); got != maxPages {
		t.Errorf("len(Calls()) = %d, want %d (stops right at the cap, doesn't make one more request first)", got, maxPages)
	}
}

// TestGetJSON_FailureOnLaterPageLeavesOutUntouched extends the no-partial-
// writes contract already covered for a first-request failure: a failure on
// a *later* page (after page 1 already decoded successfully) must not leak
// page 1's results into *out either.
func TestGetJSON_FailureOnLaterPageLeavesOutUntouched(t *testing.T) {
	fx := adofixture.New().SetSequence("GET", HostCore, "/org/_apis/projects",
		adofixture.Response{
			Status:  http.StatusOK,
			Headers: map[string]string{"X-MS-ContinuationToken": "page-2-token"},
			Body:    map[string]any{"count": 1, "value": []map[string]any{{"name": "repo-a"}}},
		},
		adofixture.Response{
			Status: http.StatusInternalServerError,
			Body:   map[string]any{"message": "TF400xxx: something went wrong on page 2"},
		},
	)
	client := newTestClient(t, "org", "ado-test-pat", fx)

	var items []demoItem
	err := GetJSON(context.Background(), client, HostCore, "/org/_apis/projects", nil, &items)
	if err == nil {
		t.Fatal("GetJSON() = nil error, want an error when a later page fails")
	}
	if len(items) != 0 {
		t.Errorf("items = %+v, want empty — page 1's results must not leak out under a page-2 failure", items)
	}
}

func TestGetJSONObject_DecodesSingleObject(t *testing.T) {
	fx := adofixture.New().Set("GET", HostAdvSec, "/org/project/_apis/management/enablement", adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"advSecEnabled": true},
	})
	client := newTestClient(t, "org", "ado-test-pat", fx)

	var got struct {
		AdvSecEnabled bool `json:"advSecEnabled"`
	}
	if err := GetJSONObject(context.Background(), client, HostAdvSec, "/org/project/_apis/management/enablement", nil, &got); err != nil {
		t.Fatalf("GetJSONObject: %v", err)
	}
	if !got.AdvSecEnabled {
		t.Error("AdvSecEnabled = false, want true")
	}
}

func TestGetJSONObject_NonSuccessStatusReturnsStatusError(t *testing.T) {
	fx := adofixture.New().Set("GET", HostAdvSec, "/org/project/_apis/management/enablement", adofixture.Response{
		Status: http.StatusForbidden,
		Body:   map[string]any{"message": "TF400xxx: advsec is not enabled for this org"},
	})
	client := newTestClient(t, "org", "ado-test-pat", fx)

	var got struct {
		AdvSecEnabled bool `json:"advSecEnabled"`
	}
	err := GetJSONObject(context.Background(), client, HostAdvSec, "/org/project/_apis/management/enablement", nil, &got)
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("error = %v, want it to be/wrap a *StatusError", err)
	}
	if statusErr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", statusErr.StatusCode)
	}
	if !IsAdvSecGated(statusErr.StatusCode) {
		t.Error("IsAdvSecGated(StatusCode) = false, want true — this is exactly the predicate collectors apply to this error")
	}
}

func TestPreviewBody_TruncatesRuneSafely(t *testing.T) {
	// Pad up to one byte short of the cap with ASCII, then place a
	// multi-byte rune ("é", 2 bytes in UTF-8) straddling the truncation
	// boundary — a naive byte-offset cut would split it and produce
	// invalid UTF-8.
	pad := strings.Repeat("a", maxErrorBodyPreview-1)
	body := []byte(pad + "é" + strings.Repeat("b", 50))

	got := previewBody(body)
	if !utf8.ValidString(got) {
		t.Fatalf("previewBody result is not valid UTF-8: %q", got)
	}
	if !strings.HasPrefix(got, pad) {
		t.Error("previewBody dropped or altered the leading ASCII padding")
	}
}

func TestGetJSON_NonSuccessStatusReturnsStatusErrorWithoutLeakingPAT(t *testing.T) {
	fx := adofixture.New().Set("GET", HostCore, "/org/_apis/projects", adofixture.Response{
		Status: http.StatusInternalServerError,
		Body:   map[string]any{"message": "TF400xxx: something went wrong"},
	})
	const pat = "ado-test-pat-should-never-leak-into-an-error"
	client := newTestClient(t, "org", pat, fx)

	var items []demoItem
	err := GetJSON(context.Background(), client, HostCore, "/org/_apis/projects", nil, &items)
	if err == nil {
		t.Fatal("GetJSON() = nil error, want a *StatusError for a 500 response")
	}
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("error = %v (%T), want it to be/wrap a *StatusError", err, err)
	}
	if statusErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want 500", statusErr.StatusCode)
	}
	if statusErr.Endpoint != "dev.azure.com/org/_apis/projects" {
		t.Errorf("Endpoint = %q, want host-qualified path, no query string", statusErr.Endpoint)
	}
	if statusErr.Body != "TF400xxx: something went wrong" {
		t.Errorf("Body = %q, want the parsed ADO error envelope's message field, not the raw JSON body", statusErr.Body)
	}
	if strings.Contains(err.Error(), pat) {
		t.Error("PAT leaked into the StatusError's message")
	}
	if len(items) != 0 {
		t.Errorf("items = %+v, want empty (a failed page must not leave a partial result in *out)", items)
	}
}

// TestClient_RateLimitedRetriesEachRecordProvenanceThroughGetJSON is the
// client-level composition test: a request issued through GetJSON must flow
// rateLimitTransport -> provenanceTransport -> the fixture (the same order
// NewClient wires them, canonical for this package), and every retry
// attempt — not just the final one — must produce its own provenance entry.
func TestClient_RateLimitedRetriesEachRecordProvenanceThroughGetJSON(t *testing.T) {
	fx := adofixture.New().SetSequence("GET", HostCore, "/org/_apis/projects",
		adofixture.Response{Status: http.StatusTooManyRequests, Headers: map[string]string{"Retry-After": "1"}},
		adofixture.Response{Status: http.StatusTooManyRequests, Headers: map[string]string{"Retry-After": "1"}},
		adofixture.Response{Status: http.StatusOK, Body: map[string]any{"count": 1, "value": []map[string]any{{"name": "repo-a"}}}},
	)

	prov := newProvenanceTransport("ado-test-pat", fx)
	rl := newRateLimitTransport(prov)
	rl.sleep = func(time.Duration) {} // this test asserts composition and provenance, not timing
	client := &Client{org: "org", prov: prov, httpClient: &http.Client{Transport: rl}}

	var items []demoItem
	if err := GetJSON(context.Background(), client, HostCore, "/org/_apis/projects", nil, &items); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if len(items) != 1 || items[0].Name != "repo-a" {
		t.Errorf("items = %+v, want [{repo-a}] (eventual success after retries)", items)
	}

	entries := client.Provenance()
	if len(entries) != 3 {
		t.Fatalf("len(Provenance()) = %d, want 3 (one entry per attempt — every 429 retry is a distinct call through provenanceTransport)", len(entries))
	}
	wantStatuses := []int{http.StatusTooManyRequests, http.StatusTooManyRequests, http.StatusOK}
	for i, e := range entries {
		if e.HTTPStatus != wantStatuses[i] {
			t.Errorf("entries[%d].HTTPStatus = %d, want %d", i, e.HTTPStatus, wantStatuses[i])
		}
		if e.Endpoint != "dev.azure.com/org/_apis/projects" {
			t.Errorf("entries[%d].Endpoint = %q, want host-qualified path", i, e.Endpoint)
		}
	}
}

func assertItemNames(t *testing.T, items []demoItem, want []string) {
	t.Helper()
	if len(items) != len(want) {
		t.Fatalf("len(items) = %d, want %d (%+v)", len(items), len(want), items)
	}
	for i, name := range want {
		if items[i].Name != name {
			t.Errorf("items[%d].Name = %q, want %q", i, items[i].Name, name)
		}
	}
}

func assertCapturedTokens(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("len(captured tokens) = %d, want %d (%v)", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("captured token[%d] = %q, want %q (must echo the prior page's continuation signal back as the query parameter)", i, got[i], w)
		}
	}
}
