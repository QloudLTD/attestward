package gitlab

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

// TestGetJSONPagedFollowsEveryPage pins the correctness property this package
// exists to guarantee: a list endpoint that pages must be read to exhaustion.
//
// This is not a completeness nicety. GitLab pages by default, so a client
// that read one page would attest on the first slice of a group and emit a
// pack that looks clean and complete. There would be no error, no warning and
// nothing in the evidence to reveal it — the single most dangerous shape of
// bug for a tool whose output gets signed.
func TestGetJSONPagedFollowsEveryPage(t *testing.T) {
	const total = 250 // 3 pages at per_page=100
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		start := (page - 1) * perPage
		end := start + perPage
		if end > total {
			end = total
		}
		if start < total && page < 3 {
			w.Header().Set("X-Next-Page", strconv.Itoa(page+1))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, "[")
		for i := start; i < end; i++ {
			if i > start {
				_, _ = fmt.Fprint(w, ",")
			}
			_, _ = fmt.Fprintf(w, `{"id":%d}`, i)
		}
		_, _ = fmt.Fprint(w, "]")
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, "t")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	type item struct {
		ID int `json:"id"`
	}
	got, err := GetJSONPaged[item](context.Background(), c, "/projects", nil)
	if err != nil {
		t.Fatalf("GetJSONPaged: %v", err)
	}
	if len(got) != total {
		t.Fatalf("read %d items, want %d — a short read here would ship a partial pack as complete", len(got), total)
	}
	if got[0].ID != 0 || got[total-1].ID != total-1 {
		t.Errorf("page boundaries wrong: first=%d last=%d", got[0].ID, got[total-1].ID)
	}
}

// TestGetJSONPagedStopsOnNonAdvancingNextPage pins that a server which keeps
// pointing at the same page fails loudly with a partial result, rather than
// looping until the context dies.
func TestGetJSONPagedStopsOnNonAdvancingNextPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Next-Page", "1") // never advances
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `[{"id":1}]`)
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, "t")
	type item struct {
		ID int `json:"id"`
	}
	_, err := GetJSONPaged[item](context.Background(), c, "/projects", nil)
	if err == nil {
		t.Fatal("want an error when X-Next-Page does not advance; got nil (this would loop in production)")
	}
}

// TestReadOnlyIsEnforcedInTheTransport pins ADR-0004 at the layer that cannot
// be bypassed by a careless collector.
func TestReadOnlyIsEnforcedInTheTransport(t *testing.T) {
	tr := newProvenanceTransport("t", http.DefaultTransport)
	req, _ := http.NewRequest(http.MethodPost, "https://gitlab.example/api/v4/projects", nil)
	if _, err := tr.RoundTrip(req); !errors.Is(err, ErrWriteMethodRejected) {
		t.Fatalf("POST was not rejected: err = %v", err)
	}
}

// TestTierGatedIsNotAFailure pins the distinction that decides whether this
// platform's evidence is trustworthy: 403 means "not entitled", which must
// never be read as "control absent".
func TestTierGatedIsNotAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"message":"403 Forbidden"}`)
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, "t")
	var out map[string]any
	err := GetJSON(context.Background(), c, "/projects/1/secret_detection", nil, &out)
	if err == nil {
		t.Fatal("want an error for 403")
	}
	if !IsTierGated(err) {
		t.Errorf("IsTierGated(403) = false; a collector would read this as a failing control")
	}
	if code, ok := StatusCodeOf(err); !ok || code != http.StatusForbidden {
		t.Errorf("StatusCodeOf = %d,%v; want 403,true", code, ok)
	}
}

// TestProvenanceRecordsEveryCall pins that the pack can prove which bytes a
// conclusion came from.
func TestProvenanceRecordsEveryCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":1}`)
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, "t")
	var out map[string]any
	if err := GetJSON(context.Background(), c, "/projects/1", url.Values{"x": {"y"}}, &out); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	prov := c.Provenance()
	if len(prov) != 1 {
		t.Fatalf("provenance entries = %d, want 1", len(prov))
	}
	if prov[0].Method != http.MethodGet || prov[0].HTTPStatus != 200 {
		t.Errorf("provenance = %+v", prov[0])
	}
	if prov[0].ResponseSHA256 == "" {
		t.Error("provenance carries no response hash; the pack could not prove what it read")
	}
	// The instance host must never appear in provenance — a self-managed URL
	// can itself be sensitive and the pack is meant to be shared.
	if got := prov[0].Endpoint; got == "" || got[0] != '/' {
		t.Errorf("Endpoint = %q; want a path only, never a full URL", got)
	}
}

// TestBaseURLDefaultsToGitLabCom pins that the hosted default is safe here,
// unlike Gogs where defaulting would target the wrong server entirely.
func TestBaseURLDefaultsToGitLabCom(t *testing.T) {
	c, err := NewClient("", "t")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.BaseURL() != defaultBaseURL {
		t.Errorf("BaseURL() = %q, want %q", c.BaseURL(), defaultBaseURL)
	}
}

// TestSelfManagedPathPrefixIsPreserved pins that an instance served under a
// suburl still resolves correctly.
func TestSelfManagedPathPrefixIsPreserved(t *testing.T) {
	c, err := NewClient("https://example.test/gitlab", "t")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got := c.resolve("/projects/1", nil)
	want := "https://example.test/gitlab/api/v4/projects/1"
	if got != want {
		t.Errorf("resolve = %q, want %q", got, want)
	}
}

// TestProjectPathIsNotDoubleEncoded pins a bug a live scan found: GitLab
// addresses a project as "group%2Fproject", and round-tripping that through
// url.URL.Path re-encodes the percent sign to %252F, so every request 404s on
// a project that exists. Every C02 result came back "project not found"
// before this was fixed.
func TestProjectPathIsNotDoubleEncoded(t *testing.T) {
	c, err := NewClient("https://gitlab.com", "t")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got := c.resolve("/projects/group%2Fproject/protected_branches", nil)
	want := "https://gitlab.com/api/v4/projects/group%2Fproject/protected_branches"
	if got != want {
		t.Errorf("resolve = %q, want %q", got, want)
	}
}
