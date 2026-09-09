package gitlab

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type boundaryTransport func(*http.Request) (*http.Response, error)

func (f boundaryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCredentialBoundaryRedirects(t *testing.T) {
	for _, target := range []string{"https://other.example/api/v4/projects", "http://gitlab.example/api/v4/projects", "https://gitlab.example:444/api/v4/projects", "https://user:password@gitlab.example/api/v4/projects"} {
		t.Run(target, func(t *testing.T) {
			calls := 0
			transport := boundaryTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls > 1 {
					t.Error("redirect destination received a request")
				}
				return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{target}}, Body: http.NoBody, Request: r}, nil
			})
			c, err := NewClientForTest("https://gitlab.example", "synthetic-token", transport)
			if err != nil {
				t.Fatal(err)
			}
			var out any
			err = GetJSON(context.Background(), c, "/projects", nil, &out)
			if code, ok := StatusCodeOf(err); !ok || code != http.StatusFound {
				t.Fatalf("rejected redirect must retain its HTTP status: %v", err)
			}
			if calls != 1 {
				t.Fatalf("sent %d requests, want 1", calls)
			}
		})
	}
}

func TestCredentialBoundaryBaseURL(t *testing.T) {
	for _, raw := range []string{"https://user:private-value@gitlab.example", "https://gitlab.example?token=private-value", "https://gitlab.example#private-value", "https://private-value%zz", "private-value", "ftp://gitlab.example/private-value"} {
		t.Run(raw, func(t *testing.T) {
			_, err := NewClient(raw, "synthetic-token")
			if err == nil {
				t.Fatal("unsafe URL accepted")
			}
			if strings.Contains(fmt.Sprint(err), "private-value") {
				t.Fatal("URL secret leaked in error")
			}
		})
	}
}

func TestCredentialBoundarySameOriginAndLimit(t *testing.T) {
	for _, loop := range []bool{false, true} {
		t.Run(fmt.Sprint(loop), func(t *testing.T) {
			calls := 0
			transport := boundaryTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get(authHeader) != "synthetic-token" {
					t.Error("same-origin request lost auth")
				}
				resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: r}
				if loop || calls == 1 {
					resp.StatusCode = http.StatusMovedPermanently
					resp.Header.Set("Location", "/api/v4/projects/123")
				} else {
					resp.Body = io.NopCloser(strings.NewReader(`{"id":123}`))
				}
				return resp, nil
			})
			// Exercise the public constructor's policy as well as the fixture seam.
			c, err := NewClient("https://gitlab.example", "synthetic-token")
			if err != nil {
				t.Fatal(err)
			}
			c.prov.base = transport
			var out struct{ ID int }
			err = GetJSON(context.Background(), c, "/projects/group%2Frepo", nil, &out)
			if loop {
				if err == nil || calls != 10 {
					t.Fatalf("loop: err=%v calls=%d", err, calls)
				}
			} else if err != nil || calls != 2 || out.ID != 123 {
				t.Fatalf("same-origin rename: err=%v calls=%d id=%d", err, calls, out.ID)
			}
			if len(c.Provenance()) != calls {
				t.Fatal("redirect provenance missing")
			}
		})
	}
}

func TestCredentialBoundaryValidBaseURLs(t *testing.T) {
	for _, raw := range []string{"", "https://gitlab.example", "http://gitlab.example:8080/subpath/"} {
		c, err := NewClient(raw, "synthetic-token")
		if err != nil {
			t.Fatalf("valid URL %q: %v", raw, err)
		}
		want := strings.TrimRight(raw, "/")
		if want == "" {
			want = defaultBaseURL
		}
		if got := c.resolve("projects/group%2Frepo", nil); got != want+"/api/v4/projects/group%2Frepo" {
			t.Fatalf("resolve = %q", got)
		}
	}
}
