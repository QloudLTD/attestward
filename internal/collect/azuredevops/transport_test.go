package azuredevops

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops/adofixture"
)

func TestProvenanceTransportInjectsBasicAuthAndRecordsProvenance(t *testing.T) {
	fx := adofixture.New().Set("GET", "dev.azure.com", "/org/_apis/projects", adofixture.Response{
		Status: 200,
		Body:   map[string]any{"count": 1},
	})

	// Sits between provenanceTransport and the fixture, capturing the
	// Authorization header provenanceTransport injects before delegating.
	var gotAuth string
	capture := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotAuth = req.Header.Get("Authorization")
		return fx.RoundTrip(req)
	})

	const pat = "ado-test-pat-should-never-leak-into-provenance"
	prov := newProvenanceTransport(pat, capture)
	client := &http.Client{Transport: prov}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://dev.azure.com/org/_apis/projects?api-version=7.1", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Basic-auth header shape: "Basic base64(\":\"+pat)" — verified per
	// issue #156 as the ADO PAT auth convention (curl equivalent: curl -u
	// :{PAT}).
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+pat))
	if gotAuth != wantAuth {
		t.Errorf("Authorization header = %q, want %q", gotAuth, wantAuth)
	}

	entries := prov.Provenance()
	if len(entries) != 1 {
		t.Fatalf("len(Provenance()) = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Endpoint != "dev.azure.com/org/_apis/projects" {
		t.Errorf("Endpoint = %q, want %q (host-qualified, query string must not leak in)", entry.Endpoint, "dev.azure.com/org/_apis/projects")
	}
	if entry.Method != "GET" {
		t.Errorf("Method = %q, want GET", entry.Method)
	}
	if entry.HTTPStatus != 200 {
		t.Errorf("HTTPStatus = %d, want 200", entry.HTTPStatus)
	}
	if entry.ResponseSHA256 == "" {
		t.Error("ResponseSHA256 is empty")
	}
	if strings.Contains(entry.Endpoint, pat) {
		t.Error("PAT leaked into Provenance.Endpoint")
	}
}

// TestProvenanceTransportRejectsWriteMethods pins ADR-0004's read-only
// enforcement: any method other than GET/HEAD must be rejected before it
// ever reaches the underlying transport. The base transport panics if
// reached at all, proving the rejection happens at the guard itself —
// before auth injection or any network I/O — not merely that the fixture
// happened not to answer a write it wasn't configured for.
func TestProvenanceTransportRejectsWriteMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			base := roundTripFunc(func(*http.Request) (*http.Response, error) {
				panic("base transport reached for a " + method + " request — the read-only guard must reject before any network call")
			})

			prov := newProvenanceTransport("ado-test-pat", base)
			client := &http.Client{Transport: prov}

			req, err := http.NewRequestWithContext(context.Background(), method, "https://dev.azure.com/org/_apis/projects", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			_, err = client.Do(req)
			if err == nil {
				t.Fatalf("%s request: got nil error, want a rejection", method)
			}
			if !errors.Is(err, ErrWriteMethodRejected) {
				t.Errorf("%s request error = %v, want it to wrap ErrWriteMethodRejected", method, err)
			}
			if len(prov.Provenance()) != 0 {
				t.Error("a rejected write request was still recorded in Provenance — it never happened, so it must not appear as evidence of anything")
			}
		})
	}
}

// TestProvenanceTransportAllowsHead confirms the guard's allow-list is
// exactly {GET, HEAD}, not GET alone — HEAD is a legitimate read method and
// must not be caught by a guard meant only to block writes.
func TestProvenanceTransportAllowsHead(t *testing.T) {
	fx := adofixture.New().Set("HEAD", "dev.azure.com", "/org/_apis/projects", adofixture.Response{Status: 200})
	prov := newProvenanceTransport("ado-test-pat", fx)
	client := &http.Client{Transport: prov}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, "https://dev.azure.com/org/_apis/projects", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HEAD request: %v", err)
	}
	_ = resp.Body.Close()

	if len(prov.Provenance()) != 1 {
		t.Errorf("len(Provenance()) = %d, want 1 (HEAD is a read method and must be allowed through)", len(prov.Provenance()))
	}
}

// roundTripFunc adapts a function to http.RoundTripper for test wiring.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
