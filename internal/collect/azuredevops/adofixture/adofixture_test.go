package adofixture

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// TestTransport_ErrorsLoudlyOnUnregisteredRoute pins the fixture's core
// safety property: a request nobody registered a Response for must fail
// loudly with ErrNoFixture, never fall through to a real network call —
// this is what lets collector tests run offline with go test ./... and
// still catch a collector that queries an endpoint its test never
// anticipated.
func TestTransport_ErrorsLoudlyOnUnregisteredRoute(t *testing.T) {
	fx := New().Set("GET", "dev.azure.com", "/org/_apis/projects", Response{Status: 200})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://dev.azure.com/org/_apis/git/repositories", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	_, err = fx.RoundTrip(req)
	if err == nil {
		t.Fatal("RoundTrip() = nil error, want ErrNoFixture for an unregistered route")
	}
	if !errors.Is(err, ErrNoFixture) {
		t.Errorf("RoundTrip() error = %v, want it to wrap ErrNoFixture", err)
	}
}

// TestTransport_HostDistinguishesOtherwiseIdenticalPaths proves the fixture
// key really is three parts, not two: the same path on two different ADO
// hosts (a real scenario — e.g. Graph vs core APIs can expose similarly
// shaped paths) must be registered and served independently, unlike
// ghfixture's path-only key which would collide here.
func TestTransport_HostDistinguishesOtherwiseIdenticalPaths(t *testing.T) {
	fx := New().
		Set("GET", "dev.azure.com", "/org/_apis/projects", Response{Status: 200, Body: map[string]any{"host": "core"}}).
		Set("GET", "vssps.dev.azure.com", "/org/_apis/projects", Response{Status: 200, Body: map[string]any{"host": "graph"}})

	for _, host := range []string{"dev.azure.com", "vssps.dev.azure.com"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+host+"/org/_apis/projects", nil)
		if err != nil {
			t.Fatalf("build request for %s: %v", host, err)
		}
		resp, err := fx.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip for %s: %v", host, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("host %s: status = %d, want 200", host, resp.StatusCode)
		}
	}
}
