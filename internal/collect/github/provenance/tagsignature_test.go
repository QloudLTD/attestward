package provenance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
)

func newTestClient(t *testing.T, mux *http.ServeMux) *ghcollect.Client {
	t.Helper()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := ghcollect.NewClient("ghp_test-token", ghcollect.ClientConfig{})
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	client.REST.BaseURL = baseURL
	return client
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode fixture response: %v", err)
	}
}

func TestResolveTagSignature_LightweightTag(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/repo-a/git/ref/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"ref":    "refs/tags/v1.0.0",
			"object": map[string]any{"type": "commit", "sha": "commit-sha-1"},
		})
	})

	client := newTestClient(t, mux)
	sig, err := resolveTagSignature(context.Background(), client, "attestward-demo", "repo-a", "v1.0.0")
	if err != nil {
		t.Fatalf("resolveTagSignature: %v", err)
	}
	if sig.Annotated {
		t.Error("Annotated = true, want false for a lightweight tag")
	}
	if sig.Signed || sig.Verified {
		t.Errorf("Signed=%v Verified=%v, want both false for a lightweight tag", sig.Signed, sig.Verified)
	}
	if sig.CommitSHA != "commit-sha-1" {
		t.Errorf("CommitSHA = %q, want commit-sha-1", sig.CommitSHA)
	}
}

func TestResolveTagSignature_AnnotatedSignedVerified(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/repo-a/git/ref/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"ref":    "refs/tags/v1.0.0",
			"object": map[string]any{"type": "tag", "sha": "tag-obj-sha"},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/repo-a/git/tags/tag-obj-sha", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"object": map[string]any{"type": "commit", "sha": "commit-sha-1"},
			"verification": map[string]any{
				"verified":  true,
				"reason":    "valid",
				"signature": "-----BEGIN PGP SIGNATURE-----...",
			},
		})
	})

	client := newTestClient(t, mux)
	sig, err := resolveTagSignature(context.Background(), client, "attestward-demo", "repo-a", "v1.0.0")
	if err != nil {
		t.Fatalf("resolveTagSignature: %v", err)
	}
	if !sig.Annotated {
		t.Error("Annotated = false, want true")
	}
	if !sig.Signed || !sig.Verified {
		t.Errorf("Signed=%v Verified=%v, want both true", sig.Signed, sig.Verified)
	}
	if sig.CommitSHA != "commit-sha-1" {
		t.Errorf("CommitSHA = %q, want commit-sha-1", sig.CommitSHA)
	}
	if sig.Reason != "valid" {
		t.Errorf("Reason = %q, want valid", sig.Reason)
	}
}

func TestResolveTagSignature_AnnotatedUnsigned(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/repo-a/git/ref/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"ref":    "refs/tags/v1.0.0",
			"object": map[string]any{"type": "tag", "sha": "tag-obj-sha"},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/repo-a/git/tags/tag-obj-sha", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"object": map[string]any{"type": "commit", "sha": "commit-sha-1"},
			"verification": map[string]any{
				"verified":  false,
				"reason":    "unsigned",
				"signature": "",
			},
		})
	})

	client := newTestClient(t, mux)
	sig, err := resolveTagSignature(context.Background(), client, "attestward-demo", "repo-a", "v1.0.0")
	if err != nil {
		t.Fatalf("resolveTagSignature: %v", err)
	}
	if sig.Signed {
		t.Error("Signed = true, want false for an unsigned annotated tag")
	}
	if sig.Reason != "unsigned" {
		t.Errorf("Reason = %q, want unsigned", sig.Reason)
	}
}

func TestResolveTagSignature_RefLookupFailurePropagatesError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestward-demo/repo-a/git/ref/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})

	client := newTestClient(t, mux)
	_, err := resolveTagSignature(context.Background(), client, "attestward-demo", "repo-a", "v1.0.0")
	if err == nil {
		t.Fatal("resolveTagSignature = nil error, want an error for a 404 ref lookup")
	}
}
