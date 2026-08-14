package github

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestResolveHostConfig_EmptyInputsKeepGitHubComDefault proves --github-url
// / GITHUB_CA_CERT both unset (today's every-existing-setup case) resolves
// to the exact zero value NewClient already treats as "github.com,
// unchanged" — issue #11's explicit "empty value keeps today's behaviour"
// requirement.
func TestResolveHostConfig_EmptyInputsKeepGitHubComDefault(t *testing.T) {
	cfg, err := ResolveHostConfig("", "")
	if err != nil {
		t.Fatalf("ResolveHostConfig(\"\", \"\") = %v, want nil error", err)
	}
	if cfg != (ClientConfig{}) {
		t.Errorf("cfg = %+v, want the zero value", cfg)
	}
}

// TestResolveHostConfig_BrowserURLDerivesRESTAndGraphQL proves the
// browser-facing form ("https://ghe.example.com", no path) derives both
// "/api/v3/" for REST and "/api/graphql" for GraphQL.
func TestResolveHostConfig_BrowserURLDerivesRESTAndGraphQL(t *testing.T) {
	cfg, err := ResolveHostConfig("https://ghe.example.com", "")
	if err != nil {
		t.Fatalf("ResolveHostConfig: %v", err)
	}
	if cfg.RESTBaseURL == nil {
		t.Fatal("RESTBaseURL is nil")
	}
	if got, want := cfg.RESTBaseURL.String(), "https://ghe.example.com/api/v3/"; got != want {
		t.Errorf("RESTBaseURL = %q, want %q", got, want)
	}
	if got, want := cfg.GraphQLURL, "https://ghe.example.com/api/graphql"; got != want {
		t.Errorf("GraphQLURL = %q, want %q", got, want)
	}
}

// TestResolveHostConfig_ExplicitAPIURLDoesNotDoubleAppend proves an
// already-API URL ("https://ghe.example.com/api/v3/") is accepted without
// growing an extra "/api/v3/api/v3/" — issue #11's explicit acceptance
// criterion.
func TestResolveHostConfig_ExplicitAPIURLDoesNotDoubleAppend(t *testing.T) {
	cfg, err := ResolveHostConfig("https://ghe.example.com/api/v3/", "")
	if err != nil {
		t.Fatalf("ResolveHostConfig: %v", err)
	}
	if got, want := cfg.RESTBaseURL.String(), "https://ghe.example.com/api/v3/"; got != want {
		t.Errorf("RESTBaseURL = %q, want %q (no double-append)", got, want)
	}
	if got, want := cfg.GraphQLURL, "https://ghe.example.com/api/graphql"; got != want {
		t.Errorf("GraphQLURL = %q, want %q", got, want)
	}
}

// TestResolveHostConfig_RejectsMissingScheme and
// TestResolveHostConfig_RejectsNonHTTPScheme cover issue #11's "a URL with
// no scheme, or a non-http(s) scheme, is rejected with an actionable
// error" acceptance criterion.
func TestResolveHostConfig_RejectsMissingScheme(t *testing.T) {
	// The input is deliberately NOT the example URL the message contains,
	// because the previous version of this test asserted the error *did*
	// mention the offending value — the inverse of the anti-echo
	// invariant — and passed only because the message's own example
	// happened to equal the test input.
	for _, raw := range []string{"internal.corp/ghe", "ghe.example.com"} {
		_, err := ResolveHostConfig(raw, "")
		if err == nil {
			t.Errorf("ResolveHostConfig(%q) = nil error, want a refusal", raw)
			continue
		}
		if strings.Contains(err.Error(), "internal.corp") {
			t.Errorf("ResolveHostConfig(%q) echoed the input back: %v", raw, err)
		}
	}
}

func TestResolveHostConfig_RejectsNonHTTPScheme(t *testing.T) {
	// The message deliberately does NOT name the offending scheme, and
	// that is the point rather than an omission: a scheme-shaped paste
	// like "svc:hunter2@ghe.example.com" parses with Scheme "svc" — the
	// username — so quoting the scheme would leak part of a credential.
	// No error from this function echoes any part of the input.
	for _, raw := range []string{"ftp://ghe.example.com", "svc:hunter2@ghe.example.com"} {
		_, err := ResolveHostConfig(raw, "")
		if err == nil {
			t.Errorf("ResolveHostConfig(%q) = nil error, want a refusal", raw)
			continue
		}
		for _, secret := range []string{"hunter2", "svc:", "ftp"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("ResolveHostConfig(%q) echoed %q back: %v", raw, secret, err)
			}
		}
	}
}

// TestResolveHostConfig_RejectsCredentials: the resolved URL is written into
// the pack as scope.github_url, and EvidencePack.Scrub walks Results only —
// Scope is never scrubbed — so a password here reaches a signed artifact
// verbatim. ScrubBytes is no backstop: it matches known token shapes, and an
// ordinary password has none.
func TestResolveHostConfig_RejectsCredentials(t *testing.T) {
	for _, raw := range []string{
		"https://svc:hunter2@ghe.example.com",
		"https://svc@ghe.example.com",
	} {
		cfg, err := ResolveHostConfig(raw, "")
		if err == nil {
			t.Errorf("ResolveHostConfig(%q) = nil error; REST base would be %v", raw, cfg.RESTBaseURL)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("ResolveHostConfig(%q) echoed the password back: %v", raw, err)
		}
	}
}

func TestResolveHostConfig_LoadsCACertPool(t *testing.T) {
	pemPath := writeTestCACert(t)

	cfg, err := ResolveHostConfig("", pemPath)
	if err != nil {
		t.Fatalf("ResolveHostConfig: %v", err)
	}
	if cfg.CACertPool == nil {
		t.Fatal("CACertPool is nil, want a pool containing the configured cert")
	}
}

// TestResolveHostConfig_MissingCACertFileIsActionableError proves a bad
// GITHUB_CA_CERT path fails loudly rather than silently falling back to
// the system trust store — a private CA is a hard blocker when absent
// (issue #11), so misconfiguring it must not look like success.
func TestResolveHostConfig_MissingCACertFileIsActionableError(t *testing.T) {
	_, err := ResolveHostConfig("", filepath.Join(t.TempDir(), "does-not-exist.pem"))
	if err == nil {
		t.Fatal("ResolveHostConfig with a nonexistent GITHUB_CA_CERT path = nil error, want a failure")
	}
}

// TestResolveHostConfig_InvalidPEMIsActionableError proves a file that
// exists but contains no PEM certificate also fails loudly.
func TestResolveHostConfig_InvalidPEMIsActionableError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-cert.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	_, err := ResolveHostConfig("", path)
	if err == nil {
		t.Fatal("ResolveHostConfig with a non-PEM GITHUB_CA_CERT = nil error, want a failure")
	}
}

// TestNewClient_GHESHost proves the full routing story end to end against a
// real httptest.Server standing in for a GHES host (issue #11's own
// acceptance criterion): every recorded provenance Endpoint is prefixed
// "/api/v3", and the response the fixture handler serves comes back
// correctly through go-github's request builder.
func TestNewClient_GHESHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/orgs/attestward-demo" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"attestward-demo","type":"Organization"}`))
	}))
	defer server.Close()

	cfg, err := ResolveHostConfig(server.URL, "")
	if err != nil {
		t.Fatalf("ResolveHostConfig: %v", err)
	}

	client := NewClient("ghp_test-token", cfg)
	org, _, err := client.REST.Organizations.Get(context.Background(), "attestward-demo")
	if err != nil {
		t.Fatalf("Organizations.Get: %v", err)
	}
	if org.GetLogin() != "attestward-demo" {
		t.Errorf("org login = %q, want attestward-demo", org.GetLogin())
	}

	prov := client.Provenance()
	if len(prov) != 1 {
		t.Fatalf("len(Provenance()) = %d, want 1", len(prov))
	}
	if !strings.HasPrefix(prov[0].Endpoint, "/api/v3") {
		t.Errorf("Provenance Endpoint = %q, want a /api/v3 prefix (GHES routing)", prov[0].Endpoint)
	}
}

// writeTestCACert generates a throwaway self-signed CA certificate and
// writes it PEM-encoded to a temp file, returning the file's path — a
// stand-in for an operator's real private-CA bundle.
func writeTestCACert(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "attestward-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ca.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("pem.Encode: %v", err)
	}
	return path
}

// TestNewClient_RedirectPolicy pins both halves of the host-scoped policy.
//
// Cross-host is refused: auth is injected inside the transport, below Go's
// redirect machinery, so its cross-domain header stripping never sees it.
// Before this policy, a --github-url answering 302 handed a third-party host
// a valid PAT and its body came back as the API's answer with a nil error.
//
// Same-host IS followed: GitHub documents 301 for renamed or transferred
// repositories and organizations, and net/http had always followed those.
// Refusing them outright — the first version of this fix — broke every scan
// naming a repo by its old name, on github.com, where nothing about GHES
// applies.
func TestNewClient_RedirectPolicy(t *testing.T) {
	t.Run("cross-host is refused and the token never leaves", func(t *testing.T) {
		var mu sync.Mutex
		var hits int
		var gotAuth string
		thirdParty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits++
			gotAuth = r.Header.Get("Authorization")
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"login":"pwned","type":"Organization"}`))
		}))
		defer thirdParty.Close()

		instance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, thirdParty.URL+"/evil", http.StatusFound)
		}))
		defer instance.Close()

		cfg, err := ResolveHostConfig(instance.URL, "")
		if err != nil {
			t.Fatalf("ResolveHostConfig: %v", err)
		}
		org, _, err := NewClient("super-secret-ghes-token", cfg).REST.Organizations.Get(context.Background(), "acme")
		if err == nil {
			t.Errorf("cross-host redirect was followed (org = %v)", org)
		}

		mu.Lock()
		defer mu.Unlock()
		if hits != 0 {
			t.Errorf("the redirect target was contacted %d times, want 0", hits)
		}
		if gotAuth != "" {
			t.Errorf("the token was sent to the redirect target: %q", gotAuth)
		}
		if org != nil && org.GetLogin() == "pwned" {
			t.Error("the redirect target's body was returned as the API answer")
		}
	})

	t.Run("same-host rename redirect is followed", func(t *testing.T) {
		var served int
		instance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/orgs/old-name") {
				http.Redirect(w, r, strings.Replace(r.URL.Path, "old-name", "new-name", 1), http.StatusMovedPermanently)
				return
			}
			served++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"login":"new-name","type":"Organization"}`))
		}))
		defer instance.Close()

		cfg, err := ResolveHostConfig(instance.URL, "")
		if err != nil {
			t.Fatalf("ResolveHostConfig: %v", err)
		}
		org, _, err := NewClient("t", cfg).REST.Organizations.Get(context.Background(), "old-name")
		if err != nil {
			t.Fatalf("same-host rename redirect was refused: %v", err)
		}
		if org.GetLogin() != "new-name" {
			t.Errorf("login = %q, want the renamed org", org.GetLogin())
		}
		if served != 1 {
			t.Errorf("target served %d times, want 1", served)
		}
	})

	t.Run("same-host scheme downgrade is refused", func(t *testing.T) {
		base, _ := url.Parse("https://ghe.example.com/api/v3/")
		policy := sameHostRedirectPolicy(base)
		req, _ := http.NewRequest(http.MethodGet, "http://ghe.example.com/api/v3/orgs/acme", nil)
		if err := policy(req, nil); err == nil {
			t.Error("an https -> http downgrade on the same host was allowed, putting the token on the wire in plaintext")
		}
	})
}
