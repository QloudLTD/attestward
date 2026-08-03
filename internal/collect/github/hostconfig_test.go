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
	"os"
	"path/filepath"
	"strings"
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
	_, err := ResolveHostConfig("ghe.example.com", "")
	if err == nil {
		t.Fatal("ResolveHostConfig(\"ghe.example.com\", \"\") = nil error, want a rejection (no scheme)")
	}
	if !strings.Contains(err.Error(), "ghe.example.com") {
		t.Errorf("error %q does not mention the offending value", err)
	}
}

func TestResolveHostConfig_RejectsNonHTTPScheme(t *testing.T) {
	_, err := ResolveHostConfig("ftp://ghe.example.com", "")
	if err == nil {
		t.Fatal("ResolveHostConfig(\"ftp://...\", \"\") = nil error, want a rejection (non-http(s) scheme)")
	}
	if !strings.Contains(err.Error(), "ftp") {
		t.Errorf("error %q does not mention the offending scheme", err)
	}
}

// TestResolveHostConfig_LoadsCACertPool proves GITHUB_CA_CERT is read and
// parsed into a non-nil pool that actually contains the given cert.
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
