package github

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestCustomCATLSMinimum(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS11, tls.VersionTLS12} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"login":"fixture"}`))
			}))
			srv.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
			srv.StartTLS()
			defer srv.Close()
			roots := x509.NewCertPool()
			roots.AddCert(srv.Certificate())
			base, err := url.Parse(srv.URL + "/")
			if err != nil {
				t.Fatal(err)
			}
			client := NewClient("synthetic-token", ClientConfig{RESTBaseURL: base, CACertPool: roots})
			user, _, err := client.REST.Users.Get(context.Background(), "fixture")
			if version == tls.VersionTLS11 {
				if err == nil {
					t.Fatal("accepted TLS 1.1")
				}
			} else if err != nil || user.GetLogin() != "fixture" {
				t.Fatalf("TLS 1.2 with trusted custom CA: user=%v error=%v", user, err)
			}
		})
	}
}
