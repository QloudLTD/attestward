package provenance

import (
	"reflect"
	"testing"
)

func TestMatchesAnyPattern_Checksums(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"checksums.txt", true},
		{"CHECKSUMS.txt", true},
		{"SHA256SUMS", true},
		{"sha256sums.txt", true},
		{"myapp_linux_amd64.tar.gz.sha256", true},
		{"myapp_linux_amd64.sha256sum", true},
		{"myapp_linux_amd64.tar.gz", false},
		{"myapp.tar.gz.sig", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesAnyPattern(tt.name, checksumAssetPatterns); got != tt.want {
				t.Errorf("matchesAnyPattern(%q, checksumAssetPatterns) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestMatchesAnyPattern_Signatures(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"myapp.tar.gz.sig", true},
		{"cosign.pem", true},
		{"provenance.intoto.jsonl", true},
		{"myapp.sigstore", true},
		{"myapp.sigstore.json", true},
		{"checksums.txt.bundle", true},
		{"checksums.txt", false},
		{"myapp.tar.gz", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesAnyPattern(tt.name, signatureAssetPatterns); got != tt.want {
				t.Errorf("matchesAnyPattern(%q, signatureAssetPatterns) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestMatchingAssetNames(t *testing.T) {
	names := []string{"myapp_linux.tar.gz", "checksums.txt", "checksums.txt.bundle", "myapp_darwin.tar.gz"}
	got := matchingAssetNames(names, checksumAssetPatterns)
	want := []string{"checksums.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("matchingAssetNames(checksums) = %v, want %v", got, want)
	}

	got = matchingAssetNames(names, signatureAssetPatterns)
	want = []string{"checksums.txt.bundle"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("matchingAssetNames(signatures) = %v, want %v", got, want)
	}
}
