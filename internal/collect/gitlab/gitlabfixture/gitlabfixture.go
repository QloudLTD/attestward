package gitlabfixture

import (
	"embed"
	"fmt"
	"path"
	"testing"
)

// files holds the recorded responses. Embedding rather than reading from disk
// at run time means a deleted or renamed fixture is a compile error, not a
// test that quietly starts passing against nothing.
//
//go:embed testdata/*.json
var files embed.FS

// Load returns the recorded response body for name (e.g.
// "vulnerabilities-all-states.json").
//
// This exists because the fixtures were, for a while, data that nothing read.
// Recordings that no test consumes are worse than no recordings: they cost
// real effort to capture, they look like coverage in a diff, and they answer
// no question. A loader is the smallest thing that makes them executable.
func Load(name string) ([]byte, error) {
	b, err := files.ReadFile(path.Join("testdata", name))
	if err != nil {
		return nil, fmt.Errorf("collect/gitlab/gitlabfixture: %w", err)
	}
	return b, nil
}

// MustLoad is Load for tests, failing the test rather than returning an error.
func MustLoad(t *testing.T, name string) []byte {
	t.Helper()
	b, err := Load(name)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	return b
}

// Names lists every recorded fixture. A test can use it to assert that each
// recording is still readable and still parses, so a corrupted or truncated
// capture is caught at the point it is committed rather than whenever the
// collector that needs it is finally written.
func Names() ([]string, error) {
	entries, err := files.ReadDir("testdata")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out, nil
}
