package scahistory

import (
	"reflect"
	"testing"
)

func TestDetectEcosystems(t *testing.T) {
	tests := []struct {
		name          string
		rootFilenames []string
		hasWorkflows  bool
		want          []string
	}{
		{
			name:          "no manifests, no workflows: nothing detected",
			rootFilenames: []string{"README.md", "LICENSE"},
			hasWorkflows:  false,
			want:          nil,
		},
		{
			name:          "go.mod detected as gomod",
			rootFilenames: []string{"go.mod", "go.sum"},
			hasWorkflows:  false,
			want:          []string{"gomod"},
		},
		{
			name:          "multiple ecosystems detected and sorted",
			rootFilenames: []string{"package.json", "go.mod", "Cargo.toml"},
			hasWorkflows:  false,
			want:          []string{"cargo", "gomod", "npm"},
		},
		{
			name:          "any pip manifest variant is detected as pip",
			rootFilenames: []string{"pyproject.toml"},
			hasWorkflows:  false,
			want:          []string{"pip"},
		},
		{
			name:          "workflows present adds github-actions",
			rootFilenames: []string{"go.mod"},
			hasWorkflows:  true,
			want:          []string{"github-actions", "gomod"},
		},
		{
			name:          "workflows present with no manifests still adds github-actions alone",
			rootFilenames: nil,
			hasWorkflows:  true,
			want:          []string{"github-actions"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectEcosystems(tt.rootFilenames, tt.hasWorkflows)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("detectEcosystems(%v, %v) = %v, want %v", tt.rootFilenames, tt.hasWorkflows, got, tt.want)
			}
		})
	}
}
