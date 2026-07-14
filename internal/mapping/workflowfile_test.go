package mapping

import (
	"reflect"
	"testing"
)

// TestParseWorkflowFile_OnFieldShapes pins that WorkflowFile.On correctly
// decodes all three legal shapes GitHub Actions allows for a workflow's
// `on:` trigger list — a bare scalar, a list, or a map keyed by event name
// — since it's untyped (any) specifically to accommodate this. Added after
// C06 sca-history started relying on this field to inspect whether a
// workflow triggers on pull_request; nothing previously exercised it
// directly.
func TestParseWorkflowFile_OnFieldShapes(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want any
	}{
		{
			name: "bare unquoted scalar decodes as a Go string, not a bool (no YAML 1.1 Norway-problem coercion)",
			yaml: "name: test\non: pull_request\njobs: {}\n",
			want: "pull_request",
		},
		{
			name: "quoted scalar decodes identically to unquoted",
			yaml: "name: test\non: \"pull_request\"\njobs: {}\n",
			want: "pull_request",
		},
		{
			name: "list of event names decodes as []any of strings",
			yaml: "name: test\non: [push, pull_request]\njobs: {}\n",
			want: []any{"push", "pull_request"},
		},
		{
			name: "map keyed by event name decodes as map[string]any",
			yaml: "name: test\non:\n  pull_request:\n    branches: [main]\njobs: {}\n",
			want: map[string]any{"pull_request": map[string]any{"branches": []any{"main"}}},
		},
		{
			name: "absent on: decodes as nil",
			yaml: "name: test\njobs: {}\n",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wf, err := ParseWorkflowFile([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("ParseWorkflowFile: %v", err)
			}
			if !reflect.DeepEqual(wf.On, tt.want) {
				t.Errorf("On = %#v (%T), want %#v (%T)", wf.On, wf.On, tt.want, tt.want)
			}
		})
	}
}
