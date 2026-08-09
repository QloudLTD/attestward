package scahistory

import (
	"testing"
)

func TestParseDependabotConfig(t *testing.T) {
	raw := []byte(`version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
`)
	cfg, err := parseDependabotConfig(raw)
	if err != nil {
		t.Fatalf("parseDependabotConfig: %v", err)
	}
	got := cfg.ecosystems()
	want := map[string]bool{"npm": true, "gomod": true}
	if len(got) != len(want) {
		t.Fatalf("ecosystems() = %v, want %v", got, want)
	}
	for e := range want {
		if !got[e] {
			t.Errorf("ecosystems() missing %q", e)
		}
	}
}

func TestParseDependabotConfig_EmptyUpdatesList(t *testing.T) {
	cfg, err := parseDependabotConfig([]byte("version: 2\nupdates: []\n"))
	if err != nil {
		t.Fatalf("parseDependabotConfig: %v", err)
	}
	if len(cfg.ecosystems()) != 0 {
		t.Errorf("ecosystems() = %v, want empty", cfg.ecosystems())
	}
}

// TestParseDependabotConfig_LenientOnUnknownFields matches
// mapping.WorkflowFile's established precedent for external, uncontrolled
// repo content: a dependabot.yml using fields this struct doesn't model
// (reviewers, labels, open-pull-requests-limit, ...) must still parse
// successfully, not fail decode.
func TestParseDependabotConfig_LenientOnUnknownFields(t *testing.T) {
	raw := []byte(`version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/backend"
    schedule:
      interval: "daily"
    reviewers:
      - "octocat"
    labels:
      - "dependencies"
    open-pull-requests-limit: 10
`)
	cfg, err := parseDependabotConfig(raw)
	if err != nil {
		t.Fatalf("parseDependabotConfig: %v", err)
	}
	if !cfg.ecosystems()["pip"] {
		t.Errorf("ecosystems() = %v, want pip present", cfg.ecosystems())
	}
}
