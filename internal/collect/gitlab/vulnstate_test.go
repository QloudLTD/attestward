package gitlab

import (
	"encoding/json"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect/gitlab/gitlabfixture"
)

// recordedVulnerability is the subset of GitLab's project-vulnerabilities
// response the state machine reasons about.
type recordedVulnerability struct {
	ID                      int    `json:"id"`
	Title                   string `json:"title"`
	State                   string `json:"state"`
	Severity                string `json:"severity"`
	ResolvedOnDefaultBranch bool   `json:"resolved_on_default_branch"`
}

// TestRecordedStatesDriveTheOpenPredicate is what makes the recording worth
// having. Before this, the state machine existed only as data no code read —
// which looks like coverage in a diff and answers no question. A collector
// that counted dismissed findings as open would have passed every test.
func TestRecordedStatesDriveTheOpenPredicate(t *testing.T) {
	var vulns []recordedVulnerability
	if err := json.Unmarshal(gitlabfixture.MustLoad(t, "vulnerabilities-all-states.json"), &vulns); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(vulns) == 0 {
		t.Fatal("fixture decoded to zero findings; this test would prove nothing")
	}

	// Every state GitLab can report must appear, or the recording has stopped
	// covering the machine it was captured to cover.
	want := map[string]bool{StateDetected: false, StateConfirmed: false, StateDismissed: false, StateResolved: false}
	open := 0
	for _, v := range vulns {
		isOpen, err := IsOpenVulnerability(v.State)
		if err != nil {
			t.Errorf("finding %d (%q): %v", v.ID, v.Title, err)
			continue
		}
		if _, known := want[v.State]; !known {
			t.Errorf("finding %d has state %q, which this build does not model", v.ID, v.State)
		}
		want[v.State] = true
		if isOpen {
			open++
		}
	}
	for state, seen := range want {
		if !seen {
			t.Errorf("no recorded finding is in state %q — the fixture no longer covers the full state machine", state)
		}
	}

	// The property that actually matters, derived from the recording rather
	// than hardcoded: open must be exactly the detected and confirmed findings,
	// and the closed ones must genuinely be excluded rather than the fixture
	// happening to contain none. A triage decision the producer already made
	// must not come back as a finding against them — reporting a dismissed
	// finding is how a scanner earns a reputation for noise.
	byState := map[string]int{}
	for _, v := range vulns {
		byState[v.State]++
	}
	wantOpen := byState[StateDetected] + byState[StateConfirmed]
	closed := byState[StateDismissed] + byState[StateResolved]
	if open != wantOpen {
		t.Errorf("open findings = %d, want %d (detected %d + confirmed %d)",
			open, wantOpen, byState[StateDetected], byState[StateConfirmed])
	}
	if closed == 0 {
		t.Fatal("the recording contains no dismissed or resolved findings, so this test cannot show they are excluded")
	}
	if open == len(vulns) {
		t.Errorf("every one of the %d recorded findings counted as open, so %d dismissed/resolved findings were "+
			"not excluded at all", len(vulns), closed)
	}
}

// TestUnrecognisedStateIsAnErrorNotAGuess pins the refusal. A GitLab release
// adding a state must stop the scan, not get silently bucketed into a signed
// attestation.
func TestUnrecognisedStateIsAnErrorNotAGuess(t *testing.T) {
	for _, state := range []string{"", "triaged", "Detected", "unknown"} {
		if _, err := IsOpenVulnerability(state); err == nil {
			t.Errorf("state %q was accepted; an unmodelled state must be an error, never a default", state)
		}
	}
}

// TestFixtureCoversTheDisagreementCase pins the edge the recording was captured
// for: state and resolved_on_default_branch can disagree, and a collector that
// reads only one gets a different answer than one that reads the other.
func TestFixtureCoversTheDisagreementCase(t *testing.T) {
	var vulns []recordedVulnerability
	if err := json.Unmarshal(gitlabfixture.MustLoad(t, "vulnerabilities-all-states.json"), &vulns); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	found := false
	for _, v := range vulns {
		if ResolvedOnDefaultBranch(v.State, v.ResolvedOnDefaultBranch) {
			found = true
			if open, _ := IsOpenVulnerability(v.State); !open {
				t.Errorf("finding %d: the disagreement case should be one the record still calls open", v.ID)
			}
		}
	}
	if !found {
		t.Error("no recorded finding is open by state while resolved on the default branch — that edge is the " +
			"reason this fixture was captured, and without it the next collector meets the case in production")
	}
}

// TestEveryRecordedFixtureIsReadableAndParses catches a truncated or corrupted
// capture when it is committed, rather than whenever the collector that needs
// it is finally written — which, for the audit-event recordings, may be months.
func TestEveryRecordedFixtureIsReadableAndParses(t *testing.T) {
	names, err := gitlabfixture.Names()
	if err != nil {
		t.Fatalf("list fixtures: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("no fixtures found")
	}
	for _, name := range names {
		var decoded any
		if err := json.Unmarshal(gitlabfixture.MustLoad(t, name), &decoded); err != nil {
			t.Errorf("%s does not parse: %v", name, err)
		}
	}
}
