package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sioakim/attestward/internal/collect"
)

// TestREADMEStructuralGapClaimsStillHold converts README prose into a guarded
// invariant.
//
// The "Coverage is not symmetric" section names specific check IDs as never
// resolvable on a platform, because nothing is read for them. That is a claim
// about the registry, and it was wrong before: an earlier version of that
// section was built from registered check TITLES, which describe what a check
// is about and say nothing about whether it ever calls an API. Eleven Azure
// DevOps mechanisms were promised that the tool never inspects.
//
// A registered title and an actual evidence source are independent facts, and
// the registry exposes both. This test asserts the README only ever claims the
// second. It fails in two directions:
//
//   - the README names a check as having no evidence source when the registry
//     says it has one (the prose is now wrong, or was always wrong);
//   - a named check disappears from the registry entirely (the prose points at
//     nothing).
//
// It deliberately does NOT assert the reverse — that every no-evidence check is
// named. The section is explicitly "the notable cases", not an inventory, and
// forcing exhaustiveness would make every new stub a README edit.
//
// The day someone implements one of these — reading Azure DevOps ACLs for C02,
// say — this test fails and says so, which is the correct outcome: the README
// claim has genuinely stopped being true.
func TestREADMEStructuralGapClaimsStillHold(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}

	section := extractStructuralGapSection(t, string(readme))
	ids := regexp.MustCompile(`C\d{2}\.[a-z][a-z0-9.-]*[a-z0-9]`).FindAllString(section, -1)
	if len(ids) == 0 {
		t.Fatal("no check IDs found in the coverage-asymmetry section — the section moved or its wording changed; re-anchor this test rather than deleting it")
	}

	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true

		// The README's gap list is about Azure DevOps except for the one
		// GitHub asymmetry it calls out explicitly.
		platform := "azuredevops"
		if strings.Contains(section, "GitHub exposes audit-log streaming") && id == "C09.audit.log-streaming" {
			platform = "github"
		}

		meta, ok := collect.LookupPlatform(platform, id)
		if !ok {
			t.Errorf("README names %s (%s) as never resolvable, but no such check is registered — the prose points at nothing", id, platform)
			continue
		}
		if len(meta.Endpoints) != 0 {
			t.Errorf("README claims %s (%s) has no evidence source, but the registry gives it endpoints %v — either the check gained an implementation (update the README) or the claim was never true",
				id, platform, meta.Endpoints)
		}
	}
}

// extractStructuralGapSection returns the coverage-asymmetry prose, anchored on
// its own heading text rather than line numbers so ordinary edits above it
// don't silently empty this test.
func extractStructuralGapSection(t *testing.T, readme string) string {
	t.Helper()
	const start = "**Coverage is not symmetric"
	i := strings.Index(readme, start)
	if i < 0 {
		t.Fatal(`could not find the "Coverage is not symmetric" section in README.md — if it was renamed, re-anchor this test; if it was deleted, the claims it guards went with it and that needs a deliberate decision, not a silent pass`)
	}
	rest := readme[i:]
	// Stop at the plan/token paragraph. That prose names checks too, but makes
	// the OPPOSITE claim about them — that a licence or scope is what gates
	// them, which means they DO have an evidence source. Scanning it would make
	// this test flag correct prose: it did exactly that on its first run, on
	// C06.sca.alerts-triaged. Two different kinds of claim, so two regions.
	for _, boundary := range []string{
		"\nSeparately from those,",
		"\nEvery check lands in one of five statuses",
	} {
		if j := strings.Index(rest, boundary); j > 0 {
			rest = rest[:j]
		}
	}
	return rest
}
