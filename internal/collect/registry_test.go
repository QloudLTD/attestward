package collect

import (
	"context"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/model"
)

type fakeCollector struct{ id string }

func (f fakeCollector) ID() string { return f.id }
func (f fakeCollector) Collect(context.Context, Scope) ([]model.CheckResult, error) {
	return nil, nil
}

func TestRegisterAndLookup(t *testing.T) {
	t.Cleanup(func() { delete(registry, registryKey{Platform: DefaultPlatform, ID: "TEST.example"}) })

	Register(CheckMeta{ID: "TEST.example", Title: "Example", Collector: "test", TokenScope: "repo:read"})

	meta, ok := Lookup("TEST.example")
	if !ok {
		t.Fatal("Lookup(\"TEST.example\") = false, want true")
	}
	if meta.Title != "Example" {
		t.Errorf("Title = %q, want %q", meta.Title, "Example")
	}
	if meta.Platform != "github" {
		t.Errorf("Platform = %q, want %q (Register must default an empty Platform)", meta.Platform, "github")
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	t.Cleanup(func() { delete(registry, registryKey{Platform: DefaultPlatform, ID: "TEST.dup"}) })
	Register(CheckMeta{ID: "TEST.dup", Title: "First"})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register with a duplicate id did not panic")
		}
	}()
	Register(CheckMeta{ID: "TEST.dup", Title: "Second"})
}

// TestRegisterDuplicateSamePlatformExplicitlyPanics pins the same guard as
// TestRegisterDuplicatePanics above, but with both registrations naming a
// non-default platform explicitly — proving the panic is keyed on
// (Platform, ID) together, not on ID alone falling back to some
// platform-blind map.
func TestRegisterDuplicateSamePlatformExplicitlyPanics(t *testing.T) {
	t.Cleanup(func() { delete(registry, registryKey{Platform: "azuredevops", ID: "TEST.ado-dup"}) })
	Register(CheckMeta{ID: "TEST.ado-dup", Platform: "azuredevops", Title: "First"})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register with a duplicate (platform, id) did not panic")
		}
	}()
	Register(CheckMeta{ID: "TEST.ado-dup", Platform: "azuredevops", Title: "Second"})
}

// TestRegisterMismatchedCollectorAcrossPlatformsPanics pins the review
// finding from #169: nothing enforced that the same check ID uses the same
// Collector string across platforms, so a second platform registering it
// under a different Collector would make internal/checksref (which groups
// by Collector, then merges same-ID entries) silently render two separate,
// duplicated sections instead of one merged check — worse than the
// last-write-wins bug that grouping replaced. Register must catch this at
// init time, the same way it already catches a duplicate (platform, id).
func TestRegisterMismatchedCollectorAcrossPlatformsPanics(t *testing.T) {
	t.Cleanup(func() { delete(registry, registryKey{Platform: "github", ID: "TEST.mismatched-collector"}) })
	Register(CheckMeta{ID: "TEST.mismatched-collector", Platform: "github", Collector: "C01.org-security"})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register with a mismatched Collector for an already-registered ID did not panic")
		}
	}()
	Register(CheckMeta{ID: "TEST.mismatched-collector", Platform: "azuredevops", Collector: "C01.org-security-ado"})
}

// TestRegisterSameIDDifferentPlatformsBothRetrievable pins issue #34's
// check-identity model: the same check ID registered under two different
// platforms is not a duplicate — it's how GitHub and Azure DevOps report
// the same SSDF-mapped control under one comparable ID — and both entries
// must be independently retrievable and carry the values registered for
// their own platform, not overwrite or shadow each other.
func TestRegisterSameIDDifferentPlatformsBothRetrievable(t *testing.T) {
	t.Cleanup(func() {
		delete(registry, registryKey{Platform: "github", ID: "TEST.dual-platform"})
		delete(registry, registryKey{Platform: "azuredevops", ID: "TEST.dual-platform"})
	})
	Register(CheckMeta{ID: "TEST.dual-platform", Platform: "github", Title: "GitHub title"})
	Register(CheckMeta{ID: "TEST.dual-platform", Platform: "azuredevops", Title: "ADO title"})

	ghMeta, ok := LookupPlatform("github", "TEST.dual-platform")
	if !ok {
		t.Fatal(`LookupPlatform("github", "TEST.dual-platform") = false, want true`)
	}
	if ghMeta.Title != "GitHub title" {
		t.Errorf("github Title = %q, want %q", ghMeta.Title, "GitHub title")
	}

	adoMeta, ok := LookupPlatform("azuredevops", "TEST.dual-platform")
	if !ok {
		t.Fatal(`LookupPlatform("azuredevops", "TEST.dual-platform") = false, want true`)
	}
	if adoMeta.Title != "ADO title" {
		t.Errorf("azuredevops Title = %q, want %q", adoMeta.Title, "ADO title")
	}

	all := Registered()
	found := map[string]bool{}
	for _, m := range all {
		if m.ID == "TEST.dual-platform" {
			found[m.Platform] = true
		}
	}
	if !found["github"] || !found["azuredevops"] {
		t.Errorf("Registered() = %v, want entries for both platforms of TEST.dual-platform", all)
	}
}

// TestLookupPlatformFallbackSemantics pins LookupPlatform's empty-platform
// default (same "github" fallback Register itself applies) and confirms it
// reports a clean miss for a platform that has nothing registered under
// that ID, rather than e.g. silently falling back to github's entry.
func TestLookupPlatformFallbackSemantics(t *testing.T) {
	t.Cleanup(func() { delete(registry, registryKey{Platform: DefaultPlatform, ID: "TEST.fallback"}) })
	Register(CheckMeta{ID: "TEST.fallback", Title: "Default-platform title"})

	byEmpty, ok := LookupPlatform("", "TEST.fallback")
	if !ok {
		t.Fatal(`LookupPlatform("", "TEST.fallback") = false, want true (empty platform defaults to github)`)
	}
	if byEmpty.Title != "Default-platform title" {
		t.Errorf("Title = %q, want %q", byEmpty.Title, "Default-platform title")
	}

	if _, ok := LookupPlatform("azuredevops", "TEST.fallback"); ok {
		t.Error(`LookupPlatform("azuredevops", "TEST.fallback") = true, want false — nothing registered there under this ID`)
	}
}

func TestRegisteredIsSortedAndLookupMisses(t *testing.T) {
	t.Cleanup(func() {
		delete(registry, registryKey{Platform: DefaultPlatform, ID: "TEST.b"})
		delete(registry, registryKey{Platform: DefaultPlatform, ID: "TEST.a"})
	})
	Register(CheckMeta{ID: "TEST.b"})
	Register(CheckMeta{ID: "TEST.a"})

	all := Registered()
	var lastB, lastA = -1, -1
	for i, m := range all {
		if m.ID == "TEST.a" {
			lastA = i
		}
		if m.ID == "TEST.b" {
			lastB = i
		}
	}
	if lastA == -1 || lastB == -1 || lastA > lastB {
		t.Errorf("Registered() not sorted by ID: %v", all)
	}

	if _, ok := Lookup("TEST.does-not-exist"); ok {
		t.Error("Lookup(\"TEST.does-not-exist\") = true, want false")
	}
}

// TestRegisteredSortsByPlatformThenID pins Registered()'s documented sort
// order once more than one platform is in play: platform is the primary
// sort key, ID only breaks ties within a platform. "azuredevops" < "github"
// alphabetically, so registering azuredevops's "TEST.sort-z" (an ID that
// would sort *last* under ID-only sorting) before github's "TEST.sort-a"
// (an ID that would sort *first*) proves platform, not ID, decides the
// primary order.
func TestRegisteredSortsByPlatformThenID(t *testing.T) {
	t.Cleanup(func() {
		delete(registry, registryKey{Platform: "azuredevops", ID: "TEST.sort-z"})
		delete(registry, registryKey{Platform: "github", ID: "TEST.sort-a"})
	})
	Register(CheckMeta{ID: "TEST.sort-z", Platform: "azuredevops"})
	Register(CheckMeta{ID: "TEST.sort-a", Platform: "github"})

	all := Registered()
	var idxADOz, idxGHa = -1, -1
	for i, m := range all {
		if m.ID == "TEST.sort-z" && m.Platform == "azuredevops" {
			idxADOz = i
		}
		if m.ID == "TEST.sort-a" && m.Platform == "github" {
			idxGHa = i
		}
	}
	if idxADOz == -1 || idxGHa == -1 || idxADOz > idxGHa {
		t.Errorf("Registered() not sorted by platform before ID: azuredevops's TEST.sort-z (idx %d) should sort before github's TEST.sort-a (idx %d)", idxADOz, idxGHa)
	}
}

func TestRegisterCollectorAndCollectors(t *testing.T) {
	before := len(Collectors())
	RegisterCollector(fakeCollector{id: "TEST.fake-a"})
	RegisterCollector(fakeCollector{id: "TEST.fake-b"})
	t.Cleanup(func() {
		collectors = collectors[:before]
		delete(collectorIDs, "TEST.fake-a")
		delete(collectorIDs, "TEST.fake-b")
	})

	all := Collectors()
	if len(all) != before+2 {
		t.Fatalf("len(Collectors()) = %d, want %d", len(all), before+2)
	}
	if all[before].ID() != "TEST.fake-a" || all[before+1].ID() != "TEST.fake-b" {
		t.Errorf("Collectors() = %v, want registration order preserved", all)
	}
}

func TestRegisterCollectorDuplicatePanics(t *testing.T) {
	RegisterCollector(fakeCollector{id: "TEST.dup-collector"})
	t.Cleanup(func() {
		collectors = collectors[:len(collectors)-1]
		delete(collectorIDs, "TEST.dup-collector")
	})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("RegisterCollector with a duplicate id did not panic")
		}
	}()
	RegisterCollector(fakeCollector{id: "TEST.dup-collector"})
}
