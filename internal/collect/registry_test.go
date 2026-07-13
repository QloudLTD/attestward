package collect

import (
	"context"
	"testing"

	"github.com/sioakim/ssdf/internal/model"
)

type fakeCollector struct{ id string }

func (f fakeCollector) ID() string { return f.id }
func (f fakeCollector) Collect(context.Context, Scope) ([]model.CheckResult, error) {
	return nil, nil
}

func TestRegisterAndLookup(t *testing.T) {
	t.Cleanup(func() { delete(registry, "TEST.example") })

	Register(CheckMeta{ID: "TEST.example", Title: "Example", Collector: "test", TokenScope: "repo:read"})

	meta, ok := Lookup("TEST.example")
	if !ok {
		t.Fatal("Lookup(\"TEST.example\") = false, want true")
	}
	if meta.Title != "Example" {
		t.Errorf("Title = %q, want %q", meta.Title, "Example")
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	t.Cleanup(func() { delete(registry, "TEST.dup") })
	Register(CheckMeta{ID: "TEST.dup", Title: "First"})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register with a duplicate id did not panic")
		}
	}()
	Register(CheckMeta{ID: "TEST.dup", Title: "Second"})
}

func TestRegisteredIsSortedAndLookupMisses(t *testing.T) {
	t.Cleanup(func() {
		delete(registry, "TEST.b")
		delete(registry, "TEST.a")
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
