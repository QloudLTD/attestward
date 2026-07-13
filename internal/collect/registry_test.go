package collect

import "testing"

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
