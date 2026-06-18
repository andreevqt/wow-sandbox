package character

import "testing"

func TestCreateAssignsGuidAndLists(t *testing.T) {
	s := NewStore()

	a := s.Create("TEST", "Rdeal", RaceHuman, 9)
	b := s.Create("TEST", "Bob", RaceHuman, 1)
	if a.GUID == 0 || b.GUID == 0 {
		t.Fatal("GUID must be non-zero")
	}
	if a.GUID == b.GUID {
		t.Fatal("GUIDs must be unique")
	}

	list := s.List("TEST")
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	if list[0].Name != "Rdeal" || list[0].Map != 0 {
		t.Fatalf("unexpected first char: %+v", list[0])
	}
}

func TestListEmptyAndNameExists(t *testing.T) {
	s := NewStore()
	if len(s.List("NOBODY")) != 0 {
		t.Fatal("expected empty list")
	}
	s.Create("TEST", "Rdeal", RaceHuman, 9)
	if !s.NameExists("rdeal") {
		t.Fatal("NameExists should be case-insensitive")
	}
	if s.NameExists("ghost") {
		t.Fatal("unexpected name")
	}
}
