package account

import "testing"

func TestRegisterAndGet(t *testing.T) {
	s := NewStore()
	s.Register("test", "secret")

	acc, ok := s.Get("TEST") // client uppercases the account name
	if !ok {
		t.Fatal("account not found by uppercase name")
	}
	if len(acc.Salt) != 32 {
		t.Fatalf("salt len = %d, want 32", len(acc.Salt))
	}
	if len(acc.Verifier) != 32 {
		t.Fatalf("verifier len = %d, want 32", len(acc.Verifier))
	}
}

func TestGetMissing(t *testing.T) {
	s := NewStore()
	if _, ok := s.Get("NOPE"); ok {
		t.Fatal("expected missing account")
	}
}
