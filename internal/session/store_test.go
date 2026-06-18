package session

import (
	"bytes"
	"testing"
)

func TestPutGet(t *testing.T) {
	s := NewStore()
	key := make([]byte, 40)
	for i := range key {
		key[i] = byte(i)
	}
	s.Put("TEST", key)

	got, ok := s.Get("TEST")
	if !ok {
		t.Fatal("key not found")
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("key mismatch")
	}
}

func TestGetMissing(t *testing.T) {
	if _, ok := NewStore().Get("NOPE"); ok {
		t.Fatal("expected missing")
	}
}
