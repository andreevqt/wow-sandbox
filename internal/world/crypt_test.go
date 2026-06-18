package world

import (
	"bytes"
	"testing"
)

// The client's Decrypt must invert the server's Encrypt when fed in lockstep.
func TestAuthCryptRoundTrip(t *testing.T) {
	key := make([]byte, 40)
	for i := range key {
		key[i] = byte(i*7 + 1)
	}
	server := NewAuthCrypt(key)
	client := NewAuthCrypt(key)

	orig := []byte{0x00, 0x06, 0x34, 0x12} // a 4-byte server header
	buf := append([]byte(nil), orig...)

	server.Encrypt(buf)
	if bytes.Equal(buf, orig) {
		t.Fatal("Encrypt did not change the bytes")
	}
	client.Decrypt(buf)
	if !bytes.Equal(buf, orig) {
		t.Fatalf("Decrypt did not invert Encrypt: got %x want %x", buf, orig)
	}
}

func TestAuthCryptMultiPacketState(t *testing.T) {
	key := make([]byte, 40)
	for i := range key {
		key[i] = byte(255 - i)
	}
	server := NewAuthCrypt(key)
	client := NewAuthCrypt(key)

	// Two consecutive headers must round-trip with persisted state.
	for _, h := range [][]byte{{0x00, 0x02, 0xEE, 0x01}, {0x00, 0x09, 0x3B, 0x00}} {
		orig := append([]byte(nil), h...)
		server.Encrypt(h)
		client.Decrypt(h)
		if !bytes.Equal(h, orig) {
			t.Fatalf("multi-packet round-trip failed: got %x want %x", h, orig)
		}
	}
}
