package packet

import (
	"bytes"
	"testing"
)

func TestWriterLittleEndian(t *testing.T) {
	w := NewWriter()
	w.U8(0x01)
	w.U16(0x0302)
	w.U32(0x07060504)
	w.CString("Hi")
	got := w.Bytes()
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 'H', 'i', 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestReaderRoundTrip(t *testing.T) {
	w := NewWriter()
	w.U8(0xAB)
	w.U16(0x1234)
	w.U32(0xDEADBEEF)
	r := NewReader(w.Bytes())
	if v, _ := r.U8(); v != 0xAB {
		t.Fatalf("U8 got %x", v)
	}
	if v, _ := r.U16(); v != 0x1234 {
		t.Fatalf("U16 got %x", v)
	}
	if v, _ := r.U32(); v != 0xDEADBEEF {
		t.Fatalf("U32 got %x", v)
	}
}

func TestHexDump(t *testing.T) {
	if got := HexDump(nil); got != "" {
		t.Fatalf("empty = %q", got)
	}
	if got := HexDump([]byte{0x01, 0xAB, 0x00}); got != "01 ab 00" {
		t.Fatalf("HexDump = %q", got)
	}
}

func TestWriterU64(t *testing.T) {
	w := NewWriter()
	w.U64(0x0807060504030201)
	got := w.Bytes()
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
