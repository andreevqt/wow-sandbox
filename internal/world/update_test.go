package world

import (
	"bytes"
	"encoding/binary"
	"testing"

	"wowsandbox/internal/character"
	"wowsandbox/internal/packet"
)

func TestPackedGUID(t *testing.T) {
	if got := packedGUID(1); !bytes.Equal(got, []byte{0x01, 0x01}) {
		t.Fatalf("packedGUID(1) = %x", got)
	}
	if got := packedGUID(0x0102); !bytes.Equal(got, []byte{0x03, 0x02, 0x01}) {
		t.Fatalf("packedGUID(0x0102) = %x", got)
	}
	if got := packedGUID(0); !bytes.Equal(got, []byte{0x00}) {
		t.Fatalf("packedGUID(0) = %x", got)
	}
}

func TestBuildUpdateMask(t *testing.T) {
	w := packet.NewWriter()
	buildUpdateMask(w, []fieldValue{{0, 0xAABBCCDD}, {34, 0x11223344}})
	got := w.Bytes()
	if got[0] != 2 {
		t.Fatalf("block_count = %d, want 2", got[0])
	}
	if binary.LittleEndian.Uint32(got[1:5]) != 1<<0 {
		t.Fatalf("mask0 = %#x", binary.LittleEndian.Uint32(got[1:5]))
	}
	if binary.LittleEndian.Uint32(got[5:9]) != 1<<(34-32) {
		t.Fatalf("mask1 = %#x", binary.LittleEndian.Uint32(got[5:9]))
	}
	if binary.LittleEndian.Uint32(got[9:13]) != 0xAABBCCDD || binary.LittleEndian.Uint32(got[13:17]) != 0x11223344 {
		t.Fatal("values wrong")
	}
}

func TestBuildCreatePlayerStartsCorrectly(t *testing.T) {
	ch := &character.Character{GUID: 1, Name: "Rdeal", Race: 1, Class: 9, Gender: 1, Level: 1, Map: 0, X: 1, Y: 2, Z: 3}
	body := buildCreatePlayer(ch)
	if binary.LittleEndian.Uint32(body[0:4]) != 1 {
		t.Fatalf("amount = %d", binary.LittleEndian.Uint32(body[0:4]))
	}
	if body[4] != 0 {
		t.Fatalf("has_transport = %d", body[4])
	}
	if body[5] != updateTypeCreate2 {
		t.Fatalf("update_type = %#x", body[5])
	}
	if body[6] != 0x01 || body[7] != 0x01 {
		t.Fatalf("packed guid = %x %x", body[6], body[7])
	}
	if body[8] != typeIDPlayer {
		t.Fatalf("object_type = %#x", body[8])
	}
	if body[9] != updateFlagSelfLiving {
		t.Fatalf("update_flag = %#x", body[9])
	}
}
