package world

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestOpcodeName(t *testing.T) {
	cases := map[uint32]string{
		uint32(CmsgPlayerLogin):   "CMSG_PLAYER_LOGIN",
		uint32(CmsgLogoutRequest): "CMSG_LOGOUT_REQUEST",
		0x0B5:                     "MSG_MOVE_START_FORWARD",
		0x0EE:                     "MSG_MOVE_HEARTBEAT",
	}
	for op, want := range cases {
		if got := opcodeName(op); got != want {
			t.Errorf("opcodeName(%#x) = %q, want %q", op, got, want)
		}
	}
	if got := opcodeName(0x999); got != "UNKNOWN_0x999" {
		t.Errorf("unknown opcode = %q", got)
	}
}

func TestDescribeBody(t *testing.T) {
	// CMSG_PLAYER_LOGIN guid
	login := make([]byte, 8)
	login[0] = 7
	if got := describeBody(uint32(CmsgPlayerLogin), login); got != "guid=7" {
		t.Errorf("player login = %q", got)
	}
	// CMSG_CHAR_CREATE: "Bob\0" + race=1 class=9 + 7 more + outfitId (9 bytes)
	cc := append([]byte("Bob"), 0, 1, 9, 0, 0, 0, 0, 0, 0, 0)
	if got := describeBody(uint32(CmsgCharCreate), cc); got != `name="Bob" race=1 class=9 gender=0 skin=0 face=0 hairStyle=0 hairColor=0 facialHair=0` {
		t.Errorf("char create = %q", got)
	}
	// movement: flags=0, time=0, x=1,y=2,z=3,o=0 (24 bytes)
	mv := make([]byte, 24)
	binary.LittleEndian.PutUint32(mv[8:], math.Float32bits(1))
	binary.LittleEndian.PutUint32(mv[12:], math.Float32bits(2))
	binary.LittleEndian.PutUint32(mv[16:], math.Float32bits(3))
	if got := describeBody(0x0B5, mv); got != "flags=0x0 time=0 x=1.00 y=2.00 z=3.00 o=0.00" {
		t.Errorf("movement = %q", got)
	}
	// no-body opcode
	if got := describeBody(uint32(CmsgCharEnum), nil); got != "(no body)" {
		t.Errorf("char enum = %q", got)
	}
}
