package world

import "testing"

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

func TestHexPreview(t *testing.T) {
	if got := hexPreview(nil); got != "" {
		t.Errorf("empty body = %q, want empty", got)
	}
	if got := hexPreview([]byte{0x01, 0xAB}); got != " [01 ab]" {
		t.Errorf("hexPreview = %q", got)
	}
}
