package world

import (
	"fmt"
	"os"
)

// logPackets controls client→server packet logging. On by default; set
// WOW_LOG_PACKETS=0 to silence it (movement generates a lot of traffic).
var logPackets = os.Getenv("WOW_LOG_PACKETS") != "0"

// opcodeNames maps known world opcodes to readable names for logging. It
// covers the opcodes we handle plus the common client→server opcodes a 1.12
// client sends after login (movement, queries, chat). Unknown opcodes are
// printed as hex.
var opcodeNames = map[uint32]string{
	uint32(CmsgAuthSession):   "CMSG_AUTH_SESSION",
	uint32(CmsgPing):          "CMSG_PING",
	uint32(CmsgCharEnum):      "CMSG_CHAR_ENUM",
	uint32(CmsgCharCreate):    "CMSG_CHAR_CREATE",
	uint32(CmsgPlayerLogin):   "CMSG_PLAYER_LOGIN",
	uint32(CmsgLogoutRequest): "CMSG_LOGOUT_REQUEST",
	uint32(CmsgLogoutCancel):  "CMSG_LOGOUT_CANCEL",

	0x050: "CMSG_NAME_QUERY",
	0x095: "CMSG_MESSAGECHAT",
	0x101: "CMSG_STANDSTATECHANGE",
	0x1CE: "CMSG_QUERY_TIME",
	0x20B: "CMSG_UPDATE_ACCOUNT_DATA",
	0x211: "CMSG_GMTICKET_GETTICKET",
	0x26A: "CMSG_SET_ACTIVE_MOVER",

	// Movement (MSG_* — same name in both directions).
	0x0B5: "MSG_MOVE_START_FORWARD",
	0x0B6: "MSG_MOVE_START_BACKWARD",
	0x0B7: "MSG_MOVE_STOP",
	0x0B8: "MSG_MOVE_START_STRAFE_LEFT",
	0x0B9: "MSG_MOVE_START_STRAFE_RIGHT",
	0x0BA: "MSG_MOVE_STOP_STRAFE",
	0x0BB: "MSG_MOVE_JUMP",
	0x0BC: "MSG_MOVE_START_TURN_LEFT",
	0x0BD: "MSG_MOVE_START_TURN_RIGHT",
	0x0BE: "MSG_MOVE_STOP_TURN",
	0x0BF: "MSG_MOVE_START_PITCH_UP",
	0x0C0: "MSG_MOVE_START_PITCH_DOWN",
	0x0C1: "MSG_MOVE_STOP_PITCH",
	0x0C2: "MSG_MOVE_SET_RUN_MODE",
	0x0C3: "MSG_MOVE_SET_WALK_MODE",
	0x0C9: "MSG_MOVE_FALL_LAND",
	0x0DA: "MSG_MOVE_SET_FACING",
	0x0DB: "MSG_MOVE_SET_PITCH",
	0x0EE: "MSG_MOVE_HEARTBEAT",
}

// opcodeName returns a readable name for an opcode, or its hex value.
func opcodeName(op uint32) string {
	if n, ok := opcodeNames[op]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN_0x%03X", op)
}
