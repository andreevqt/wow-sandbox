package world

// World protocol opcodes for build 5875.
const (
	SmsgAuthChallenge uint16 = 0x1EC
	CmsgAuthSession   uint16 = 0x1ED
	SmsgAuthResponse  uint16 = 0x1EE
	CmsgPing          uint16 = 0x1DC
	SmsgPong          uint16 = 0x1DD
	CmsgCharEnum      uint16 = 0x37
	SmsgCharEnum      uint16 = 0x3B
)

// SMSG_AUTH_RESPONSE result code.
const authOK = 0x0C
