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
	CmsgCharCreate    uint16 = 0x36
	SmsgCharCreate    uint16 = 0x3A

	CmsgPlayerLogin      uint16 = 0x3D
	SmsgLoginVerifyWorld uint16 = 0x236
	SmsgTutorialFlags    uint16 = 0xFD
	SmsgUpdateObject     uint16 = 0xA9
)

// SMSG_AUTH_RESPONSE result code.
const authOK = 0x0C

// SMSG_CHAR_CREATE result codes (WorldResult). CHAR_CREATE_ERROR=0x2F is
// verified; the others are contiguous in the vanilla enum.
const (
	charCreateSuccess   = 0x2E
	charCreateError     = 0x2F
	charCreateFailed    = 0x30
	charCreateNameInUse = 0x31
	charCreateDisabled  = 0x32
)
