package auth

// Logon (realmd) protocol opcodes for build 5875.
const (
	CmdAuthLogonChallenge byte = 0x00
	CmdAuthLogonProof     byte = 0x01
	CmdRealmList          byte = 0x10
)

// Auth result codes (subset).
const (
	WowSuccess            byte = 0x00
	WowFailUnknownAccount byte = 0x04
)
