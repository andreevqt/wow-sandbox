package auth

import "os"

// logPackets controls client→server logon packet logging. On by default; set
// WOW_LOG_PACKETS=0 to silence it.
var logPackets = os.Getenv("WOW_LOG_PACKETS") != "0"

// logonOpcodeName returns a readable name for a logon (realmd) opcode.
func logonOpcodeName(cmd byte) string {
	switch cmd {
	case CmdAuthLogonChallenge:
		return "CMD_AUTH_LOGON_CHALLENGE"
	case CmdAuthLogonProof:
		return "CMD_AUTH_LOGON_PROOF"
	case CmdRealmList:
		return "CMD_REALM_LIST"
	default:
		return "UNKNOWN_0x" + byteHex(cmd)
	}
}

func byteHex(b byte) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{digits[b>>4], digits[b&0xF]})
}
