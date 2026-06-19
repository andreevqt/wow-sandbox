package auth

import "os"

// logPackets controls client→server logon packet logging. On by default; set
// WOW_LOG_PACKETS=0 to silence it.
var logPackets = os.Getenv("WOW_LOG_PACKETS") != "0"
