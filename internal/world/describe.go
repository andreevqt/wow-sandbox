package world

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"wowsandbox/internal/packet"
)

// describeBody renders a client packet body as readable named fields when the
// opcode layout is known, falling back to a hex dump otherwise.
func describeBody(opcode uint32, body []byte) string {
	switch uint16(opcode) {
	case CmsgPlayerLogin:
		if len(body) >= 8 {
			return fmt.Sprintf("guid=%d", binary.LittleEndian.Uint64(body))
		}
	case CmsgPing:
		if len(body) >= 8 {
			return fmt.Sprintf("seq=%d latency=%dms",
				binary.LittleEndian.Uint32(body[0:4]), binary.LittleEndian.Uint32(body[4:8]))
		}
	case CmsgCharCreate:
		return describeCharCreate(body)
	case CmsgAuthSession:
		return describeAuthSession(body)
	case CmsgCharEnum, CmsgLogoutRequest, CmsgLogoutCancel:
		return "(no body)"
	}
	if strings.HasPrefix(opcodeName(opcode), "MSG_MOVE") {
		return describeMovement(body)
	}
	return packet.HexDump(body)
}

// describeMovement decodes the leading MovementInfo (flags, position, facing).
func describeMovement(b []byte) string {
	if len(b) < 24 {
		return packet.HexDump(b)
	}
	flags := binary.LittleEndian.Uint32(b[0:4])
	return fmt.Sprintf("flags=0x%X time=%d x=%.2f y=%.2f z=%.2f o=%.2f",
		flags, binary.LittleEndian.Uint32(b[4:8]),
		f32at(b, 8), f32at(b, 12), f32at(b, 16), f32at(b, 20))
}

func describeCharCreate(b []byte) string {
	end := cstrEnd(b)
	r := b[min(end+1, len(b)):]
	if end >= len(b) || len(r) < 9 {
		return packet.HexDump(b)
	}
	return fmt.Sprintf("name=%q race=%d class=%d gender=%d skin=%d face=%d hairStyle=%d hairColor=%d facialHair=%d",
		string(b[:end]), r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7])
}

func describeAuthSession(b []byte) string {
	if len(b) < 8 {
		return packet.HexDump(b)
	}
	build := binary.LittleEndian.Uint32(b[0:4])
	end := 8 + cstrEnd(b[8:])
	if end >= len(b) {
		return fmt.Sprintf("build=%d", build)
	}
	account := string(b[8:end])
	rest := b[end+1:]
	seed := ""
	if len(rest) >= 4 {
		seed = fmt.Sprintf(" clientSeed=0x%X", binary.LittleEndian.Uint32(rest[0:4]))
	}
	return fmt.Sprintf("build=%d account=%q%s", build, account, seed)
}

func f32at(b []byte, off int) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(b[off:]))
}

// cstrEnd returns the index of the first NUL in b, or len(b) if none.
func cstrEnd(b []byte) int {
	for i := range b {
		if b[i] == 0 {
			return i
		}
	}
	return len(b)
}
