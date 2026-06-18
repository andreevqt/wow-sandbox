package world

import (
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"wowsandbox/internal/session"
)

// readServerPacket mirrors the client: decrypt the 4-byte server header
// (once crypt is active), then read the body.
func readServerPacket(t *testing.T, conn net.Conn, crypt *AuthCrypt) (uint16, []byte) {
	t.Helper()
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("read header: %v", err)
	}
	if crypt != nil {
		crypt.Decrypt(header)
	}
	size := int(header[0])<<8 | int(header[1])
	opcode := binary.LittleEndian.Uint16(header[2:4])
	body := make([]byte, size-2)
	if size-2 > 0 {
		if _, err := io.ReadFull(conn, body); err != nil {
			t.Fatalf("read body: %v", err)
		}
	}
	return opcode, body
}

// writeClientPacket mirrors the client: build a 6-byte header (u32 opcode),
// encrypt it once crypt is active, then write body.
func writeClientPacket(t *testing.T, conn net.Conn, crypt *AuthCrypt, opcode uint32, body []byte) {
	t.Helper()
	header := make([]byte, 6)
	size := uint16(len(body) + 4)
	header[0] = byte(size >> 8)
	header[1] = byte(size)
	binary.LittleEndian.PutUint32(header[2:], opcode)
	if crypt != nil {
		crypt.Encrypt(header)
	}
	if _, err := conn.Write(header); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if len(body) > 0 {
		if _, err := conn.Write(body); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
}

func TestWorldHandshakeToCharEnum(t *testing.T) {
	const account = "TEST"
	key := make([]byte, 40)
	for i := range key {
		key[i] = byte(i*3 + 5)
	}
	sessions := session.NewStore()
	sessions.Put(account, key)

	srvConn, cliConn := net.Pipe()
	go NewSession(srvConn, sessions).Handle()
	defer cliConn.Close()
	cliConn.SetDeadline(time.Now().Add(2 * time.Second))

	// 1) Read SMSG_AUTH_CHALLENGE (unencrypted), grab serverSeed.
	op, body := readServerPacket(t, cliConn, nil)
	if op != SmsgAuthChallenge {
		t.Fatalf("expected AUTH_CHALLENGE, got %#x", op)
	}
	serverSeed := binary.LittleEndian.Uint32(body)

	// 2) Send CMSG_AUTH_SESSION (unencrypted) with a correct digest.
	clientSeed := uint32(0xDEADBEEF)
	digest := authDigest(account, clientSeed, serverSeed, key)
	asBody := make([]byte, 0, 64)
	asBody = binary.LittleEndian.AppendUint32(asBody, 5875) // build
	asBody = binary.LittleEndian.AppendUint32(asBody, 0)    // serverId
	asBody = append(asBody, []byte(account)...)
	asBody = append(asBody, 0) // cstring terminator
	asBody = binary.LittleEndian.AppendUint32(asBody, clientSeed)
	asBody = append(asBody, digest...)
	writeClientPacket(t, cliConn, nil, uint32(CmsgAuthSession), asBody)

	// 3) From here both sides use the header cipher.
	clientCrypt := NewAuthCrypt(key)

	// 4) Read SMSG_AUTH_RESPONSE (encrypted header) = AUTH_OK.
	op, body = readServerPacket(t, cliConn, clientCrypt)
	if op != SmsgAuthResponse {
		t.Fatalf("expected AUTH_RESPONSE, got %#x", op)
	}
	if body[0] != authOK {
		t.Fatalf("auth result = %#x, want AUTH_OK", body[0])
	}

	// 5) Send CMSG_CHAR_ENUM (encrypted header), expect empty SMSG_CHAR_ENUM.
	writeClientPacket(t, cliConn, clientCrypt, uint32(CmsgCharEnum), nil)
	op, body = readServerPacket(t, cliConn, clientCrypt)
	if op != SmsgCharEnum {
		t.Fatalf("expected CHAR_ENUM, got %#x", op)
	}
	if len(body) != 1 || body[0] != 0 {
		t.Fatalf("expected 0 characters, got body %x", body)
	}

	// 6) Send CMSG_PING, expect SMSG_PONG echoing the sequence.
	pingBody := make([]byte, 8)
	binary.LittleEndian.PutUint32(pingBody[0:], 0x1234) // seq
	binary.LittleEndian.PutUint32(pingBody[4:], 50)     // latency
	writeClientPacket(t, cliConn, clientCrypt, uint32(CmsgPing), pingBody)
	op, body = readServerPacket(t, cliConn, clientCrypt)
	if op != SmsgPong {
		t.Fatalf("expected PONG, got %#x", op)
	}
	if binary.LittleEndian.Uint32(body) != 0x1234 {
		t.Fatalf("pong seq = %x, want 1234", body)
	}
	_ = sha1.New // keep import stable if refactored
}

func TestWorldRejectsBadDigest(t *testing.T) {
	const account = "TEST"
	key := make([]byte, 40)
	sessions := session.NewStore()
	sessions.Put(account, key)

	srvConn, cliConn := net.Pipe()
	go NewSession(srvConn, sessions).Handle()
	defer cliConn.Close()
	cliConn.SetDeadline(time.Now().Add(2 * time.Second))

	_, body := readServerPacket(t, cliConn, nil) // AUTH_CHALLENGE
	_ = body

	asBody := make([]byte, 0, 64)
	asBody = binary.LittleEndian.AppendUint32(asBody, 5875)
	asBody = binary.LittleEndian.AppendUint32(asBody, 0)
	asBody = append(asBody, []byte(account)...)
	asBody = append(asBody, 0)
	asBody = binary.LittleEndian.AppendUint32(asBody, 1)
	asBody = append(asBody, make([]byte, 20)...) // wrong (zero) digest
	writeClientPacket(t, cliConn, nil, uint32(CmsgAuthSession), asBody)

	// Server must drop the connection: next read fails (EOF/closed pipe).
	if _, err := io.ReadFull(cliConn, make([]byte, 4)); err == nil {
		t.Fatal("expected connection to close on bad digest")
	}
}
