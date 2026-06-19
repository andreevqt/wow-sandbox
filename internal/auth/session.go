package auth

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"wowsandbox/internal/account"
	"wowsandbox/internal/packet"
	"wowsandbox/internal/session"
	"wowsandbox/internal/srp"
)

// WorldAddress is the "ip:port" advertised in the realm list. The world
// server (separate plan) must listen here.
const WorldAddress = "127.0.0.1:8085"

// Session drives one client connection through the logon flow.
type Session struct {
	conn     net.Conn
	r        *bufio.Reader
	store    *account.Store
	sessions *session.Store
	srp      *srp.Server
	username string
	salt     []byte
}

func NewSession(conn net.Conn, store *account.Store, sessions *session.Store) *Session {
	return &Session{conn: conn, r: bufio.NewReader(conn), store: store, sessions: sessions}
}

// Handle reads opcodes until the connection closes or errors.
func (s *Session) Handle() {
	defer s.conn.Close()
	for {
		cmd, err := s.r.ReadByte()
		if err != nil {
			return
		}
		switch cmd {
		case CmdAuthLogonChallenge:
			err = s.handleChallenge()
		case CmdAuthLogonProof:
			err = s.handleProof()
		case CmdRealmList:
			err = s.handleRealmList()
		default:
			return // unknown opcode: drop the connection
		}
		if err != nil {
			return
		}
	}
}

// handleChallenge parses CMD_AUTH_LOGON_CHALLENGE and replies with B, g, N, salt.
//
// Wire layout after the (already-consumed) cmd byte:
//   error u8, size u16, gamename[4], v1 u8, v2 u8, v3 u8, build u16,
//   platform[4], os[4], locale[4], tzBias u32, ip u32, iLen u8, I[iLen]
// That fixed prefix is 32 bytes, then iLen, then the account name.
func (s *Session) handleChallenge() error {
	hdr := make([]byte, 33)
	if _, err := io.ReadFull(s.r, hdr); err != nil {
		return err
	}
	iLen := int(hdr[32])
	I := make([]byte, iLen)
	if _, err := io.ReadFull(s.r, I); err != nil {
		return err
	}
	username := string(I)
	if logPackets {
		ver := fmt.Sprintf("%d.%d.%d", hdr[7], hdr[8], hdr[9])
		log.Printf("C→S logon CMD_AUTH_LOGON_CHALLENGE account=%q version=%s build=%d",
			username, ver, binary.LittleEndian.Uint16(hdr[10:12]))
	}

	acc, ok := s.store.Get(username)
	if !ok {
		_, err := s.conn.Write([]byte{CmdAuthLogonChallenge, 0x00, WowFailUnknownAccount})
		return err
	}

	srv := srp.NewServer(acc.Verifier)
	s.srp = srv
	s.username = acc.Username
	s.salt = acc.Salt

	w := packet.NewWriter()
	w.U8(CmdAuthLogonChallenge)
	w.U8(0x00)       // protocol error byte
	w.U8(WowSuccess) // result
	w.Raw(srv.Bbytes())
	w.U8(1)             // length of g
	w.U8(7)             // g
	w.U8(32)            // length of N
	w.Raw(srp.Nbytes()) // N (little-endian)
	w.Raw(acc.Salt)     // 32-byte salt
	w.Raw(make([]byte, 16)) // CRC salt (unused by us)
	w.U8(0)             // security flags
	_, err := s.conn.Write(w.Bytes())
	return err
}

// handleProof parses CMD_AUTH_LOGON_PROOF and verifies M1.
//
// Wire layout after cmd: A[32], M1[20], crc[20], numKeys u8, secFlags u8 = 74 bytes.
func (s *Session) handleProof() error {
	buf := make([]byte, 74)
	if _, err := io.ReadFull(s.r, buf); err != nil {
		return err
	}
	if s.srp == nil {
		return io.ErrUnexpectedEOF // proof before challenge
	}
	A := buf[0:32]
	M1 := buf[32:52]
	if logPackets {
		log.Printf("C→S logon CMD_AUTH_LOGON_PROOF A=%s M1=%s", packet.HexDump(A), packet.HexDump(M1))
	}

	M2, K, ok := s.srp.Verify(s.username, s.salt, A, M1)
	if !ok {
		_, err := s.conn.Write([]byte{CmdAuthLogonProof, WowFailIncorrectPassword})
		return err
	}
	s.sessions.Put(s.username, K) // hand K to the world server

	w := packet.NewWriter()
	w.U8(CmdAuthLogonProof)
	w.U8(WowSuccess)
	w.Raw(M2)  // 20 bytes
	w.U32(0)   // account flags / unk
	_, err := s.conn.Write(w.Bytes())
	return err
}

// handleRealmList replies with a single realm pointing at the world server.
//
// Vanilla (5875) layout — body: unk u32=0, numRealms u8, then per realm:
//   realmType u32, lockFlags u8, name cstring, address cstring, population f32,
//   numChars u8, timezone u8, realmId u8; trailer u16.
// NOTE: in vanilla the realm type is a u32 (4 bytes). Using u8 here shifts the
// whole entry by 3 bytes — the real client then reads the name 3 bytes in
// (e.g. "Sandbox" rendered as "dbox"). Verified against the 1.12 client.
func (s *Session) handleRealmList() error {
	pad := make([]byte, 4) // client sends 4 bytes of padding
	if _, err := io.ReadFull(s.r, pad); err != nil {
		return err
	}
	if logPackets {
		log.Printf("C→S logon CMD_REALM_LIST")
	}

	body := packet.NewWriter()
	body.U32(0) // unused
	body.U8(1)  // number of realms
	body.U32(0) // realm type (0 = normal PvE) — u32 in vanilla
	body.U8(0)  // lock / color flags
	body.CString("Sandbox")
	body.CString(WorldAddress)
	body.F32(0) // population
	body.U8(0)  // characters on this realm for this account
	body.U8(1)  // timezone category
	body.U8(1)  // realm id
	body.U16(0) // trailer

	out := packet.NewWriter()
	out.U8(CmdRealmList)
	out.U16(uint16(len(body.Bytes())))
	out.Raw(body.Bytes())
	_, err := s.conn.Write(out.Bytes())
	return err
}
