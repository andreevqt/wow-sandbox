package world

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"wowsandbox/internal/character"
	"wowsandbox/internal/packet"
	"wowsandbox/internal/session"
)

var errBadSize = errors.New("world: packet size < 4")

// Session drives one world-server connection: handshake, then opcode loop.
type Session struct {
	conn       net.Conn
	r          *bufio.Reader
	sessions   *session.Store
	characters *character.Store
	crypt      *AuthCrypt // nil until auth completes
	account    string     // set on successful auth
}

func NewSession(conn net.Conn, sessions *session.Store, characters *character.Store) *Session {
	return &Session{conn: conn, r: bufio.NewReader(conn), sessions: sessions, characters: characters}
}

// sendPacket writes opcode+body, encrypting the 4-byte header once crypt is set.
func (s *Session) sendPacket(opcode uint16, body []byte) error {
	header := make([]byte, 4)
	size := uint16(len(body) + 2) // opcode (2) + body
	header[0] = byte(size >> 8)   // size, big-endian
	header[1] = byte(size)
	binary.LittleEndian.PutUint16(header[2:], opcode)
	if s.crypt != nil {
		s.crypt.Encrypt(header)
	}
	if _, err := s.conn.Write(header); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := s.conn.Write(body); err != nil {
			return err
		}
	}
	return nil
}

// readPacket reads one client packet, decrypting the 6-byte header once crypt
// is set. Returns opcode and body.
func (s *Session) readPacket() (uint32, []byte, error) {
	header := make([]byte, 6)
	if _, err := io.ReadFull(s.r, header); err != nil {
		return 0, nil, err
	}
	if s.crypt != nil {
		s.crypt.Decrypt(header)
	}
	size := int(header[0])<<8 | int(header[1]) // big-endian
	opcode := binary.LittleEndian.Uint32(header[2:6])
	bodyLen := size - 4 // size counts the 4-byte opcode
	if bodyLen < 0 {
		return 0, nil, errBadSize
	}
	body := make([]byte, bodyLen)
	if bodyLen > 0 {
		if _, err := io.ReadFull(s.r, body); err != nil {
			return 0, nil, err
		}
	}
	return opcode, body, nil
}

// Handle runs the connection: challenge, auth, then the opcode loop.
func (s *Session) Handle() {
	defer s.conn.Close()

	serverSeed, err := randU32()
	if err != nil {
		return
	}
	if err := s.sendAuthChallenge(serverSeed); err != nil {
		return
	}
	if err := s.handleAuthSession(serverSeed); err != nil {
		return
	}

	for {
		opcode, body, err := s.readPacket()
		if err != nil {
			return
		}
		switch uint16(opcode) {
		case CmsgPing:
			if err := s.handlePing(body); err != nil {
				return
			}
		case CmsgCharCreate:
			if err := s.handleCharCreate(body); err != nil {
				return
			}
		case CmsgCharEnum:
			if err := s.handleCharEnum(); err != nil {
				return
			}
		default:
			// ignore unknown opcodes (M2 only needs ping + char enum)
		}
	}
}

func (s *Session) sendAuthChallenge(serverSeed uint32) error {
	body := make([]byte, 4)
	binary.LittleEndian.PutUint32(body, serverSeed)
	return s.sendPacket(SmsgAuthChallenge, body)
}

// handleAuthSession reads CMSG_AUTH_SESSION, verifies the digest, enables the
// header cipher, and replies with SMSG_AUTH_RESPONSE = AUTH_OK.
func (s *Session) handleAuthSession(serverSeed uint32) error {
	opcode, body, err := s.readPacket()
	if err != nil {
		return err
	}
	if uint16(opcode) != CmsgAuthSession {
		return errors.New("world: expected CMSG_AUTH_SESSION")
	}
	// body: build u32, serverId u32, account cstring, clientSeed u32, digest[20]
	if len(body) < 8 {
		return errBadSize
	}
	p := 8 // skip build + serverId
	nameEnd := p
	for nameEnd < len(body) && body[nameEnd] != 0 {
		nameEnd++
	}
	if nameEnd >= len(body) {
		return errBadSize
	}
	account := string(body[p:nameEnd])
	p = nameEnd + 1
	if p+4+20 > len(body) {
		return errBadSize
	}
	clientSeed := binary.LittleEndian.Uint32(body[p : p+4])
	p += 4
	digest := body[p : p+20]

	key, ok := s.sessions.Get(account)
	if !ok {
		return errors.New("world: unknown session for account")
	}
	expected := authDigest(account, clientSeed, serverSeed, key)
	if subtle.ConstantTimeCompare(expected, digest) != 1 {
		return errors.New("world: bad auth digest")
	}

	// Header encryption is active from the next packet onward.
	s.account = account
	s.crypt = NewAuthCrypt(key)

	// SMSG_AUTH_RESPONSE (AUTH_OK) + billing fields (all zero in vanilla).
	resp := []byte{
		authOK,
		0, 0, 0, 0, // billing time remaining (u32)
		0,          // billing flags (u8)
		0, 0, 0, 0, // billing time rested (u32)
	}
	return s.sendPacket(SmsgAuthResponse, resp)
}

// handlePing echoes the ping sequence back as SMSG_PONG.
func (s *Session) handlePing(body []byte) error {
	if len(body) < 4 {
		return errBadSize
	}
	seq := body[:4] // ping sequence (u32); latency follows but we ignore it
	return s.sendPacket(SmsgPong, append([]byte(nil), seq...))
}

// handleCharEnum replies with the account's characters.
func (s *Session) handleCharEnum() error {
	chars := s.characters.List(s.account)
	w := packet.NewWriter()
	w.U8(uint8(len(chars)))
	for _, ch := range chars {
		writeEnumCharacter(w, ch)
	}
	return s.sendPacket(SmsgCharEnum, w.Bytes())
}

// writeEnumCharacter serialises one character into the vanilla SMSG_CHAR_ENUM
// block. Equipment slots are sent empty (no items in M3).
func writeEnumCharacter(w *packet.Writer, ch *character.Character) {
	w.U64(ch.GUID)
	w.CString(ch.Name)
	w.U8(ch.Race)
	w.U8(ch.Class)
	w.U8(ch.Gender)
	w.U8(ch.Skin)
	w.U8(ch.Face)
	w.U8(ch.HairStyle)
	w.U8(ch.HairColor)
	w.U8(ch.FacialHair)
	w.U8(ch.Level)
	w.U32(ch.Zone)
	w.U32(ch.Map)
	w.F32(ch.X)
	w.F32(ch.Y)
	w.F32(ch.Z)
	w.U32(0) // guild id
	w.U32(0) // character flags
	w.U8(1)  // first login
	w.U32(0) // pet display id
	w.U32(0) // pet level
	w.U32(0) // pet family
	for i := 0; i < 19; i++ {
		w.U32(0) // equipment display id
		w.U8(0)  // equipment inventory type
	}
	w.U32(0) // first bag display id
	w.U8(0)  // first bag inventory type
}

// handleCharCreate parses CMSG_CHAR_CREATE, enforces Human-only, stores the
// character, and replies with SMSG_CHAR_CREATE.
//
// Body: name CString, race u8, class u8, gender u8, skin u8, face u8,
// hairStyle u8, hairColor u8, facialHair u8, outfitId u8.
func (s *Session) handleCharCreate(body []byte) error {
	nameEnd := 0
	for nameEnd < len(body) && body[nameEnd] != 0 {
		nameEnd++
	}
	if nameEnd >= len(body) {
		return s.sendCharCreateResult(charCreateFailed)
	}
	name := string(body[:nameEnd])
	rest := body[nameEnd+1:]
	if len(rest) < 9 {
		return s.sendCharCreateResult(charCreateFailed)
	}
	race := rest[0]
	class := rest[1]
	gender := rest[2]
	skin := rest[3]
	face := rest[4]
	hairStyle := rest[5]
	hairColor := rest[6]
	facialHair := rest[7]

	if race != character.RaceHuman {
		return s.sendCharCreateResult(charCreateDisabled) // sandbox: Humans only
	}
	if name == "" {
		return s.sendCharCreateResult(charCreateFailed)
	}
	if s.characters.NameExists(name) {
		return s.sendCharCreateResult(charCreateNameInUse)
	}

	ch := s.characters.Create(s.account, name, race, class)
	ch.Gender = gender
	ch.Skin = skin
	ch.Face = face
	ch.HairStyle = hairStyle
	ch.HairColor = hairColor
	ch.FacialHair = facialHair
	return s.sendCharCreateResult(charCreateSuccess)
}

func (s *Session) sendCharCreateResult(code uint8) error {
	return s.sendPacket(SmsgCharCreate, []byte{code})
}

// authDigest = SHA1(account · 0x00000000 · clientSeed · serverSeed · K).
func authDigest(account string, clientSeed, serverSeed uint32, key []byte) []byte {
	h := sha1.New()
	h.Write([]byte(account))
	h.Write([]byte{0, 0, 0, 0})
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], clientSeed)
	h.Write(b[:])
	binary.LittleEndian.PutUint32(b[:], serverSeed)
	h.Write(b[:])
	h.Write(key)
	return h.Sum(nil)
}

func randU32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}
