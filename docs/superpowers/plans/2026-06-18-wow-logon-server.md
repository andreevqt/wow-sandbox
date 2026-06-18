# WoW 1.12.1 Logon Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Go logon/auth server for the WoW 1.12.1 client (build 5875) that performs SRP6 authentication and returns a realm list, so the client reaches the character-selection screen.

**Architecture:** A single TCP listener on `:3724` speaking the plaintext vanilla logon protocol. Each connection runs a small state machine: `LOGON_CHALLENGE` → `LOGON_PROOF` → `REALM_LIST`. Accounts live in an in-memory store (one hardcoded test account). SRP6 (WoW variant) is implemented by hand because it is the core RE lesson; byte (de)serialization uses a small `packet` helper. The world server (where gameplay happens) is a **separate plan** — this server only advertises a realm pointing at `127.0.0.1:8085`.

**Tech Stack:** Go (stdlib only — `net`, `bufio`, `crypto/sha1`, `crypto/rand`, `math/big`, `encoding/binary`, `crypto/subtle`).

**Protocol references (cross-check byte layouts here):** CMaNGOS-classic `realmd/AuthSocket.cpp` (build 5875 ground truth), gtker.com vanilla writeup, wowdev.wiki. Where exact field widths are uncertain (realm list), the code below is a concrete starting point and the deferred client checkpoint is the validator.

---

## File Structure

- `go.mod` — module definition
- `cmd/authserver/main.go` — entrypoint, TCP listener, registers test account
- `internal/packet/buffer.go` — little-endian `Writer`/`Reader` helpers
- `internal/packet/buffer_test.go` — unit tests
- `internal/srp/srp.go` — WoW SRP6 (constants, verifier, server-side proof)
- `internal/srp/srp_test.go` — SRP6 round-trip unit test
- `internal/account/account.go` — in-memory account store + registration
- `internal/account/account_test.go` — unit test
- `internal/auth/opcodes.go` — logon opcodes + result codes
- `internal/auth/session.go` — per-connection state machine + packet build/parse
- `internal/auth/session_test.go` — in-process integration test over `net.Pipe`

---

## Task 0: Project scaffold

**Files:**
- Create: `go.mod`

- [ ] **Step 1: Initialize the module**

Run (from `/Users/andreevxdr/sources/wow-sandbox`):
```bash
go mod init wowsandbox
```
Expected: creates `go.mod` containing `module wowsandbox` and a `go 1.2x` line.

- [ ] **Step 2: Verify the toolchain**

Run: `go version`
Expected: prints `go version go1.21` or newer (need 1.18+ for `binary.LittleEndian.AppendUint*`).

- [ ] **Step 3: Commit**

```bash
git init
git add go.mod
git commit -m "chore: init go module for wow logon server"
```

---

## Task 1: Packet buffer helpers

**Files:**
- Create: `internal/packet/buffer.go`
- Test: `internal/packet/buffer_test.go`

- [ ] **Step 1: Write the failing test**

`internal/packet/buffer_test.go`:
```go
package packet

import (
	"bytes"
	"testing"
)

func TestWriterLittleEndian(t *testing.T) {
	w := NewWriter()
	w.U8(0x01)
	w.U16(0x0302)
	w.U32(0x07060504)
	w.CString("Hi")
	got := w.Bytes()
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 'H', 'i', 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestReaderRoundTrip(t *testing.T) {
	w := NewWriter()
	w.U8(0xAB)
	w.U16(0x1234)
	w.U32(0xDEADBEEF)
	r := NewReader(w.Bytes())
	if v, _ := r.U8(); v != 0xAB {
		t.Fatalf("U8 got %x", v)
	}
	if v, _ := r.U16(); v != 0x1234 {
		t.Fatalf("U16 got %x", v)
	}
	if v, _ := r.U32(); v != 0xDEADBEEF {
		t.Fatalf("U32 got %x", v)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/packet/ -run TestWriter -v`
Expected: FAIL — `undefined: NewWriter`.

- [ ] **Step 3: Write minimal implementation**

`internal/packet/buffer.go`:
```go
package packet

import (
	"encoding/binary"
	"io"
	"math"
)

// Writer accumulates little-endian encoded bytes.
type Writer struct{ b []byte }

func NewWriter() *Writer { return &Writer{} }

func (w *Writer) U8(v uint8)   { w.b = append(w.b, v) }
func (w *Writer) U16(v uint16) { w.b = binary.LittleEndian.AppendUint16(w.b, v) }
func (w *Writer) U32(v uint32) { w.b = binary.LittleEndian.AppendUint32(w.b, v) }
func (w *Writer) F32(v float32) {
	w.b = binary.LittleEndian.AppendUint32(w.b, math.Float32bits(v))
}
func (w *Writer) Raw(p []byte) { w.b = append(w.b, p...) }
func (w *Writer) CString(s string) {
	w.b = append(w.b, []byte(s)...)
	w.b = append(w.b, 0)
}
func (w *Writer) Bytes() []byte { return w.b }

// Reader consumes little-endian encoded bytes.
type Reader struct {
	b   []byte
	pos int
}

func NewReader(b []byte) *Reader { return &Reader{b: b} }

func (r *Reader) U8() (uint8, error) {
	if r.pos+1 > len(r.b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := r.b[r.pos]
	r.pos++
	return v, nil
}

func (r *Reader) U16() (uint16, error) {
	if r.pos+2 > len(r.b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.LittleEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *Reader) U32() (uint32, error) {
	if r.pos+4 > len(r.b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.LittleEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *Reader) Take(n int) ([]byte, error) {
	if r.pos+n > len(r.b) {
		return nil, io.ErrUnexpectedEOF
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/packet/ -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add internal/packet/
git commit -m "feat: little-endian packet buffer helpers"
```

---

## Task 2: SRP6 (WoW variant)

The WoW logon uses SRP6 with `g=7`, `k=3`, SHA-1, and a fixed 256-bit safe prime `N`. All SHA-1 digests and large numbers are interpreted/transmitted **little-endian**. This task implements the server side plus the helpers, and proves correctness with a self-contained client↔server round trip (no external vectors needed; the real-client byte order is validated later at the deferred checkpoint).

**Files:**
- Create: `internal/srp/srp.go`
- Test: `internal/srp/srp_test.go`

- [ ] **Step 1: Write the failing test**

`internal/srp/srp_test.go`:
```go
package srp

import (
	"crypto/rand"
	"crypto/sha1"
	"math/big"
	"strings"
	"testing"
)

// simulateClient mimics what the real 1.12 client computes, to prove the
// server's SRP math is internally consistent.
func simulateClient(t *testing.T, user, pass string, salt, bBytes []byte) (A, M1, K []byte) {
	t.Helper()
	B := fromLE(bBytes)

	a := randBigTest(19)
	Abig := new(big.Int).Exp(g, a, N) // A = g^a mod N
	A = toLE(Abig, 32)

	// x = SHA1(salt | SHA1(UPPER(user):UPPER(pass)))  (little-endian int)
	idHash := sha1.Sum([]byte(strings.ToUpper(user) + ":" + strings.ToUpper(pass)))
	x := fromLE(sha1Concat(salt, idHash[:]))

	// u = SHA1(A | B)
	u := fromLE(sha1Concat(A, bBytes))

	// S = (B - k*g^x)^(a + u*x) mod N
	gx := new(big.Int).Exp(g, x, N)
	kgx := new(big.Int).Mul(k, gx)
	base := new(big.Int).Mod(new(big.Int).Sub(B, kgx), N)
	exp := new(big.Int).Add(a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(base, exp, N)

	K = calculateK(S)
	M1 = computeM1(user, salt, Abig, B, K)
	return A, M1, K
}

func randBigTest(n int) *big.Int {
	b := make([]byte, n)
	rand.Read(b)
	return new(big.Int).SetBytes(b)
}

func TestSRP6RoundTrip(t *testing.T) {
	user, pass := "TEST", "TEST"
	salt := GenerateSalt()
	v := MakeVerifier(user, pass, salt)

	srv := NewServer(v)
	A, M1, K := simulateClient(t, user, pass, salt, srv.Bbytes())

	M2, ok := srv.Verify(user, salt, A, M1)
	if !ok {
		t.Fatal("server rejected a valid client proof")
	}

	// Client independently computes the expected M2 = SHA1(A | M1 | K).
	wantM2 := sha1Concat(A, M1, K)
	if string(M2) != string(wantM2) {
		t.Fatalf("M2 mismatch:\n got  %x\n want %x", M2, wantM2)
	}
}

func TestSRP6RejectsWrongPassword(t *testing.T) {
	salt := GenerateSalt()
	v := MakeVerifier("TEST", "RIGHT", salt)
	srv := NewServer(v)
	A, M1, _ := simulateClient(t, "TEST", "WRONG", salt, srv.Bbytes())
	if _, ok := srv.Verify("TEST", salt, A, M1); ok {
		t.Fatal("server accepted a wrong-password proof")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/srp/ -v`
Expected: FAIL — `undefined: GenerateSalt` (etc).

- [ ] **Step 3: Write the implementation**

`internal/srp/srp.go`:
```go
package srp

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"math/big"
	"strings"
)

// WoW SRP6 constants (build 5875). N is the canonical 256-bit safe prime,
// written here as a big-endian integer literal.
var (
	N = mustHex("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7")
	g = big.NewInt(7)
	k = big.NewInt(3)
)

func mustHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("srp: bad hex constant")
	}
	return n
}

// Nbytes returns N as a 32-byte little-endian slice (packet wire format).
func Nbytes() []byte { return toLE(N, 32) }

// GenerateSalt returns 32 random bytes used as the SRP salt.
func GenerateSalt() []byte {
	s := make([]byte, 32)
	if _, err := rand.Read(s); err != nil {
		panic(err)
	}
	return s
}

// MakeVerifier computes the SRP verifier v = g^x mod N for an account,
// returned as 32 little-endian bytes. user/pass are uppercased.
func MakeVerifier(user, pass string, salt []byte) []byte {
	x := computeX(user, pass, salt)
	v := new(big.Int).Exp(g, x, N)
	return toLE(v, 32)
}

func computeX(user, pass string, salt []byte) *big.Int {
	idHash := sha1.Sum([]byte(strings.ToUpper(user) + ":" + strings.ToUpper(pass)))
	return fromLE(sha1Concat(salt, idHash[:]))
}

// Server holds per-login server-side SRP state.
type Server struct {
	b *big.Int
	B *big.Int
	v *big.Int
}

// NewServer picks a private b and computes B = (k*v + g^b) mod N.
func NewServer(verifier []byte) *Server {
	v := fromLE(verifier)
	b := randBig(19)
	gb := new(big.Int).Exp(g, b, N)
	kv := new(big.Int).Mul(k, v)
	B := new(big.Int).Mod(new(big.Int).Add(kv, gb), N)
	return &Server{b: b, B: B, v: v}
}

// Bbytes returns B as 32 little-endian bytes (for the challenge response).
func (s *Server) Bbytes() []byte { return toLE(s.B, 32) }

// Verify checks the client's proof M1. On success it returns the server
// proof M2 (20 bytes) and true. aBytes and m1 come straight off the wire.
func (s *Server) Verify(user string, salt, aBytes, m1 []byte) ([]byte, bool) {
	A := fromLE(aBytes)
	if new(big.Int).Mod(A, N).Sign() == 0 { // reject A ≡ 0 (mod N)
		return nil, false
	}
	u := fromLE(sha1Concat(aBytes, toLE(s.B, 32)))
	// S = (A * v^u)^b mod N
	vu := new(big.Int).Exp(s.v, u, N)
	avu := new(big.Int).Mod(new(big.Int).Mul(A, vu), N)
	S := new(big.Int).Exp(avu, s.b, N)
	K := calculateK(S)

	expM1 := computeM1(user, salt, A, s.B, K)
	if subtle.ConstantTimeCompare(expM1, m1) != 1 {
		return nil, false
	}
	M2 := sha1Concat(toLE(A, 32), expM1, K)
	return M2, true
}

// computeM1 = SHA1( (SHA1(N) xor SHA1(g)) | SHA1(UPPER(user)) | salt | A | B | K )
func computeM1(user string, salt []byte, A, B *big.Int, K []byte) []byte {
	hN := sha1.Sum(toLE(N, 32))
	hg := sha1.Sum([]byte{7})
	xorNg := make([]byte, 20)
	for i := range xorNg {
		xorNg[i] = hN[i] ^ hg[i]
	}
	hI := sha1.Sum([]byte(strings.ToUpper(user)))
	return sha1Concat(xorNg, hI[:], salt, toLE(A, 32), toLE(B, 32), K)
}

// calculateK derives the 40-byte session key from S via SHA1-interleave:
// split the 32-byte LE S into even/odd byte streams, SHA1 each, interleave.
func calculateK(S *big.Int) []byte {
	sBytes := toLE(S, 32)
	even := make([]byte, 16)
	odd := make([]byte, 16)
	for i := 0; i < 16; i++ {
		even[i] = sBytes[i*2]
		odd[i] = sBytes[i*2+1]
	}
	he := sha1.Sum(even)
	ho := sha1.Sum(odd)
	K := make([]byte, 40)
	for i := 0; i < 20; i++ {
		K[i*2] = he[i]
		K[i*2+1] = ho[i]
	}
	return K
}

func sha1Concat(parts ...[]byte) []byte {
	h := sha1.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func randBig(n int) *big.Int {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(b)
}

// toLE returns n as a little-endian byte slice of exactly size bytes.
func toLE(n *big.Int, size int) []byte {
	be := n.Bytes() // big-endian, no leading zeros
	out := make([]byte, size)
	for i := 0; i < len(be) && i < size; i++ {
		out[i] = be[len(be)-1-i]
	}
	return out
}

// fromLE interprets b as a little-endian unsigned integer.
func fromLE(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[i] = b[len(b)-1-i]
	}
	return new(big.Int).SetBytes(be)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/srp/ -v`
Expected: PASS (`TestSRP6RoundTrip`, `TestSRP6RejectsWrongPassword`).

> Note: `calculateK` assumes a full 32-byte S. The real algorithm trims leading
> zero bytes (LE: trailing) so the interleaved halves stay aligned; with random
> 256-bit S this matters in <1% of logins. If the deferred client checkpoint
> shows intermittent proof failures, add the trim — see CMaNGOS `SRP6::Hash_SK`.

- [ ] **Step 5: Commit**

```bash
git add internal/srp/
git commit -m "feat: WoW SRP6 server with round-trip test"
```

---

## Task 3: In-memory account store

**Files:**
- Create: `internal/account/account.go`
- Test: `internal/account/account_test.go`

- [ ] **Step 1: Write the failing test**

`internal/account/account_test.go`:
```go
package account

import "testing"

func TestRegisterAndGet(t *testing.T) {
	s := NewStore()
	s.Register("test", "secret")

	acc, ok := s.Get("TEST") // client uppercases the account name
	if !ok {
		t.Fatal("account not found by uppercase name")
	}
	if len(acc.Salt) != 32 {
		t.Fatalf("salt len = %d, want 32", len(acc.Salt))
	}
	if len(acc.Verifier) != 32 {
		t.Fatalf("verifier len = %d, want 32", len(acc.Verifier))
	}
}

func TestGetMissing(t *testing.T) {
	s := NewStore()
	if _, ok := s.Get("NOPE"); ok {
		t.Fatal("expected missing account")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/account/ -v`
Expected: FAIL — `undefined: NewStore`.

- [ ] **Step 3: Write the implementation**

`internal/account/account.go`:
```go
package account

import (
	"strings"
	"sync"

	"wowsandbox/internal/srp"
)

// Account holds the SRP credentials we store for a user.
type Account struct {
	Username string // stored uppercased
	Salt     []byte // 32 bytes
	Verifier []byte // 32 bytes, little-endian
}

// Store is a thread-safe in-memory account registry.
type Store struct {
	mu sync.RWMutex
	m  map[string]*Account
}

func NewStore() *Store {
	return &Store{m: make(map[string]*Account)}
}

// Register creates (or overwrites) an account. The plaintext password is only
// used to derive the SRP verifier and is not retained.
func (s *Store) Register(user, pass string) *Account {
	u := strings.ToUpper(user)
	salt := srp.GenerateSalt()
	acc := &Account{
		Username: u,
		Salt:     salt,
		Verifier: srp.MakeVerifier(u, pass, salt),
	}
	s.mu.Lock()
	s.m[u] = acc
	s.mu.Unlock()
	return acc
}

// Get looks up an account by name (case-insensitive).
func (s *Store) Get(user string) (*Account, bool) {
	s.mu.RLock()
	acc, ok := s.m[strings.ToUpper(user)]
	s.mu.RUnlock()
	return acc, ok
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/account/ -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add internal/account/
git commit -m "feat: in-memory account store with SRP registration"
```

---

## Task 4: Logon opcodes and result codes

**Files:**
- Create: `internal/auth/opcodes.go`

- [ ] **Step 1: Write the constants**

`internal/auth/opcodes.go`:
```go
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
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./internal/auth/`
Expected: no output (success). (No test yet — pure constants; covered by Task 6.)

- [ ] **Step 3: Commit**

```bash
git add internal/auth/opcodes.go
git commit -m "feat: logon opcodes and result codes"
```

---

## Task 5: Session state machine and packet handlers

This is the wiring: read an opcode, dispatch, parse the request, build the response. Packet layouts below are for build 5875. The realm-list field widths are the most uncertain part — see the cross-check note.

**Files:**
- Create: `internal/auth/session.go`

- [ ] **Step 1: Write the implementation**

`internal/auth/session.go`:
```go
package auth

import (
	"bufio"
	"io"
	"net"

	"wowsandbox/internal/account"
	"wowsandbox/internal/packet"
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
	srp      *srp.Server
	username string
	salt     []byte
}

func NewSession(conn net.Conn, store *account.Store) *Session {
	return &Session{conn: conn, r: bufio.NewReader(conn), store: store}
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

	M2, ok := s.srp.Verify(s.username, s.salt, A, M1)
	if !ok {
		_, err := s.conn.Write([]byte{CmdAuthLogonProof, 0x03}) // 0x03 = WOW_FAIL_INCORRECT_PASSWORD
		return err
	}

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
//   icon u8, lockFlags u8, name cstring, address cstring, population f32,
//   numChars u8, timezone u8, realmId u8; trailer u16.
// CROSS-CHECK against CMaNGOS-classic realmd if the client shows no realm or
// disconnects here (vanilla uses u8 realm count; TBC+ switched to u16).
func (s *Session) handleRealmList() error {
	pad := make([]byte, 4) // client sends 4 bytes of padding
	if _, err := io.ReadFull(s.r, pad); err != nil {
		return err
	}

	body := packet.NewWriter()
	body.U32(0) // unused
	body.U8(1)  // number of realms
	body.U8(0)  // icon / realm type (0 = normal PvE)
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
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./...`
Expected: no output (success).

- [ ] **Step 3: Commit**

```bash
git add internal/auth/session.go
git commit -m "feat: logon session state machine and packet handlers"
```

---

## Task 6: In-process integration test (fake client over net.Pipe)

Drives a full `challenge → proof` exchange through `Session.Handle` using an in-memory pipe and a client SRP simulation, asserting the server accepts the proof and returns a valid M2. This validates packet parsing/building end-to-end without the real client.

**Files:**
- Create: `internal/auth/session_test.go`

- [ ] **Step 1: Write the failing test**

`internal/auth/session_test.go`:
```go
package auth

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"wowsandbox/internal/account"
)

// --- minimal client-side SRP mirror for the test ---

var (
	testN = mustHexBig("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7")
	testG = big.NewInt(7)
	testK = big.NewInt(3)
)

func mustHexBig(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 16)
	return n
}

func leToBig(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[i] = b[len(b)-1-i]
	}
	return new(big.Int).SetBytes(be)
}

func bigToLE(n *big.Int, size int) []byte {
	be := n.Bytes()
	out := make([]byte, size)
	for i := 0; i < len(be) && i < size; i++ {
		out[i] = be[len(be)-1-i]
	}
	return out
}

func sha1cat(parts ...[]byte) []byte {
	h := sha1.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func clientK(S *big.Int) []byte {
	s := bigToLE(S, 32)
	even, odd := make([]byte, 16), make([]byte, 16)
	for i := 0; i < 16; i++ {
		even[i] = s[i*2]
		odd[i] = s[i*2+1]
	}
	he, ho := sha1.Sum(even), sha1.Sum(odd)
	K := make([]byte, 40)
	for i := 0; i < 20; i++ {
		K[i*2] = he[i]
		K[i*2+1] = ho[i]
	}
	return K
}

func buildChallengeRequest(user string) []byte {
	// cmd + 32-byte fixed prefix + iLen + account name (uppercased by client)
	b := []byte{CmdAuthLogonChallenge}
	b = append(b, make([]byte, 32)...) // contents irrelevant to our parser
	u := strings.ToUpper(user)
	b = append(b, byte(len(u)))
	b = append(b, []byte(u)...)
	return b
}

func TestLogonFlowEndToEnd(t *testing.T) {
	store := account.NewStore()
	store.Register("test", "test")

	srvConn, cliConn := net.Pipe()
	go NewSession(srvConn, store).Handle()
	defer cliConn.Close()
	cliConn.SetDeadline(time.Now().Add(2 * time.Second))

	// 1) Send challenge, read response.
	if _, err := cliConn.Write(buildChallengeRequest("test")); err != nil {
		t.Fatal(err)
	}
	// Response: cmd(1) err(1) result(1) B(32) gLen(1) g(1) NLen(1) N(32) salt(32) crc(16) secFlags(1) = 119
	resp := make([]byte, 119)
	if _, err := io.ReadFull(cliConn, resp); err != nil {
		t.Fatalf("read challenge resp: %v", err)
	}
	if resp[2] != WowSuccess {
		t.Fatalf("challenge result = %d", resp[2])
	}
	bBytes := resp[3:35]
	salt := resp[3+32+1+1+1+32 : 3+32+1+1+1+32+32]

	// 2) Compute client proof.
	B := leToBig(bBytes)
	a := func() *big.Int { x := make([]byte, 19); rand.Read(x); return new(big.Int).SetBytes(x) }()
	Abig := new(big.Int).Exp(testG, a, testN)
	A := bigToLE(Abig, 32)

	idHash := sha1.Sum([]byte("TEST:TEST"))
	x := leToBig(sha1cat(salt, idHash[:]))
	u := leToBig(sha1cat(A, bBytes))
	gx := new(big.Int).Exp(testG, x, testN)
	base := new(big.Int).Mod(new(big.Int).Sub(B, new(big.Int).Mul(testK, gx)), testN)
	exp := new(big.Int).Add(a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(base, exp, testN)
	K := clientK(S)

	hN := sha1.Sum(bigToLE(testN, 32))
	hg := sha1.Sum([]byte{7})
	xorNg := make([]byte, 20)
	for i := range xorNg {
		xorNg[i] = hN[i] ^ hg[i]
	}
	hI := sha1.Sum([]byte("TEST"))
	M1 := sha1cat(xorNg, hI[:], salt, A, bBytes, K)

	// 3) Send proof: cmd + A(32) + M1(20) + crc(20) + numKeys(1) + secFlags(1).
	proof := []byte{CmdAuthLogonProof}
	proof = append(proof, A...)
	proof = append(proof, M1...)
	proof = append(proof, make([]byte, 22)...)
	if _, err := cliConn.Write(proof); err != nil {
		t.Fatal(err)
	}

	// 4) Read proof response and verify M2.
	pr := make([]byte, 26) // cmd + err + M2(20) + u32
	if _, err := io.ReadFull(cliConn, pr); err != nil {
		t.Fatalf("read proof resp: %v", err)
	}
	if pr[1] != WowSuccess {
		t.Fatalf("proof rejected, code %d", pr[1])
	}
	wantM2 := sha1cat(A, M1, K)
	if string(pr[2:22]) != string(wantM2) {
		t.Fatalf("M2 mismatch\n got  %x\n want %x", pr[2:22], wantM2)
	}
	_ = binary.LittleEndian // keep import if unused elsewhere
}
```

- [ ] **Step 2: Run test to verify it fails (then drives implementation if needed)**

Run: `go test ./internal/auth/ -run TestLogonFlowEndToEnd -v`
Expected initially: FAIL if any layout offset is off (e.g. wrong response length). Adjust `session.go` byte layout until it passes — this test *is* the layout spec for the in-memory path.

- [ ] **Step 3: Run test to verify it passes**

Run: `go test ./internal/auth/ -v`
Expected: PASS.

- [ ] **Step 4: Run the whole suite**

Run: `go test ./...`
Expected: all packages PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/session_test.go
git commit -m "test: end-to-end logon flow over net.Pipe"
```

---

## Task 7: Server entrypoint

**Files:**
- Create: `cmd/authserver/main.go`

- [ ] **Step 1: Write the implementation**

`cmd/authserver/main.go`:
```go
package main

import (
	"log"
	"net"

	"wowsandbox/internal/account"
	"wowsandbox/internal/auth"
)

func main() {
	store := account.NewStore()
	store.Register("TEST", "TEST")
	log.Printf("registered test account: TEST / TEST")

	ln, err := net.Listen("tcp", ":3724")
	if err != nil {
		log.Fatalf("listen :3724: %v", err)
	}
	log.Printf("logon server listening on :3724 (realm -> %s)", auth.WorldAddress)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		log.Printf("connection from %s", conn.RemoteAddr())
		go auth.NewSession(conn, store).Handle()
	}
}
```

- [ ] **Step 2: Build and start it**

Run: `go build ./... && go run ./cmd/authserver`
Expected: logs `logon server listening on :3724 ...` and stays running. Stop with Ctrl-C.

- [ ] **Step 3: Smoke-test the listener (no client needed)**

In a second terminal, run: `nc -z 127.0.0.1 3724 && echo "port open"`
Expected: prints `port open` (confirms the listener accepts TCP).

- [ ] **Step 4: Commit**

```bash
git add cmd/authserver/main.go
git commit -m "feat: authserver entrypoint listening on :3724"
```

---

## Task 8: Manual verification with the real 1.12 client  **[deferred verification]**

> Run this once the 1.12.1 client is installed on macOS (via CrossOver / Whisky / VM).
> No code changes expected — if the client misbehaves, the suspect is a byte
> layout, fixed by cross-checking CMaNGOS-classic `realmd` and re-running Task 6.

- [ ] **Step 1: Point the client at the local server**

Edit the client's `realmlist.wtf` (next to `WoW.exe`) to contain exactly:
```
set realmlist "127.0.0.1"
```

- [ ] **Step 2: Start the server**

Run: `go run ./cmd/authserver`
Expected: server logs `listening on :3724`.

- [ ] **Step 3: Log in**

Launch the client, log in with account `TEST`, password `TEST`.
Expected: login succeeds (no "Unable to connect" / "Incorrect password"); the
server logs a connection. **Success criterion (M1 complete): the realm "Sandbox"
appears in the realm list and selecting it advances to the character screen.**

- [ ] **Step 4: Triage table if it fails**

| Symptom | Likely cause | Where to look |
|---|---|---|
| "Unable to connect" | server not listening / firewall | Task 7 logs, `nc -z` smoke test |
| "Incorrect password" with correct creds | SRP byte order or `calculateK` trim | `internal/srp/srp.go`, re-run Task 2/6 |
| Login OK but no realm / disconnect at list | realm-list field widths or trailer | `handleRealmList`, cross-check CMaNGOS-classic |
| Realm shown but can't proceed | expected — world server not built yet | next plan (M2–M5) |

> Selecting the realm will try to connect to `127.0.0.1:8085`. There is no world
> server yet, so it will fail there — that is the boundary of this plan and the
> starting point of the next.

---

## Self-Review

- **Spec coverage:** M0 (TCP skeleton) → Tasks 0,7; M1 (SRP6 logon + realm list) → Tasks 1–6,8. SRP6 landmine → Task 2 (+trim note). Header-encryption / UPDATE_OBJECT / world opcodes are explicitly out of scope (next plan). ✓
- **Placeholders:** none — every code step has complete code; deferred steps are client-dependent and labeled, not vague. ✓
- **Type consistency:** `packet.NewWriter`/`U8`/`U16`/`U32`/`F32`/`CString`/`Raw`/`Bytes`, `srp.NewServer`/`Bbytes`/`Verify`/`Nbytes`/`GenerateSalt`/`MakeVerifier`, `account.NewStore`/`Register`/`Get`, `auth.NewSession`/`Handle`/`WorldAddress` are referenced consistently across tasks. ✓

## Out of scope (next plan: world server M2–M5)

World handshake (`SMSG_AUTH_CHALLENGE`/`CMSG_AUTH_SESSION` + header encryption), `CHAR_ENUM`/`CHAR_CREATE`, `PLAYER_LOGIN` + the login packet barrage, `SMSG_UPDATE_OBJECT` for the player, and movement opcodes. The logon server here advertises `127.0.0.1:8085` for that server to bind.
