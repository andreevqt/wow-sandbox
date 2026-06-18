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
