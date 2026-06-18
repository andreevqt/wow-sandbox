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
