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
