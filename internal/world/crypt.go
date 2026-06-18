package world

// AuthCrypt is the vanilla (1.12) world header cipher: a byte-wise
// XOR-with-carry stream keyed by the 40-byte SRP session key. Only packet
// headers are passed through it; bodies are plaintext. State persists across
// packets, so one instance handles a whole connection.
type AuthCrypt struct {
	key                        []byte
	sendI, sendJ, recvI, recvJ uint8
}

func NewAuthCrypt(key []byte) *AuthCrypt {
	dup := make([]byte, len(key))
	copy(dup, key)
	return &AuthCrypt{key: dup}
}

// Encrypt transforms an outgoing (server→client) header in place.
func (c *AuthCrypt) Encrypt(data []byte) {
	n := uint8(len(c.key))
	for i := range data {
		x := (data[i] ^ c.key[c.sendI%n]) + c.sendJ
		c.sendI++
		c.sendJ = x
		data[i] = x
	}
}

// Decrypt transforms an incoming (client→server) header in place.
func (c *AuthCrypt) Decrypt(data []byte) {
	n := uint8(len(c.key))
	for i := range data {
		orig := data[i]
		x := (data[i] - c.recvJ) ^ c.key[c.recvI%n]
		c.recvI++
		c.recvJ = orig
		data[i] = x
	}
}
