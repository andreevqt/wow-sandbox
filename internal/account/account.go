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
