package session

import "sync"

// Store maps an uppercase account name to its 40-byte SRP session key (K).
// The logon server fills it on successful proof; the world server reads it
// to verify the auth digest. In-memory stand-in for the realmd/mangosd
// shared database.
type Store struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

func NewStore() *Store {
	return &Store{keys: make(map[string][]byte)}
}

func (s *Store) Put(account string, key []byte) {
	dup := make([]byte, len(key))
	copy(dup, key)
	s.mu.Lock()
	s.keys[account] = dup
	s.mu.Unlock()
}

func (s *Store) Get(account string) ([]byte, bool) {
	s.mu.RLock()
	k, ok := s.keys[account]
	s.mu.RUnlock()
	return k, ok
}
