package character

import (
	"strings"
	"sync"
)

// RaceHuman is the only race this sandbox allows to be created.
const RaceHuman uint8 = 1

// Human starting location: Northshire, Elwynn Forest (map 0).
const (
	startMap  uint32  = 0
	startArea uint32  = 12
	startX    float32 = -8949.95
	startY    float32 = -132.493
	startZ    float32 = 83.5312
)

// Character is a stored player character (M3 subset — appearance + position).
type Character struct {
	GUID                                         uint64
	Account                                      string
	Name                                         string
	Race, Class, Gender                          uint8
	Skin, Face, HairStyle, HairColor, FacialHair uint8
	Level                                        uint8
	Zone, Map                                    uint32
	X, Y, Z                                      float32
}

// Store holds created characters in memory, keyed by uppercase account name.
type Store struct {
	mu       sync.Mutex
	byAcct   map[string][]*Character
	nextGUID uint64
}

func NewStore() *Store {
	return &Store{byAcct: make(map[string][]*Character), nextGUID: 1}
}

// Create makes a level-1 Human character at the start location and stores it.
// Appearance bytes default to zero; callers may set them on the returned value
// before it is serialised (they are stored by reference).
func (s *Store) Create(account, name string, race, class uint8) *Character {
	acct := strings.ToUpper(account)
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := &Character{
		GUID:    s.nextGUID,
		Account: acct,
		Name:    name,
		Race:    race,
		Class:   class,
		Level:   1,
		Zone:    startArea,
		Map:     startMap,
		X:       startX,
		Y:       startY,
		Z:       startZ,
	}
	s.nextGUID++
	s.byAcct[acct] = append(s.byAcct[acct], ch)
	return ch
}

// List returns the characters for an account (case-insensitive), or nil.
func (s *Store) List(account string) []*Character {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byAcct[strings.ToUpper(account)]
}

// GetByGUID returns the character with the given GUID, or nil.
func (s *Store) GetByGUID(guid uint64) *Character {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, list := range s.byAcct {
		for _, ch := range list {
			if ch.GUID == guid {
				return ch
			}
		}
	}
	return nil
}

// NameExists reports whether any account already has a character with that
// name (case-insensitive).
func (s *Store) NameExists(name string) bool {
	target := strings.ToLower(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, list := range s.byAcct {
		for _, ch := range list {
			if strings.ToLower(ch.Name) == target {
				return true
			}
		}
	}
	return false
}
