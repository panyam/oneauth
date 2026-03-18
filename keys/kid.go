package keys

import (
	"sync"
	"time"
)

// kidRecord holds key material indexed by kid, with an optional expiry.
type kidRecord struct {
	Key       any
	Algorithm string
	ClientID  string
	ExpiresAt time.Time // zero value means no expiry (current key)
}

// isExpired reports whether this record has passed its expiry time.
// Records with zero ExpiresAt never expire.
func (r *kidRecord) isExpired() bool {
	return !r.ExpiresAt.IsZero() && time.Now().After(r.ExpiresAt)
}

// KidStore is an in-memory KeyLookup that tracks kid→key mappings,
// including grace-period entries retained during key rotation.
//
// Usage during rotation:
//  1. kidStore.Add(oldKid, oldKey, alg, clientID, time.Now().Add(gracePeriod))
//  2. keyStorage.PutKey(newRecord)  // overwrites current
//  3. kidStore holds the old key until grace period expires
type KidStore struct {
	mu      sync.RWMutex
	records map[string]*kidRecord // kid -> record
}

// NewKidStore creates a new empty KidStore.
func NewKidStore() *KidStore {
	return &KidStore{
		records: make(map[string]*kidRecord),
	}
}

// Add registers a kid→key mapping. If expiresAt is zero, the key has no expiry.
func (s *KidStore) Add(kid string, key any, algorithm string, clientID string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[kid] = &kidRecord{
		Key:       key,
		Algorithm: algorithm,
		ClientID:  clientID,
		ExpiresAt: expiresAt,
	}
}

// Remove deletes a kid entry.
func (s *KidStore) Remove(kid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, kid)
}

// GetKey always returns ErrKeyNotFound — KidStore only supports kid-based lookup.
func (s *KidStore) GetKey(clientID string) (*KeyRecord, error) {
	return nil, ErrKeyNotFound
}

// GetKeyByKid returns the key record for the given kid.
// Returns ErrKidNotFound if the kid is unknown or expired.
func (s *KidStore) GetKeyByKid(kid string) (*KeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, ok := s.records[kid]
	if !ok || rec.isExpired() {
		return nil, ErrKidNotFound
	}
	return &KeyRecord{
		ClientID:  rec.ClientID,
		Key:       rec.Key,
		Algorithm: rec.Algorithm,
		Kid:       kid,
	}, nil
}

// CleanExpired removes all expired entries.
func (s *KidStore) CleanExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for kid, rec := range s.records {
		if rec.isExpired() {
			delete(s.records, kid)
		}
	}
}

// Len returns the number of entries (including expired ones not yet cleaned).
func (s *KidStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}

// CompositeKeyLookup tries multiple KeyLookups in order, returning the
// first successful result. Used to combine a KeyStorage's current-key
// lookup with a KidStore's grace-period entries.
type CompositeKeyLookup struct {
	Lookups []KeyLookup
}

// GetKey tries each lookup in order for a client_id match.
func (c *CompositeKeyLookup) GetKey(clientID string) (*KeyRecord, error) {
	for _, l := range c.Lookups {
		rec, err := l.GetKey(clientID)
		if err == nil {
			return rec, nil
		}
	}
	return nil, ErrKeyNotFound
}

// GetKeyByKid tries each lookup in order for a kid match.
func (c *CompositeKeyLookup) GetKeyByKid(kid string) (*KeyRecord, error) {
	for _, l := range c.Lookups {
		rec, err := l.GetKeyByKid(kid)
		if err == nil {
			return rec, nil
		}
	}
	return nil, ErrKidNotFound
}
