package oneauth

import (
	"fmt"
	"sync"

	"github.com/panyam/oneauth/utils"
)

// Common errors for key operations
var (
	ErrKeyNotFound       = fmt.Errorf("signing key not found")
	ErrAlgorithmMismatch = fmt.Errorf("algorithm mismatch")
	ErrKidNotFound       = fmt.Errorf("key not found for kid")
)

// KeyRecord holds all fields for a stored signing key.
// All key operations work with this type rather than separate accessor methods.
type KeyRecord struct {
	ClientID  string // owning client/app
	Key       any    // []byte for HMAC, PEM bytes for asymmetric
	Algorithm string // "HS256", "RS256", "ES256", etc.
	Kid       string // key identifier, computed from key material
}

// KeyLookup provides read-only key lookup by clientID or kid.
// Implemented by all keystores, including read-only ones like JWKSKeyStore.
type KeyLookup interface {
	// GetKey returns the key record for the given clientID.
	// Returns ErrKeyNotFound if the client has no registered key.
	GetKey(clientID string) (*KeyRecord, error)

	// GetKeyByKid returns the key record matching the given kid.
	// Returns ErrKidNotFound if no key matches or the key has expired.
	GetKeyByKid(kid string) (*KeyRecord, error)
}

// KeyStorage extends KeyLookup with write operations.
// Implemented by persistent backends (InMemory, GORM, FS, GAE).
type KeyStorage interface {
	KeyLookup

	// PutKey stores a key record. If Kid is empty, it is auto-computed
	// from the key material and algorithm. Overwrites any existing key
	// for the same ClientID.
	PutKey(record *KeyRecord) error

	// DeleteKey removes the key for the given clientID.
	DeleteKey(clientID string) error

	// ListKeyIDs returns all registered client IDs.
	ListKeyIDs() ([]string, error)
}

// keyEntry is the internal storage representation for InMemoryKeyStore.
type keyEntry struct {
	Key       any
	Algorithm string
	Kid       string
}

// InMemoryKeyStore is a thread-safe in-memory KeyStorage implementation.
// Suitable for testing and simple single-process deployments.
type InMemoryKeyStore struct {
	mu       sync.RWMutex
	keys     map[string]*keyEntry
	kidIndex map[string]string // kid -> clientID
}

// NewInMemoryKeyStore creates a new empty InMemoryKeyStore.
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{
		keys:     make(map[string]*keyEntry),
		kidIndex: make(map[string]string),
	}
}

func computeKid(key any, alg string) string {
	kid, _ := utils.ComputeKid(key, alg)
	return kid
}

// PutKey stores a key record. Computes Kid from key material if not set.
func (s *InMemoryKeyStore) PutKey(rec *KeyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	kid := rec.Kid
	if kid == "" {
		kid = computeKid(rec.Key, rec.Algorithm)
	}

	// Remove old kid from index
	if old, ok := s.keys[rec.ClientID]; ok && old.Kid != "" {
		delete(s.kidIndex, old.Kid)
	}

	s.keys[rec.ClientID] = &keyEntry{Key: rec.Key, Algorithm: rec.Algorithm, Kid: kid}
	if kid != "" {
		s.kidIndex[kid] = rec.ClientID
	}
	return nil
}

// DeleteKey removes the key for the given clientID.
func (s *InMemoryKeyStore) DeleteKey(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.keys[clientID]
	if !ok {
		return ErrKeyNotFound
	}
	if entry.Kid != "" {
		delete(s.kidIndex, entry.Kid)
	}
	delete(s.keys, clientID)
	return nil
}

// GetKey returns the key record for the given clientID.
func (s *InMemoryKeyStore) GetKey(clientID string) (*KeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.keys[clientID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return &KeyRecord{
		ClientID:  clientID,
		Key:       entry.Key,
		Algorithm: entry.Algorithm,
		Kid:       entry.Kid,
	}, nil
}

// GetKeyByKid returns the key record matching the given kid.
func (s *InMemoryKeyStore) GetKeyByKid(kid string) (*KeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clientID, ok := s.kidIndex[kid]
	if !ok {
		return nil, ErrKidNotFound
	}

	entry, ok := s.keys[clientID]
	if !ok || entry.Kid != kid {
		return nil, ErrKidNotFound
	}

	return &KeyRecord{
		ClientID:  clientID,
		Key:       entry.Key,
		Algorithm: entry.Algorithm,
		Kid:       entry.Kid,
	}, nil
}

// ListKeyIDs returns all registered client IDs.
func (s *InMemoryKeyStore) ListKeyIDs() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.keys))
	for k := range s.keys {
		ids = append(ids, k)
	}
	return ids, nil
}

// ============================================================================
// Backward-compatible aliases (used by existing callers during migration)
// ============================================================================

// RegisterKey is a convenience method matching the old WritableKeyStore interface.
func (s *InMemoryKeyStore) RegisterKey(clientID string, key any, algorithm string) error {
	return s.PutKey(&KeyRecord{ClientID: clientID, Key: key, Algorithm: algorithm})
}

// GetVerifyKey is a convenience method matching the old KeyStore interface.
func (s *InMemoryKeyStore) GetVerifyKey(clientID string) (any, error) {
	rec, err := s.GetKey(clientID)
	if err != nil {
		return nil, err
	}
	return rec.Key, nil
}

// GetSigningKey is a convenience method matching the old KeyStore interface.
func (s *InMemoryKeyStore) GetSigningKey(clientID string) (any, error) {
	return s.GetVerifyKey(clientID)
}

// GetExpectedAlg is a convenience method matching the old KeyStore interface.
func (s *InMemoryKeyStore) GetExpectedAlg(clientID string) (string, error) {
	rec, err := s.GetKey(clientID)
	if err != nil {
		return "", err
	}
	return rec.Algorithm, nil
}

// ListKeys is a convenience alias for ListKeyIDs.
func (s *InMemoryKeyStore) ListKeys() ([]string, error) {
	return s.ListKeyIDs()
}

// GetCurrentKid returns the kid for the given clientID.
func (s *InMemoryKeyStore) GetCurrentKid(clientID string) (string, error) {
	rec, err := s.GetKey(clientID)
	if err != nil {
		return "", err
	}
	return rec.Kid, nil
}
