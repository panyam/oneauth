package oneauth

import (
	"fmt"
	"sync"
)

// Common errors for key operations
var (
	ErrKeyNotFound      = fmt.Errorf("signing key not found")
	ErrAlgorithmMismatch = fmt.Errorf("algorithm mismatch")
)

// KeyStore provides multi-tenant signing key lookup for JWT verification and minting.
// For HS256 keys, GetVerifyKey and GetSigningKey return []byte (shared secret).
// For RS256/ES256 (future), GetVerifyKey returns crypto.PublicKey and GetSigningKey returns crypto.PrivateKey.
type KeyStore interface {
	// GetVerifyKey returns the key material for verifying a JWT from the given client.
	GetVerifyKey(clientID string) (any, error)

	// GetSigningKey returns the key material for signing a JWT on behalf of the given client.
	GetSigningKey(clientID string) (any, error)

	// GetExpectedAlg returns the expected signing algorithm for the given client.
	// Used to prevent algorithm confusion attacks.
	GetExpectedAlg(clientID string) (string, error)
}

// WritableKeyStore extends KeyStore with write operations for key registration and management.
// All persistent KeyStore implementations (GORM, FS, GAE) implement this interface.
// InMemoryKeyStore also implements it for testing.
type WritableKeyStore interface {
	KeyStore

	// RegisterKey adds or overwrites a signing key for the given client_id.
	RegisterKey(clientID string, key any, algorithm string) error

	// DeleteKey removes the signing key for the given client_id.
	DeleteKey(clientID string) error

	// ListKeys returns all registered client IDs.
	ListKeys() ([]string, error)
}

// keyEntry stores key material and metadata for a single client.
type keyEntry struct {
	Key       any    // []byte for HMAC, crypto.PublicKey for asymmetric (future)
	Algorithm string // "HS256", "HS384", "HS512", "RS256", "ES256"
}

// InMemoryKeyStore is a thread-safe in-memory KeyStore implementation.
// Suitable for testing and simple single-process deployments.
type InMemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*keyEntry
}

// NewInMemoryKeyStore creates a new empty InMemoryKeyStore.
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{
		keys: make(map[string]*keyEntry),
	}
}

// RegisterKey adds or overwrites a signing key for the given client_id.
func (s *InMemoryKeyStore) RegisterKey(clientID string, key any, algorithm string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[clientID] = &keyEntry{Key: key, Algorithm: algorithm}
	return nil
}

// DeleteKey removes the signing key for the given client_id.
func (s *InMemoryKeyStore) DeleteKey(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[clientID]; !ok {
		return ErrKeyNotFound
	}
	delete(s.keys, clientID)
	return nil
}

// GetVerifyKey returns the verification key for the given client_id.
// For HMAC algorithms, this is the same shared secret used for signing.
func (s *InMemoryKeyStore) GetVerifyKey(clientID string) (any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.keys[clientID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return entry.Key, nil
}

// GetSigningKey returns the signing key for the given client_id.
// For HMAC algorithms, this is the same shared secret used for verification.
func (s *InMemoryKeyStore) GetSigningKey(clientID string) (any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.keys[clientID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return entry.Key, nil
}

// GetExpectedAlg returns the expected signing algorithm for the given client_id.
func (s *InMemoryKeyStore) GetExpectedAlg(clientID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.keys[clientID]
	if !ok {
		return "", ErrKeyNotFound
	}
	return entry.Algorithm, nil
}

// ListKeys returns all registered client IDs.
func (s *InMemoryKeyStore) ListKeys() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]string, 0, len(s.keys))
	for k := range s.keys {
		keys = append(keys, k)
	}
	return keys, nil
}
