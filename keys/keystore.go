package keys

import (
	"context"
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

// ----------------------------------------------------------------------------
// Request / response types — KeyLookup
// ----------------------------------------------------------------------------

// GetKeyRequest is the input to KeyLookup.GetKey.
type GetKeyRequest struct {
	ClientID string
}

// GetKeyResponse is the output of KeyLookup.GetKey.
type GetKeyResponse struct {
	Record *KeyRecord
}

// GetKeyByKidRequest is the input to KeyLookup.GetKeyByKid.
type GetKeyByKidRequest struct {
	Kid string
}

// GetKeyByKidResponse is the output of KeyLookup.GetKeyByKid.
type GetKeyByKidResponse struct {
	Record *KeyRecord
}

// ----------------------------------------------------------------------------
// Request / response types — KeyStorage
// ----------------------------------------------------------------------------

// PutKeyRequest is the input to KeyStorage.PutKey.
type PutKeyRequest struct {
	Record *KeyRecord
}

// PutKeyResponse is the output of KeyStorage.PutKey.
type PutKeyResponse struct{}

// DeleteKeyRequest is the input to KeyStorage.DeleteKey.
type DeleteKeyRequest struct {
	ClientID string
}

// DeleteKeyResponse is the output of KeyStorage.DeleteKey.
type DeleteKeyResponse struct{}

// ListKeyIDsRequest is the input to KeyStorage.ListKeyIDs.
type ListKeyIDsRequest struct{}

// ListKeyIDsResponse is the output of KeyStorage.ListKeyIDs.
type ListKeyIDsResponse struct {
	ClientIDs []string
}

// ----------------------------------------------------------------------------
// Interfaces
// ----------------------------------------------------------------------------

// KeyLookup provides read-only key lookup by clientID or kid.
// Implemented by all keystores, including read-only ones like JWKSKeyStore.
type KeyLookup interface {
	// GetKey returns the key record for the given clientID.
	// Returns ErrKeyNotFound if the client has no registered key.
	GetKey(ctx context.Context, req *GetKeyRequest) (*GetKeyResponse, error)

	// GetKeyByKid returns the key record matching the given kid.
	// Returns ErrKidNotFound if no key matches or the key has expired.
	GetKeyByKid(ctx context.Context, req *GetKeyByKidRequest) (*GetKeyByKidResponse, error)
}

// KeyStorage extends KeyLookup with write operations.
// Implemented by persistent backends (InMemory, GORM, FS, GAE).
type KeyStorage interface {
	KeyLookup

	// PutKey stores a key record. If req.Record.Kid is empty, it is
	// auto-computed from the key material and algorithm. Overwrites any
	// existing key for the same ClientID.
	PutKey(ctx context.Context, req *PutKeyRequest) (*PutKeyResponse, error)

	// DeleteKey removes the key for the given clientID.
	DeleteKey(ctx context.Context, req *DeleteKeyRequest) (*DeleteKeyResponse, error)

	// ListKeyIDs returns all registered client IDs.
	ListKeyIDs(ctx context.Context, req *ListKeyIDsRequest) (*ListKeyIDsResponse, error)
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
func (s *InMemoryKeyStore) PutKey(ctx context.Context, req *PutKeyRequest) (*PutKeyResponse, error) {
	if req == nil || req.Record == nil {
		return nil, fmt.Errorf("PutKey: req.Record is required")
	}
	rec := req.Record
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
	return &PutKeyResponse{}, nil
}

// DeleteKey removes the key for the given clientID.
func (s *InMemoryKeyStore) DeleteKey(ctx context.Context, req *DeleteKeyRequest) (*DeleteKeyResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("DeleteKey: req is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.keys[req.ClientID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	if entry.Kid != "" {
		delete(s.kidIndex, entry.Kid)
	}
	delete(s.keys, req.ClientID)
	return &DeleteKeyResponse{}, nil
}

// GetKey returns the key record for the given clientID.
func (s *InMemoryKeyStore) GetKey(ctx context.Context, req *GetKeyRequest) (*GetKeyResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetKey: req is required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.keys[req.ClientID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return &GetKeyResponse{Record: &KeyRecord{
		ClientID:  req.ClientID,
		Key:       entry.Key,
		Algorithm: entry.Algorithm,
		Kid:       entry.Kid,
	}}, nil
}

// GetKeyByKid returns the key record matching the given kid.
func (s *InMemoryKeyStore) GetKeyByKid(ctx context.Context, req *GetKeyByKidRequest) (*GetKeyByKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetKeyByKid: req is required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	clientID, ok := s.kidIndex[req.Kid]
	if !ok {
		return nil, ErrKidNotFound
	}

	entry, ok := s.keys[clientID]
	if !ok || entry.Kid != req.Kid {
		return nil, ErrKidNotFound
	}

	return &GetKeyByKidResponse{Record: &KeyRecord{
		ClientID:  clientID,
		Key:       entry.Key,
		Algorithm: entry.Algorithm,
		Kid:       entry.Kid,
	}}, nil
}

// ListKeyIDs returns all registered client IDs.
func (s *InMemoryKeyStore) ListKeyIDs(ctx context.Context, req *ListKeyIDsRequest) (*ListKeyIDsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.keys))
	for k := range s.keys {
		ids = append(ids, k)
	}
	return &ListKeyIDsResponse{ClientIDs: ids}, nil
}
