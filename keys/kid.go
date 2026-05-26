package keys

import (
	"context"
	"fmt"
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

// ----------------------------------------------------------------------------
// Request / response types — KidStorage
// ----------------------------------------------------------------------------

// AddKidRequest is the input to KidStorage.Add. If ExpiresAt is zero,
// the kid has no expiry (current key).
type AddKidRequest struct {
	Kid       string
	Key       any
	Algorithm string
	ClientID  string
	ExpiresAt time.Time
}

// AddKidResponse is the output of KidStorage.Add.
type AddKidResponse struct{}

// RemoveKidRequest is the input to KidStorage.Remove.
type RemoveKidRequest struct {
	Kid string
}

// RemoveKidResponse is the output of KidStorage.Remove.
type RemoveKidResponse struct{}

// CleanExpiredRequest is the input to KidStorage.CleanExpired.
type CleanExpiredRequest struct{}

// CleanExpiredResponse is the output of KidStorage.CleanExpired.
type CleanExpiredResponse struct {
	// Removed is the number of expired records evicted by this call.
	Removed int
}

// KidStorage is the write side of a kid-indexed key store. It extends the
// read-only KeyLookup with the grace-period operations KidStore provides,
// so retired keys can be persisted across process restarts by backends in
// stores/ (FS, GORM, GAE) rather than living only in process memory.
//
// Unlike KeyStorage, KidStorage is keyed by kid (not clientID): GetKey by
// clientID always returns ErrKeyNotFound — only GetKeyByKid is meaningful.
type KidStorage interface {
	KeyLookup

	// Add registers a kid→key mapping. If req.ExpiresAt is zero, the key
	// has no expiry. Re-adding an existing kid overwrites it.
	Add(ctx context.Context, req *AddKidRequest) (*AddKidResponse, error)

	// Remove deletes a kid entry. Removing an absent kid is not an error.
	Remove(ctx context.Context, req *RemoveKidRequest) (*RemoveKidResponse, error)

	// CleanExpired removes all entries whose expiry has passed.
	CleanExpired(ctx context.Context, req *CleanExpiredRequest) (*CleanExpiredResponse, error)
}

// KidStore is an in-memory KidStorage that tracks kid→key mappings,
// including grace-period entries retained during key rotation.
//
// Usage during rotation:
//  1. kidStore.Add(ctx, &AddKidRequest{Kid: oldKid, Key: oldKey, Algorithm: alg, ClientID: clientID, ExpiresAt: time.Now().Add(gracePeriod)})
//  2. keyStorage.PutKey(ctx, &PutKeyRequest{Record: newRecord})  // overwrites current
//  3. kidStore holds the old key until grace period expires
type KidStore struct {
	mu      sync.RWMutex
	records map[string]*kidRecord // kid -> record
}

var _ KidStorage = (*KidStore)(nil)

// NewKidStore creates a new empty KidStore.
func NewKidStore() *KidStore {
	return &KidStore{
		records: make(map[string]*kidRecord),
	}
}

// Add registers a kid→key mapping. If req.ExpiresAt is zero, the key has no expiry.
func (s *KidStore) Add(ctx context.Context, req *AddKidRequest) (*AddKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("Add: req is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[req.Kid] = &kidRecord{
		Key:       req.Key,
		Algorithm: req.Algorithm,
		ClientID:  req.ClientID,
		ExpiresAt: req.ExpiresAt,
	}
	return &AddKidResponse{}, nil
}

// Remove deletes a kid entry. Removing an absent kid is not an error.
func (s *KidStore) Remove(ctx context.Context, req *RemoveKidRequest) (*RemoveKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("Remove: req is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, req.Kid)
	return &RemoveKidResponse{}, nil
}

// GetKey always returns ErrKeyNotFound — KidStore only supports kid-based lookup.
func (s *KidStore) GetKey(ctx context.Context, req *GetKeyRequest) (*GetKeyResponse, error) {
	return nil, ErrKeyNotFound
}

// GetKeyByKid returns the key record for the given kid.
// Returns ErrKidNotFound if the kid is unknown or expired.
func (s *KidStore) GetKeyByKid(ctx context.Context, req *GetKeyByKidRequest) (*GetKeyByKidResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetKeyByKid: req is required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, ok := s.records[req.Kid]
	if !ok || rec.isExpired() {
		return nil, ErrKidNotFound
	}
	return &GetKeyByKidResponse{Record: &KeyRecord{
		ClientID:  rec.ClientID,
		Key:       rec.Key,
		Algorithm: rec.Algorithm,
		Kid:       req.Kid,
	}}, nil
}

// CleanExpired removes all expired entries.
func (s *KidStore) CleanExpired(ctx context.Context, req *CleanExpiredRequest) (*CleanExpiredResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for kid, rec := range s.records {
		if rec.isExpired() {
			delete(s.records, kid)
			removed++
		}
	}
	return &CleanExpiredResponse{Removed: removed}, nil
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
func (c *CompositeKeyLookup) GetKey(ctx context.Context, req *GetKeyRequest) (*GetKeyResponse, error) {
	for _, l := range c.Lookups {
		resp, err := l.GetKey(ctx, req)
		if err == nil {
			return resp, nil
		}
	}
	return nil, ErrKeyNotFound
}

// GetKeyByKid tries each lookup in order for a kid match.
func (c *CompositeKeyLookup) GetKeyByKid(ctx context.Context, req *GetKeyByKidRequest) (*GetKeyByKidResponse, error) {
	for _, l := range c.Lookups {
		resp, err := l.GetKeyByKid(ctx, req)
		if err == nil {
			return resp, nil
		}
	}
	return nil, ErrKidNotFound
}
