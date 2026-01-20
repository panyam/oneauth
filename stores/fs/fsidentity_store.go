package fs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	oa "github.com/panyam/oneauth"
)

// FSIdentityStore stores identities as JSON files
type FSIdentityStore struct {
	StoragePath string
}

func NewFSIdentityStore(storagePath string) *FSIdentityStore {
	return &FSIdentityStore{StoragePath: storagePath}
}

func (s *FSIdentityStore) getIdentityPath(identityType, identityValue string) string {
	key := oa.IdentityKey(identityType, identityValue)
	// Use safe filename
	safeKey := filepath.Base(key) // prevents path traversal
	return filepath.Join(s.StoragePath, "identities", safeKey+".json")
}

func (s *FSIdentityStore) GetIdentity(identityType, identityValue string, createIfMissing bool) (*oa.Identity, bool, error) {
	path := s.getIdentityPath(identityType, identityValue)
	data, err := os.ReadFile(path)

	if err != nil {
		if os.IsNotExist(err) && createIfMissing {
			now := time.Now()
			identity := &oa.Identity{
				Type:      identityType,
				Value:     identityValue,
				UserID:    "", // Not assigned yet
				Verified:  false,
				CreatedAt: now,
				UpdatedAt: now,
				Version:   1,
			}
			if err := s.SaveIdentity(identity); err != nil {
				return nil, false, err
			}
			return identity, true, nil
		}
		if os.IsNotExist(err) {
			return nil, false, fmt.Errorf("identity not found")
		}
		return nil, false, err
	}

	var identity oa.Identity
	if err := json.Unmarshal(data, &identity); err != nil {
		return nil, false, err
	}
	return &identity, false, nil
}

func (s *FSIdentityStore) SaveIdentity(identity *oa.Identity) error {
	path := s.getIdentityPath(identity.Type, identity.Value)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return err
	}

	return writeAtomicFile(path, data)
}

func (s *FSIdentityStore) SetUserForIdentity(identityType, identityValue string, newUserId string) error {
	identity, _, err := s.GetIdentity(identityType, identityValue, false)
	if err != nil {
		return err
	}

	identity.UserID = newUserId
	identity.UpdatedAt = time.Now()
	identity.Version++
	return s.SaveIdentity(identity)
}

func (s *FSIdentityStore) MarkIdentityVerified(identityType, identityValue string) error {
	identity, _, err := s.GetIdentity(identityType, identityValue, false)
	if err != nil {
		return err
	}

	identity.Verified = true
	identity.UpdatedAt = time.Now()
	identity.Version++
	return s.SaveIdentity(identity)
}

func (s *FSIdentityStore) GetUserIdentities(userId string) ([]*oa.Identity, error) {
	identitiesDir := filepath.Join(s.StoragePath, "identities")
	entries, err := os.ReadDir(identitiesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*oa.Identity{}, nil
		}
		return nil, err
	}

	var identities []*oa.Identity
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(identitiesDir, entry.Name()))
		if err != nil {
			continue
		}

		var identity oa.Identity
		if err := json.Unmarshal(data, &identity); err != nil {
			continue
		}

		if identity.UserID == userId {
			identities = append(identities, &identity)
		}
	}

	return identities, nil
}
