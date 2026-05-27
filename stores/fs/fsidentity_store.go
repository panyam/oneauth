package fs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/panyam/oneauth/accounts"
)

// FSIdentityStore stores identities as JSON files
type FSIdentityStore struct {
	StoragePath string
}

func NewFSIdentityStore(storagePath string) *FSIdentityStore {
	return &FSIdentityStore{StoragePath: storagePath}
}

func (s *FSIdentityStore) getIdentityPath(identityType, identityValue string) string {
	key := accounts.IdentityKey(identityType, identityValue)
	safeKey := filepath.Base(key)
	return filepath.Join(s.StoragePath, "identities", safeKey+".json")
}

func (s *FSIdentityStore) GetIdentity(ctx context.Context, req *accounts.GetIdentityRequest) (*accounts.GetIdentityResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetIdentity: req is required")
	}
	path := s.getIdentityPath(req.IdentityType, req.IdentityValue)
	data, err := os.ReadFile(path)

	if err != nil {
		if os.IsNotExist(err) && req.CreateIfMissing {
			now := time.Now()
			identity := &accounts.Identity{
				Type:      req.IdentityType,
				Value:     req.IdentityValue,
				UserID:    "",
				Verified:  false,
				CreatedAt: now,
				UpdatedAt: now,
				Version:   1,
			}
			if _, err := s.SaveIdentity(ctx, &accounts.SaveIdentityRequest{Identity: identity}); err != nil {
				return nil, err
			}
			return &accounts.GetIdentityResponse{Identity: identity, NewCreated: true}, nil
		}
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("identity not found")
		}
		return nil, err
	}

	var identity accounts.Identity
	if err := json.Unmarshal(data, &identity); err != nil {
		return nil, err
	}
	return &accounts.GetIdentityResponse{Identity: &identity}, nil
}

func (s *FSIdentityStore) SaveIdentity(ctx context.Context, req *accounts.SaveIdentityRequest) (*accounts.SaveIdentityResponse, error) {
	if req == nil || req.Identity == nil {
		return nil, fmt.Errorf("SaveIdentity: req.Identity is required")
	}
	identity := req.Identity
	path := s.getIdentityPath(identity.Type, identity.Value)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeAtomicFile(path, data); err != nil {
		return nil, err
	}
	return &accounts.SaveIdentityResponse{}, nil
}

func (s *FSIdentityStore) SetUserForIdentity(ctx context.Context, req *accounts.SetUserForIdentityRequest) (*accounts.SetUserForIdentityResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("SetUserForIdentity: req is required")
	}
	resp, err := s.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: req.IdentityType, IdentityValue: req.IdentityValue})
	if err != nil {
		return nil, err
	}
	identity := resp.Identity
	identity.UserID = req.NewUserID
	identity.UpdatedAt = time.Now()
	identity.Version++
	if _, err := s.SaveIdentity(ctx, &accounts.SaveIdentityRequest{Identity: identity}); err != nil {
		return nil, err
	}
	return &accounts.SetUserForIdentityResponse{}, nil
}

func (s *FSIdentityStore) MarkIdentityVerified(ctx context.Context, req *accounts.MarkIdentityVerifiedRequest) (*accounts.MarkIdentityVerifiedResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("MarkIdentityVerified: req is required")
	}
	resp, err := s.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: req.IdentityType, IdentityValue: req.IdentityValue})
	if err != nil {
		return nil, err
	}
	identity := resp.Identity
	identity.Verified = true
	identity.UpdatedAt = time.Now()
	identity.Version++
	if _, err := s.SaveIdentity(ctx, &accounts.SaveIdentityRequest{Identity: identity}); err != nil {
		return nil, err
	}
	return &accounts.MarkIdentityVerifiedResponse{}, nil
}

func (s *FSIdentityStore) GetUserIdentities(ctx context.Context, req *accounts.GetUserIdentitiesRequest) (*accounts.GetUserIdentitiesResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetUserIdentities: req is required")
	}
	identitiesDir := filepath.Join(s.StoragePath, "identities")
	entries, err := os.ReadDir(identitiesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &accounts.GetUserIdentitiesResponse{Identities: []*accounts.Identity{}}, nil
		}
		return nil, err
	}

	var identities []*accounts.Identity
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(identitiesDir, entry.Name()))
		if err != nil {
			continue
		}
		var identity accounts.Identity
		if err := json.Unmarshal(data, &identity); err != nil {
			continue
		}
		if identity.UserID == req.UserID {
			identities = append(identities, &identity)
		}
	}
	return &accounts.GetUserIdentitiesResponse{Identities: identities}, nil
}
