package fs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/panyam/oneauth/accounts"
)

// FSUsername represents a username reservation stored as JSON
type FSUsername struct {
	NormalizedUsername string    `json:"normalized_username"`
	Username           string    `json:"username"`
	UserID             string    `json:"user_id"`
	Version            int       `json:"version"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// FSUsernameStore implements accounts.UsernameStore using filesystem storage.
type FSUsernameStore struct {
	StoragePath string
}

func NewFSUsernameStore(storagePath string) *FSUsernameStore {
	return &FSUsernameStore{StoragePath: storagePath}
}

func (s *FSUsernameStore) normalizeUsername(username string) string {
	return strings.ToLower(username)
}

func (s *FSUsernameStore) getUsernamePath(normalizedUsername string) (string, error) {
	safe, err := safeName(normalizedUsername)
	if err != nil {
		return "", fmt.Errorf("invalid username: %w", err)
	}
	return filepath.Join(s.StoragePath, "usernames", safe+".json"), nil
}

func (s *FSUsernameStore) readUsername(normalizedUsername string) (*FSUsername, error) {
	path, err := s.getUsernamePath(normalizedUsername)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var username FSUsername
	if err := json.Unmarshal(data, &username); err != nil {
		return nil, err
	}
	return &username, nil
}

func (s *FSUsernameStore) writeUsername(username *FSUsername) error {
	path, err := s.getUsernamePath(username.NormalizedUsername)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(username, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicFile(path, data)
}

func (s *FSUsernameStore) ReserveUsername(ctx context.Context, req *accounts.ReserveUsernameRequest) (*accounts.ReserveUsernameResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("ReserveUsername: req is required")
	}
	normalized := s.normalizeUsername(req.Username)

	existing, err := s.readUsername(normalized)
	if err != nil {
		return nil, err
	}

	if existing != nil {
		if existing.UserID == req.UserID {
			if existing.Username != req.Username {
				existing.Username = req.Username
				existing.Version++
				existing.UpdatedAt = time.Now()
				if err := s.writeUsername(existing); err != nil {
					return nil, err
				}
			}
			return &accounts.ReserveUsernameResponse{}, nil
		}
		return nil, fmt.Errorf("username already taken")
	}

	now := time.Now()
	record := &FSUsername{
		NormalizedUsername: normalized,
		Username:           req.Username,
		UserID:             req.UserID,
		Version:            1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := s.writeUsername(record); err != nil {
		return nil, err
	}
	return &accounts.ReserveUsernameResponse{}, nil
}

func (s *FSUsernameStore) GetUserByUsername(ctx context.Context, req *accounts.GetUserByUsernameRequest) (*accounts.GetUserByUsernameResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetUserByUsername: req is required")
	}
	normalized := s.normalizeUsername(req.Username)
	record, err := s.readUsername(normalized)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, fmt.Errorf("username not found")
	}
	return &accounts.GetUserByUsernameResponse{UserID: record.UserID}, nil
}

func (s *FSUsernameStore) ReleaseUsername(ctx context.Context, req *accounts.ReleaseUsernameRequest) (*accounts.ReleaseUsernameResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("ReleaseUsername: req is required")
	}
	normalized := s.normalizeUsername(req.Username)
	path, err := s.getUsernamePath(normalized)
	if err != nil {
		return nil, err
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return &accounts.ReleaseUsernameResponse{}, nil
}

func (s *FSUsernameStore) ChangeUsername(ctx context.Context, req *accounts.ChangeUsernameRequest) (*accounts.ChangeUsernameResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("ChangeUsername: req is required")
	}
	oldNormalized := s.normalizeUsername(req.OldUsername)
	newNormalized := s.normalizeUsername(req.NewUsername)

	if oldNormalized == newNormalized {
		existing, err := s.readUsername(oldNormalized)
		if err != nil {
			return nil, err
		}
		if existing == nil {
			return nil, fmt.Errorf("username not found")
		}
		if existing.UserID != req.UserID {
			return nil, fmt.Errorf("username not owned by user")
		}
		existing.Username = req.NewUsername
		existing.Version++
		existing.UpdatedAt = time.Now()
		if err := s.writeUsername(existing); err != nil {
			return nil, err
		}
		return &accounts.ChangeUsernameResponse{}, nil
	}

	oldRecord, err := s.readUsername(oldNormalized)
	if err != nil {
		return nil, err
	}
	if oldRecord == nil {
		return nil, fmt.Errorf("old username not found")
	}
	if oldRecord.UserID != req.UserID {
		return nil, fmt.Errorf("old username not owned by user")
	}

	newRecord, err := s.readUsername(newNormalized)
	if err != nil {
		return nil, err
	}
	if newRecord != nil {
		return nil, fmt.Errorf("new username already taken")
	}

	oldPath, err := s.getUsernamePath(oldNormalized)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(oldPath); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	now := time.Now()
	newRecord = &FSUsername{
		NormalizedUsername: newNormalized,
		Username:           req.NewUsername,
		UserID:             req.UserID,
		Version:            1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := s.writeUsername(newRecord); err != nil {
		oldRecord.Version++
		oldRecord.UpdatedAt = time.Now()
		_ = s.writeUsername(oldRecord)
		return nil, fmt.Errorf("failed to create new username: %w", err)
	}

	return &accounts.ChangeUsernameResponse{}, nil
}
