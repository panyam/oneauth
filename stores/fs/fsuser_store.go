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

// FSUser implements the accounts.User interface
type FSUser struct {
	UserId      string         `json:"user_id"`
	IsActive    bool           `json:"is_active"`
	UserProfile map[string]any `json:"profile"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

func (u *FSUser) Id() string { return u.UserId }

func fsUserID(u *FSUser) string           { return u.UserId }
func (u *FSUser) Profile() map[string]any { return u.UserProfile }

// LastUpdated reports when the user record last changed, which
// localauth.ProfileClaims returns as OIDC's updated_at claim. It
// implements accounts.LastUpdatedUser.
func (u *FSUser) LastUpdated() time.Time { return u.UpdatedAt }

// FSUserStore stores users as JSON files
type FSUserStore struct {
	StoragePath string
}

func NewFSUserStore(storagePath string) *FSUserStore {
	return &FSUserStore{StoragePath: storagePath}
}

func (s *FSUserStore) getUserPath(userId string) (string, error) {
	safeID, err := safeName(userId)
	if err != nil {
		return "", fmt.Errorf("invalid userId: %w", err)
	}
	return filepath.Join(s.StoragePath, "users", safeID+".json"), nil
}

func (s *FSUserStore) CreateUser(ctx context.Context, req *accounts.CreateUserRequest) (*accounts.CreateUserResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("CreateUser: req is required")
	}
	user := &FSUser{
		UserId:      req.UserID,
		IsActive:    req.IsActive,
		UserProfile: req.Profile,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if _, err := s.SaveUser(ctx, &accounts.SaveUserRequest{User: user}); err != nil {
		return nil, err
	}
	return &accounts.CreateUserResponse{User: user}, nil
}

func (s *FSUserStore) GetUserById(ctx context.Context, req *accounts.GetUserByIDRequest) (*accounts.GetUserByIDResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetUserById: req is required")
	}
	path, err := s.getUserPath(req.UserID)
	if err != nil {
		return nil, err
	}
	user, err := readKeyed(path, req.UserID, fsUserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("user not found: %s", req.UserID)
	}
	return &accounts.GetUserByIDResponse{User: user}, nil
}

func (s *FSUserStore) SaveUser(ctx context.Context, req *accounts.SaveUserRequest) (*accounts.SaveUserResponse, error) {
	if req == nil || req.User == nil {
		return nil, fmt.Errorf("SaveUser: req.User is required")
	}
	user := req.User
	fsUser, ok := user.(*FSUser)
	if !ok {
		fsUser = &FSUser{
			UserId:      user.Id(),
			UserProfile: user.Profile(),
			UpdatedAt:   time.Now(),
		}
		if createdAt, ok := user.Profile()["created_at"].(time.Time); ok {
			fsUser.CreatedAt = createdAt
		} else {
			fsUser.CreatedAt = time.Now()
		}
	} else {
		fsUser.UpdatedAt = time.Now()
	}

	path, err := s.getUserPath(fsUser.UserId)
	if err != nil {
		return nil, err
	}
	if err := checkOwner(path, fsUser.UserId, fsUserID); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	data, err := json.MarshalIndent(fsUser, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeAtomicFile(path, data); err != nil {
		return nil, err
	}
	return &accounts.SaveUserResponse{}, nil
}
