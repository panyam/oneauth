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

func (u *FSUser) Id() string              { return u.UserId }
func (u *FSUser) Profile() map[string]any { return u.UserProfile }

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
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("user not found: %s", req.UserID)
		}
		return nil, err
	}

	var user FSUser
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}
	return &accounts.GetUserByIDResponse{User: &user}, nil
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
