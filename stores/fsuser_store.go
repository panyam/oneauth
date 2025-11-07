package stores

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	oa "github.com/panyam/oneauth"
)

// FSUser implements the oneauth.User interface
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

func (s *FSUserStore) getUserPath(userId string) string {
	return filepath.Join(s.StoragePath, "users", userId+".json")
}

func (s *FSUserStore) CreateUser(userId string, isActive bool, profile map[string]any) (oa.User, error) {
	user := &FSUser{
		UserId:      userId,
		IsActive:    isActive,
		UserProfile: profile,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	return user, s.SaveUser(user)
}

func (s *FSUserStore) GetUserById(userId string) (oa.User, error) {
	path := s.getUserPath(userId)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("user not found: %s", userId)
		}
		return nil, err
	}

	var user FSUser
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *FSUserStore) SaveUser(user oa.User) error {
	fsUser, ok := user.(*FSUser)
	if !ok {
		// Convert if it's a different implementation
		fsUser = &FSUser{
			UserId:      user.Id(),
			UserProfile: user.Profile(),
			UpdatedAt:   time.Now(),
		}
		// Try to preserve created_at if it exists in profile
		if createdAt, ok := user.Profile()["created_at"].(time.Time); ok {
			fsUser.CreatedAt = createdAt
		} else {
			fsUser.CreatedAt = time.Now()
		}
	} else {
		fsUser.UpdatedAt = time.Now()
	}

	path := s.getUserPath(fsUser.UserId)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(fsUser, "", "  ")
	if err != nil {
		return err
	}

	return writeAtomicFile(path, data)
}
