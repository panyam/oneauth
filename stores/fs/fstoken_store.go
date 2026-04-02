package fs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/panyam/oneauth/core"
)

// FSTokenStore stores verification and reset tokens as JSON files
type FSTokenStore struct {
	StoragePath string
}

func NewFSTokenStore(storagePath string) *FSTokenStore {
	return &FSTokenStore{StoragePath: storagePath}
}

func (s *FSTokenStore) getTokenPath(token string) (string, error) {
	safeToken, err := safeName(token)
	if err != nil {
		return "", fmt.Errorf("invalid token: %w", err)
	}
	return filepath.Join(s.StoragePath, "tokens", safeToken+".json"), nil
}

func (s *FSTokenStore) CreateToken(userID, email string, tokenType core.TokenType, expiryDuration time.Duration) (*core.AuthToken, error) {
	token, err := core.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	authToken := &core.AuthToken{
		Token:     token,
		Type:      tokenType,
		UserID:    userID,
		Email:     email,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(expiryDuration),
	}

	path, err := s.getTokenPath(token)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	data, err := json.MarshalIndent(authToken, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := writeAtomicFile(path, data); err != nil {
		return nil, err
	}

	return authToken, nil
}

func (s *FSTokenStore) GetToken(token string) (*core.AuthToken, error) {
	path, err := s.getTokenPath(token)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("token not found")
		}
		return nil, err
	}

	var authToken core.AuthToken
	if err := json.Unmarshal(data, &authToken); err != nil {
		return nil, err
	}

	// Check if token is expired
	if authToken.IsExpired() {
		// Auto-delete expired token
		_ = s.DeleteToken(token)
		return nil, fmt.Errorf("token expired")
	}

	return &authToken, nil
}

func (s *FSTokenStore) DeleteToken(token string) error {
	path, err := s.getTokenPath(token)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if os.IsNotExist(err) {
		return nil // Already deleted
	}
	return err
}

func (s *FSTokenStore) DeleteUserTokens(userID string, tokenType core.TokenType) error {
	tokensDir := filepath.Join(s.StoragePath, "tokens")
	entries, err := os.ReadDir(tokensDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(tokensDir, entry.Name()))
		if err != nil {
			continue
		}

		var authToken core.AuthToken
		if err := json.Unmarshal(data, &authToken); err != nil {
			continue
		}

		if authToken.UserID == userID && authToken.Type == tokenType {
			_ = os.Remove(filepath.Join(tokensDir, entry.Name()))
		}
	}

	return nil
}
