package fs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	oa "github.com/panyam/oneauth"
)

// FSRefreshTokenStore stores refresh tokens as JSON files
type FSRefreshTokenStore struct {
	StoragePath string
	mu          sync.RWMutex
}

// NewFSRefreshTokenStore creates a new file-based refresh token store
func NewFSRefreshTokenStore(storagePath string) *FSRefreshTokenStore {
	return &FSRefreshTokenStore{StoragePath: storagePath}
}

// getTokenDir returns the directory for refresh tokens
func (s *FSRefreshTokenStore) getTokenDir() string {
	return filepath.Join(s.StoragePath, "refresh_tokens")
}

// getTokenPath returns the file path for a token (using hash of token for filename)
func (s *FSRefreshTokenStore) getTokenPath(token string) string {
	hash := sha256.Sum256([]byte(token))
	filename := hex.EncodeToString(hash[:]) + ".json"
	return filepath.Join(s.getTokenDir(), filename)
}

// CreateRefreshToken creates a new refresh token for a user
func (s *FSRefreshTokenStore) CreateRefreshToken(userID, clientID string, deviceInfo map[string]any, scopes []string) (*oa.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, err := oa.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	family, err := oa.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	refreshToken := &oa.RefreshToken{
		Token:      token,
		TokenHash:  s.hashToken(token),
		UserID:     userID,
		ClientID:   clientID,
		DeviceInfo: deviceInfo,
		Family:     family[:16], // Use first 16 chars as family ID
		Generation: 1,
		Scopes:     scopes,
		CreatedAt:  now,
		ExpiresAt:  now.Add(oa.TokenExpiryRefreshToken),
		LastUsedAt: now,
		Revoked:    false,
	}

	if err := s.saveToken(refreshToken); err != nil {
		return nil, err
	}

	return refreshToken, nil
}

// hashToken creates a SHA256 hash of the token for storage
func (s *FSRefreshTokenStore) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// saveToken saves a refresh token to disk
func (s *FSRefreshTokenStore) saveToken(token *oa.RefreshToken) error {
	path := s.getTokenPath(token.Token)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}

	return writeAtomicFile(path, data)
}

// GetRefreshToken retrieves a refresh token by its value
func (s *FSRefreshTokenStore) GetRefreshToken(token string) (*oa.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.getTokenUnsafe(token)
}

// getTokenUnsafe retrieves a token without locking (caller must hold lock)
func (s *FSRefreshTokenStore) getTokenUnsafe(token string) (*oa.RefreshToken, error) {
	path := s.getTokenPath(token)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, oa.ErrTokenNotFound
		}
		return nil, err
	}

	var refreshToken oa.RefreshToken
	if err := json.Unmarshal(data, &refreshToken); err != nil {
		return nil, err
	}

	return &refreshToken, nil
}

// RotateRefreshToken invalidates old token and creates new one in same family
// Returns ErrTokenReused if the old token was already revoked (theft detection)
func (s *FSRefreshTokenStore) RotateRefreshToken(oldToken string) (*oa.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get the old token
	old, err := s.getTokenUnsafe(oldToken)
	if err != nil {
		return nil, err
	}

	// Check if already revoked (token reuse attack detection)
	if old.Revoked {
		return nil, oa.ErrTokenReused
	}

	// Check if expired
	if old.IsExpired() {
		return nil, oa.ErrTokenExpired
	}

	// Mark old token as revoked
	now := time.Now()
	old.Revoked = true
	old.RevokedAt = &now
	if err := s.saveToken(old); err != nil {
		return nil, err
	}

	// Create new token in same family
	newToken, err := oa.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	refreshToken := &oa.RefreshToken{
		Token:      newToken,
		TokenHash:  s.hashToken(newToken),
		UserID:     old.UserID,
		ClientID:   old.ClientID,
		DeviceInfo: old.DeviceInfo,
		Family:     old.Family,
		Generation: old.Generation + 1,
		Scopes:     old.Scopes,
		CreatedAt:  now,
		ExpiresAt:  now.Add(oa.TokenExpiryRefreshToken),
		LastUsedAt: now,
		Revoked:    false,
	}

	if err := s.saveToken(refreshToken); err != nil {
		return nil, err
	}

	return refreshToken, nil
}

// RevokeRefreshToken marks a token as revoked
func (s *FSRefreshTokenStore) RevokeRefreshToken(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	refreshToken, err := s.getTokenUnsafe(token)
	if err != nil {
		if err == oa.ErrTokenNotFound {
			return nil // Already gone
		}
		return err
	}

	if refreshToken.Revoked {
		return nil // Already revoked
	}

	now := time.Now()
	refreshToken.Revoked = true
	refreshToken.RevokedAt = &now
	return s.saveToken(refreshToken)
}

// RevokeUserTokens revokes all refresh tokens for a user
func (s *FSRefreshTokenStore) RevokeUserTokens(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.forEachToken(func(token *oa.RefreshToken, path string) error {
		if token.UserID == userID && !token.Revoked {
			now := time.Now()
			token.Revoked = true
			token.RevokedAt = &now
			data, err := json.MarshalIndent(token, "", "  ")
			if err != nil {
				return err
			}
			return writeAtomicFile(path, data)
		}
		return nil
	})
}

// RevokeTokenFamily revokes all tokens in a family (theft detection)
func (s *FSRefreshTokenStore) RevokeTokenFamily(family string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.forEachToken(func(token *oa.RefreshToken, path string) error {
		if token.Family == family && !token.Revoked {
			now := time.Now()
			token.Revoked = true
			token.RevokedAt = &now
			data, err := json.MarshalIndent(token, "", "  ")
			if err != nil {
				return err
			}
			return writeAtomicFile(path, data)
		}
		return nil
	})
}

// GetUserTokens lists all active (non-revoked, non-expired) refresh tokens for a user
func (s *FSRefreshTokenStore) GetUserTokens(userID string) ([]*oa.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var tokens []*oa.RefreshToken
	err := s.forEachToken(func(token *oa.RefreshToken, path string) error {
		if token.UserID == userID && token.IsValid() {
			// Don't include the actual token value for security
			tokenCopy := *token
			tokenCopy.Token = "" // Clear token value
			tokens = append(tokens, &tokenCopy)
		}
		return nil
	})

	return tokens, err
}

// CleanupExpiredTokens removes expired tokens (for maintenance)
func (s *FSRefreshTokenStore) CleanupExpiredTokens() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tokensDir := s.getTokenDir()
	entries, err := os.ReadDir(tokensDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(tokensDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var token oa.RefreshToken
		if err := json.Unmarshal(data, &token); err != nil {
			continue
		}

		// Remove if expired or revoked more than 24 hours ago
		if token.IsExpired() || (token.Revoked && token.RevokedAt != nil && time.Since(*token.RevokedAt) > 24*time.Hour) {
			_ = os.Remove(path)
		}
	}

	return nil
}

// forEachToken iterates over all tokens in the store
func (s *FSRefreshTokenStore) forEachToken(fn func(token *oa.RefreshToken, path string) error) error {
	tokensDir := s.getTokenDir()
	entries, err := os.ReadDir(tokensDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(tokensDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var token oa.RefreshToken
		if err := json.Unmarshal(data, &token); err != nil {
			continue
		}

		if err := fn(&token, path); err != nil {
			return err
		}
	}

	return nil
}
