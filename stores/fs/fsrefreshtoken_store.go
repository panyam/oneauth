package fs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/panyam/oneauth/core"
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

func (s *FSRefreshTokenStore) getTokenDir() string {
	return filepath.Join(s.StoragePath, "refresh_tokens")
}

func (s *FSRefreshTokenStore) getTokenPath(token string) string {
	hash := sha256.Sum256([]byte(token))
	filename := hex.EncodeToString(hash[:]) + ".json"
	return filepath.Join(s.getTokenDir(), filename)
}

func (s *FSRefreshTokenStore) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *FSRefreshTokenStore) CreateRefreshToken(ctx context.Context, req *core.CreateRefreshTokenRequest) (*core.CreateRefreshTokenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, err := core.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	family, err := core.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	refreshToken := &core.RefreshToken{
		Token:      token,
		TokenHash:  s.hashToken(token),
		Subject:    req.Subject,
		ClientID:   req.ClientID,
		DeviceInfo: req.DeviceInfo,
		Family:     family[:16],
		Generation: 1,
		Scopes:     req.Scopes,
		CreatedAt:  now,
		ExpiresAt:  now.Add(core.TokenExpiryRefreshToken),
		LastUsedAt: now,
		Revoked:    false,
	}

	if err := s.saveToken(refreshToken); err != nil {
		return nil, err
	}

	return &core.CreateRefreshTokenResponse{Token: refreshToken}, nil
}

func (s *FSRefreshTokenStore) saveToken(token *core.RefreshToken) error {
	path := s.getTokenPath(token.Token)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}

	return writeAtomicFile(path, data)
}

func (s *FSRefreshTokenStore) GetRefreshToken(ctx context.Context, req *core.GetRefreshTokenRequest) (*core.GetRefreshTokenResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rt, err := s.getTokenUnsafe(req.Token)
	if err != nil {
		return nil, err
	}
	return &core.GetRefreshTokenResponse{Token: rt}, nil
}

func (s *FSRefreshTokenStore) getTokenUnsafe(token string) (*core.RefreshToken, error) {
	path := s.getTokenPath(token)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, core.ErrTokenNotFound
		}
		return nil, err
	}

	var refreshToken core.RefreshToken
	if err := json.Unmarshal(data, &refreshToken); err != nil {
		return nil, err
	}

	return &refreshToken, nil
}

func (s *FSRefreshTokenStore) RotateRefreshToken(ctx context.Context, req *core.RotateRefreshTokenRequest) (*core.RotateRefreshTokenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	old, err := s.getTokenUnsafe(req.OldToken)
	if err != nil {
		return nil, err
	}

	if old.Revoked {
		return nil, core.ErrTokenReused
	}

	if old.IsExpired() {
		return nil, core.ErrTokenExpired
	}

	now := time.Now()
	old.Revoked = true
	old.RevokedAt = &now
	if err := s.saveToken(old); err != nil {
		return nil, err
	}

	newToken, err := core.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	refreshToken := &core.RefreshToken{
		Token:                newToken,
		TokenHash:            s.hashToken(newToken),
		Subject:              old.Subject,
		ClientID:             old.ClientID,
		DeviceInfo:           old.DeviceInfo,
		Family:               old.Family,
		Generation:           old.Generation + 1,
		Scopes:               old.Scopes,
		AuthorizationDetails: old.AuthorizationDetails,
		CreatedAt:            now,
		ExpiresAt:            now.Add(core.TokenExpiryRefreshToken),
		LastUsedAt:           now,
		Revoked:              false,
	}

	if err := s.saveToken(refreshToken); err != nil {
		return nil, err
	}

	return &core.RotateRefreshTokenResponse{Token: refreshToken}, nil
}

func (s *FSRefreshTokenStore) RevokeRefreshToken(ctx context.Context, req *core.RevokeRefreshTokenRequest) (*core.RevokeRefreshTokenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	refreshToken, err := s.getTokenUnsafe(req.Token)
	if err != nil {
		if err == core.ErrTokenNotFound {
			return &core.RevokeRefreshTokenResponse{}, nil
		}
		return nil, err
	}

	if refreshToken.Revoked {
		return &core.RevokeRefreshTokenResponse{}, nil
	}

	now := time.Now()
	refreshToken.Revoked = true
	refreshToken.RevokedAt = &now
	if err := s.saveToken(refreshToken); err != nil {
		return nil, err
	}
	return &core.RevokeRefreshTokenResponse{}, nil
}

func (s *FSRefreshTokenStore) RevokeSubjectTokens(ctx context.Context, req *core.RevokeSubjectTokensRequest) (*core.RevokeSubjectTokensResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.forEachToken(func(token *core.RefreshToken, path string) error {
		if token.Subject == req.Subject && !token.Revoked {
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
	}); err != nil {
		return nil, err
	}
	return &core.RevokeSubjectTokensResponse{}, nil
}

func (s *FSRefreshTokenStore) RevokeTokenFamily(ctx context.Context, req *core.RevokeTokenFamilyRequest) (*core.RevokeTokenFamilyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.forEachToken(func(token *core.RefreshToken, path string) error {
		if token.Family == req.Family && !token.Revoked {
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
	}); err != nil {
		return nil, err
	}
	return &core.RevokeTokenFamilyResponse{}, nil
}

func (s *FSRefreshTokenStore) GetSubjectTokens(ctx context.Context, req *core.GetSubjectTokensRequest) (*core.GetSubjectTokensResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var tokens []*core.RefreshToken
	err := s.forEachToken(func(token *core.RefreshToken, path string) error {
		if token.Subject == req.Subject && token.IsValid() {
			tokenCopy := *token
			tokenCopy.Token = ""
			tokens = append(tokens, &tokenCopy)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &core.GetSubjectTokensResponse{Tokens: tokens}, nil
}

func (s *FSRefreshTokenStore) CleanupExpiredTokens(ctx context.Context, req *core.CleanupExpiredTokensRequest) (*core.CleanupExpiredTokensResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tokensDir := s.getTokenDir()
	entries, err := os.ReadDir(tokensDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &core.CleanupExpiredTokensResponse{}, nil
		}
		return nil, err
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

		var token core.RefreshToken
		if err := json.Unmarshal(data, &token); err != nil {
			continue
		}

		if token.IsExpired() || (token.Revoked && token.RevokedAt != nil && time.Since(*token.RevokedAt) > 24*time.Hour) {
			_ = os.Remove(path)
		}
	}

	return &core.CleanupExpiredTokensResponse{}, nil
}

func (s *FSRefreshTokenStore) forEachToken(fn func(token *core.RefreshToken, path string) error) error {
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

		var token core.RefreshToken
		if err := json.Unmarshal(data, &token); err != nil {
			continue
		}

		if err := fn(&token, path); err != nil {
			return err
		}
	}

	return nil
}
