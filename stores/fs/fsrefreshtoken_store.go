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

// FSRefreshTokenStore implements core.RefreshTokenStore with one JSON file
// per refresh token, named by the SHA-256 of the token. One mutex guards
// every method, so each call is atomic against the others in this
// process. Two processes sharing StoragePath are not coordinated.
type FSRefreshTokenStore struct {
	StoragePath string
	mu          sync.RWMutex
}

// NewFSRefreshTokenStore returns a store that keeps its files under
// storagePath/refresh_tokens, creating the directory on first write.
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

// CreateRefreshToken mints a token that starts a new family at
// generation 1 and expires after core.TokenExpiryRefreshToken. The
// returned record carries the raw token. The file stores it too, under a
// name derived from its hash.
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
		Token:        token,
		TokenHash:    s.hashToken(token),
		Subject:      req.Subject,
		ClientID:     req.ClientID,
		DeviceInfo:   req.DeviceInfo,
		Family:       family[:16],
		Generation:   1,
		Scopes:       req.Scopes,
		Confirmation: req.Confirmation,
		OIDC:         req.OIDC,
		CreatedAt:    now,
		ExpiresAt:    now.Add(core.TokenExpiryRefreshToken),
		LastUsedAt:   now,
		Revoked:      false,
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

// GetRefreshToken returns the record for req.Token, revoked or expired
// ones included, so callers can tell reuse from an unknown token. A
// missing token is core.ErrTokenNotFound.
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

// RotateRefreshToken revokes req.OldToken and mints its successor in the
// same family at the next generation, under the store lock. The
// successor keeps the family's expiry, scopes, binding and OIDC grant.
// A missing token is core.ErrTokenNotFound, an already-revoked one is
// core.ErrTokenReused (the caller revokes the family), and an expired
// one is core.ErrTokenExpired.
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
		Confirmation:         old.Confirmation,
		OIDC:                 old.OIDC,
		CreatedAt:            now,
		ExpiresAt:            old.ExpiresAt, // the family's, not extended
		LastUsedAt:           now,
		Revoked:              false,
	}

	if err := s.saveToken(refreshToken); err != nil {
		return nil, err
	}

	return &core.RotateRefreshTokenResponse{Token: refreshToken}, nil
}

// RevokeRefreshToken marks one token revoked. It is idempotent: a token
// that is missing or already revoked is not an error. Its family and
// recorded access tokens are left alone; RevokeTokenFamily covers those.
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

// RevokeSubjectTokens revokes every live token of req.Subject and returns
// the unexpired access tokens recorded on any of them, revoked or not.
// It holds the store lock throughout, so it is atomic against
// RecordAccessToken.
func (s *FSRefreshTokenStore) RevokeSubjectTokens(ctx context.Context, req *core.RevokeSubjectTokensRequest) (*core.RevokeSubjectTokensResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	issued, err := s.revokeWhereUnsafe(func(t *core.RefreshToken) bool { return t.Subject == req.Subject })
	if err != nil {
		return nil, err
	}
	return &core.RevokeSubjectTokensResponse{AccessTokens: issued}, nil
}

// RecordAccessToken appends the access token to req.Token's record under
// the store lock, so it is atomic against RevokeTokenFamily. A missing
// token is core.ErrTokenNotFound.
func (s *FSRefreshTokenStore) RecordAccessToken(ctx context.Context, req *core.RecordAccessTokenRequest) (*core.RecordAccessTokenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rt, err := s.getTokenUnsafe(req.Token)
	if err != nil {
		return nil, err
	}
	rt.AccessTokens = core.AppendIssuedAccessToken(rt.AccessTokens,
		core.IssuedAccessToken{TokenID: req.TokenID, ExpiresAt: req.ExpiresAt}, time.Now())
	if err := s.saveToken(rt); err != nil {
		return nil, err
	}
	return &core.RecordAccessTokenResponse{Revoked: rt.Revoked}, nil
}

// RevokeTokenFamily revokes every live token in the family and returns
// the unexpired access tokens recorded on any of them, revoked or not.
func (s *FSRefreshTokenStore) RevokeTokenFamily(ctx context.Context, req *core.RevokeTokenFamilyRequest) (*core.RevokeTokenFamilyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	issued, err := s.revokeWhereUnsafe(func(t *core.RefreshToken) bool { return t.Family == req.Family })
	if err != nil {
		return nil, err
	}
	return &core.RevokeTokenFamilyResponse{AccessTokens: issued}, nil
}

// revokeWhereUnsafe revokes every live token match selects and returns
// the unexpired access tokens recorded on every selected token. The
// caller holds s.mu.
func (s *FSRefreshTokenStore) revokeWhereUnsafe(match func(*core.RefreshToken) bool) ([]core.IssuedAccessToken, error) {
	now := time.Now()
	var issued []core.IssuedAccessToken
	err := s.forEachToken(func(token *core.RefreshToken, path string) error {
		if !match(token) {
			return nil
		}
		issued = append(issued, core.LiveIssuedAccessTokens(token.AccessTokens, now)...)
		if token.Revoked {
			return nil
		}
		token.Revoked = true
		token.RevokedAt = &now
		data, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			return err
		}
		return writeAtomicFile(path, data)
	})
	return issued, err
}

// GetSubjectTokens lists req.Subject's tokens that are neither revoked
// nor expired. Each result has Token cleared, so a session listing can't
// leak a usable refresh token.
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

// CleanupExpiredTokens deletes the files of expired tokens, and of tokens
// revoked more than 24 hours ago. The grace period keeps a recently
// revoked token on disk, so presenting it again still reads as reuse
// rather than as an unknown token. Unreadable files are skipped.
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
