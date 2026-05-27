package fs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/localauth"
)

// FSTokenStore stores localauth verification and reset tokens as JSON files.
// Satisfies localauth.VerificationTokenStore.
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

func (s *FSTokenStore) CreateToken(ctx context.Context, req *localauth.CreateVerificationTokenRequest) (*localauth.CreateVerificationTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("CreateToken: req is required")
	}
	token, err := core.GenerateSecureToken()
	if err != nil {
		return nil, err
	}

	verToken := &localauth.VerificationToken{
		Token:     token,
		Type:      req.Type,
		Subject:   req.Subject,
		Email:     req.Email,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(req.ExpiryDuration),
	}

	path, err := s.getTokenPath(token)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	data, err := json.MarshalIndent(verToken, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := writeAtomicFile(path, data); err != nil {
		return nil, err
	}

	return &localauth.CreateVerificationTokenResponse{Token: verToken}, nil
}

func (s *FSTokenStore) GetToken(ctx context.Context, req *localauth.GetVerificationTokenRequest) (*localauth.GetVerificationTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("GetToken: req is required")
	}
	path, err := s.getTokenPath(req.Token)
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

	var verToken localauth.VerificationToken
	if err := json.Unmarshal(data, &verToken); err != nil {
		return nil, err
	}

	if verToken.IsExpired() {
		_, _ = s.DeleteToken(ctx, &localauth.DeleteVerificationTokenRequest{Token: req.Token})
		return nil, fmt.Errorf("token expired")
	}

	return &localauth.GetVerificationTokenResponse{Token: &verToken}, nil
}

func (s *FSTokenStore) DeleteToken(ctx context.Context, req *localauth.DeleteVerificationTokenRequest) (*localauth.DeleteVerificationTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("DeleteToken: req is required")
	}
	path, err := s.getTokenPath(req.Token)
	if err != nil {
		return nil, err
	}
	err = os.Remove(path)
	if os.IsNotExist(err) {
		return &localauth.DeleteVerificationTokenResponse{}, nil
	}
	if err != nil {
		return nil, err
	}
	return &localauth.DeleteVerificationTokenResponse{}, nil
}

func (s *FSTokenStore) DeleteSubjectTokens(ctx context.Context, req *localauth.DeleteSubjectVerificationTokensRequest) (*localauth.DeleteSubjectVerificationTokensResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("DeleteSubjectTokens: req is required")
	}
	tokensDir := filepath.Join(s.StoragePath, "tokens")
	entries, err := os.ReadDir(tokensDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &localauth.DeleteSubjectVerificationTokensResponse{}, nil
		}
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(tokensDir, entry.Name()))
		if err != nil {
			continue
		}

		var verToken localauth.VerificationToken
		if err := json.Unmarshal(data, &verToken); err != nil {
			continue
		}

		if verToken.Subject == req.Subject && verToken.Type == req.Type {
			_ = os.Remove(filepath.Join(tokensDir, entry.Name()))
		}
	}

	return &localauth.DeleteSubjectVerificationTokensResponse{}, nil
}
