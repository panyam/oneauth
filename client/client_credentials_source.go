package client

import (
	"fmt"
	"sync"
	"time"

	"github.com/panyam/oneauth/core"
)

// tokenExpiryBuffer is subtracted from token expiry times to account for
// clock skew and network latency. Without this, tokens could expire between
// the freshness check and the server receiving the request.
const tokenExpiryBuffer = 30 * time.Second

// TokenSource provides OAuth2 access tokens. This interface matches
// mcpkit/core.TokenSource by structural typing — no cross-module import needed.
type TokenSource interface {
	Token() (string, error)
}

// ScopeAwareTokenSource extends TokenSource with scope step-up capability.
// When additional scopes are required, the cached token is invalidated and
// a new token is obtained with the merged scope set.
type ScopeAwareTokenSource interface {
	TokenSource
	TokenForScopes(scopes []string) (string, error)
}

// ClientCredentialsSource implements TokenSource for machine-to-machine auth
// using the OAuth 2.0 client_credentials grant (RFC 6749 §4.4).
//
// It caches the access token and automatically refreshes it when expired.
// TokenForScopes supports scope step-up by merging additional scopes and
// invalidating the cache.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
type ClientCredentialsSource struct {
	// TokenEndpoint is the authorization server's token URL.
	TokenEndpoint string

	// ClientID identifies this client to the authorization server.
	ClientID string

	// ClientSecret authenticates this client.
	ClientSecret string

	// Scopes to request.
	Scopes []string

	// Audience is the resource server's canonical URI (RFC 8707 resource indicator).
	Audience string

	mu     sync.Mutex
	client *AuthClient
	token  string
	expiry time.Time
}

// Token returns a cached access token if still valid, or fetches a new one
// via the client_credentials grant.
func (s *ClientCredentialsSource) Token() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Now().Add(tokenExpiryBuffer).Before(s.expiry) {
		return s.token, nil
	}

	if s.client == nil {
		s.client = NewAuthClient(s.TokenEndpoint, nil,
			WithASMetadata(&ASMetadata{TokenEndpoint: s.TokenEndpoint}))
	}

	cred, err := s.client.ClientCredentialsToken(s.ClientID, s.ClientSecret, s.Scopes)
	if err != nil {
		return "", fmt.Errorf("client credentials: %w", err)
	}

	s.token = cred.AccessToken
	s.expiry = cred.ExpiresAt
	return s.token, nil
}

// TokenForScopes invalidates the cached token, merges the requested scopes
// with the existing scope set (using core.UnionScopes), and fetches a fresh
// token with the combined scopes.
func (s *ClientCredentialsSource) TokenForScopes(scopes []string) (string, error) {
	s.mu.Lock()
	s.token = ""
	s.expiry = time.Time{}
	s.Scopes = core.UnionScopes(s.Scopes, scopes)
	s.mu.Unlock()

	return s.Token()
}
