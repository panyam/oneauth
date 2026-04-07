package client

// Tests for the AuthClient core logic: credential expiration, token retrieval, login state, and URL normalization.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServerCredential_IsExpired verifies that IsExpired correctly identifies credentials past their expiration time.
func TestServerCredential_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "expired",
			expiresAt: time.Now().Add(-1 * time.Hour),
			want:      true,
		},
		{
			name:      "not expired",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      false,
		},
		{
			name:      "just expired",
			expiresAt: time.Now().Add(-1 * time.Second),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ServerCredential{ExpiresAt: tt.expiresAt}
			if got := c.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestServerCredential_IsExpiringSoon verifies that IsExpiringSoon detects credentials expiring within a given duration.
func TestServerCredential_IsExpiringSoon(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		within    time.Duration
		want      bool
	}{
		{
			name:      "expiring soon",
			expiresAt: time.Now().Add(2 * time.Minute),
			within:    5 * time.Minute,
			want:      true,
		},
		{
			name:      "not expiring soon",
			expiresAt: time.Now().Add(10 * time.Minute),
			within:    5 * time.Minute,
			want:      false,
		},
		{
			name:      "already expired",
			expiresAt: time.Now().Add(-1 * time.Minute),
			within:    5 * time.Minute,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ServerCredential{ExpiresAt: tt.expiresAt}
			if got := c.IsExpiringSoon(tt.within); got != tt.want {
				t.Errorf("IsExpiringSoon(%v) = %v, want %v", tt.within, got, tt.want)
			}
		})
	}
}

// TestServerCredential_HasRefreshToken verifies that HasRefreshToken returns true only when a non-empty refresh token is present.
func TestServerCredential_HasRefreshToken(t *testing.T) {
	tests := []struct {
		name         string
		refreshToken string
		want         bool
	}{
		{
			name:         "has refresh token",
			refreshToken: "abc123",
			want:         true,
		},
		{
			name:         "no refresh token",
			refreshToken: "",
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ServerCredential{RefreshToken: tt.refreshToken}
			if got := c.HasRefreshToken(); got != tt.want {
				t.Errorf("HasRefreshToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

// mockCredentialStore is a simple in-memory store for testing
type mockCredentialStore struct {
	creds map[string]*ServerCredential
}

func newMockCredentialStore() *mockCredentialStore {
	return &mockCredentialStore{creds: make(map[string]*ServerCredential)}
}

func (m *mockCredentialStore) GetCredential(serverURL string) (*ServerCredential, error) {
	return m.creds[serverURL], nil
}

func (m *mockCredentialStore) SetCredential(serverURL string, cred *ServerCredential) error {
	m.creds[serverURL] = cred
	return nil
}

func (m *mockCredentialStore) RemoveCredential(serverURL string) error {
	delete(m.creds, serverURL)
	return nil
}

func (m *mockCredentialStore) ListServers() ([]string, error) {
	servers := make([]string, 0, len(m.creds))
	for k := range m.creds {
		servers = append(servers, k)
	}
	return servers, nil
}

func (m *mockCredentialStore) Save() error {
	return nil
}

// TestAuthClient_GetToken_NoCredential verifies that GetToken returns an empty string when no credential is stored.
func TestAuthClient_GetToken_NoCredential(t *testing.T) {
	store := newMockCredentialStore()
	client := NewAuthClient("http://localhost:8080", store)

	token, err := client.GetToken()
	if err != nil {
		t.Errorf("GetToken() error = %v", err)
	}
	if token != "" {
		t.Errorf("GetToken() = %v, want empty string", token)
	}
}

// TestAuthClient_GetToken_ValidCredential verifies that GetToken returns the access token when a valid (non-expired) credential exists.
func TestAuthClient_GetToken_ValidCredential(t *testing.T) {
	store := newMockCredentialStore()
	store.creds["http://localhost:8080"] = &ServerCredential{
		AccessToken: "valid-token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	client := NewAuthClient("http://localhost:8080", store)

	token, err := client.GetToken()
	if err != nil {
		t.Errorf("GetToken() error = %v", err)
	}
	if token != "valid-token" {
		t.Errorf("GetToken() = %v, want valid-token", token)
	}
}

// TestAuthClient_GetToken_ExpiredCredential verifies that GetToken returns an empty string when the stored credential has expired.
func TestAuthClient_GetToken_ExpiredCredential(t *testing.T) {
	store := newMockCredentialStore()
	store.creds["http://localhost:8080"] = &ServerCredential{
		AccessToken: "expired-token",
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
	}

	client := NewAuthClient("http://localhost:8080", store)

	token, err := client.GetToken()
	if err != nil {
		t.Errorf("GetToken() error = %v", err)
	}
	if token != "" {
		t.Errorf("GetToken() = %v, want empty (expired)", token)
	}
}

// TestAuthClient_IsLoggedIn verifies that IsLoggedIn reflects the presence and validity of stored credentials.
func TestAuthClient_IsLoggedIn(t *testing.T) {
	store := newMockCredentialStore()
	client := NewAuthClient("http://localhost:8080", store)

	// No credential
	if client.IsLoggedIn() {
		t.Error("IsLoggedIn() = true, want false (no credential)")
	}

	// Valid credential
	store.creds["http://localhost:8080"] = &ServerCredential{
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	if !client.IsLoggedIn() {
		t.Error("IsLoggedIn() = false, want true (valid credential)")
	}

	// Expired credential
	store.creds["http://localhost:8080"] = &ServerCredential{
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
	}
	if client.IsLoggedIn() {
		t.Error("IsLoggedIn() = true, want false (expired credential)")
	}
}

// TestAuthClient_Logout verifies that Logout removes the stored credential for the server URL.
func TestAuthClient_Logout(t *testing.T) {
	store := newMockCredentialStore()
	store.creds["http://localhost:8080"] = &ServerCredential{
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	client := NewAuthClient("http://localhost:8080", store)

	if err := client.Logout(); err != nil {
		t.Errorf("Logout() error = %v", err)
	}

	if _, ok := store.creds["http://localhost:8080"]; ok {
		t.Error("Logout() did not remove credential")
	}
}

// =============================================================================
// #72 — ClientCredentialsToken auth method negotiation
// =============================================================================

// TestClientCredentialsToken_BasicAuth verifies that ClientCredentialsToken
// sends credentials via HTTP Basic authentication when AS metadata advertises
// client_secret_basic. The token request must use application/x-www-form-urlencoded
// with grant_type in the body and credentials in the Authorization header.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
// See: https://github.com/panyam/oneauth/issues/72
func TestClientCredentialsToken_BasicAuth(t *testing.T) {
	var receivedBasicUser, receivedBasicPass string
	var receivedBasicAuth bool
	var receivedContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedBasicUser, receivedBasicPass, receivedBasicAuth = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OAuth2TokenResponse{
			AccessToken: "basic-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	store := newMockCredentialStore()
	meta := &ASMetadata{TokenEndpointAuthMethods: []string{"client_secret_basic"}}
	c := NewAuthClient(server.URL, store, WithASMetadata(meta), WithTokenEndpoint("/token"))

	cred, err := c.ClientCredentialsToken("my-client", "my-secret", []string{"read"})
	require.NoError(t, err)
	assert.Equal(t, "basic-token", cred.AccessToken)
	assert.True(t, receivedBasicAuth, "should use HTTP Basic auth")
	assert.Equal(t, "my-client", receivedBasicUser)
	assert.Equal(t, "my-secret", receivedBasicPass)
	assert.Contains(t, receivedContentType, "application/x-www-form-urlencoded")
}

// TestClientCredentialsToken_PostAuth verifies that when the AS only supports
// client_secret_post, credentials are sent as form body parameters instead of
// the Authorization header.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
// See: https://github.com/panyam/oneauth/issues/72
func TestClientCredentialsToken_PostAuth(t *testing.T) {
	var receivedClientID, receivedClientSecret string
	var receivedBasicAuth bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_, _, receivedBasicAuth = r.BasicAuth()
		receivedClientID = r.FormValue("client_id")
		receivedClientSecret = r.FormValue("client_secret")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OAuth2TokenResponse{
			AccessToken: "post-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	store := newMockCredentialStore()
	meta := &ASMetadata{TokenEndpointAuthMethods: []string{"client_secret_post"}}
	c := NewAuthClient(server.URL, store, WithASMetadata(meta), WithTokenEndpoint("/token"))

	cred, err := c.ClientCredentialsToken("my-client", "my-secret", nil)
	require.NoError(t, err)
	assert.Equal(t, "post-token", cred.AccessToken)
	assert.False(t, receivedBasicAuth, "should NOT use Basic auth")
	assert.Equal(t, "my-client", receivedClientID)
	assert.Equal(t, "my-secret", receivedClientSecret)
}

// TestClientCredentialsToken_DefaultBasic_NoDiscovery verifies that without
// any AS metadata, ClientCredentialsToken defaults to client_secret_basic
// per RFC 6749 §2.3.1. This is the backward-compatible safe default.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
// See: https://github.com/panyam/oneauth/issues/72
func TestClientCredentialsToken_DefaultBasic_NoDiscovery(t *testing.T) {
	var receivedBasicAuth bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, receivedBasicAuth = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OAuth2TokenResponse{
			AccessToken: "default-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	store := newMockCredentialStore()
	// No WithASMetadata — no discovery data
	c := NewAuthClient(server.URL, store, WithTokenEndpoint("/token"))

	cred, err := c.ClientCredentialsToken("my-client", "my-secret", nil)
	require.NoError(t, err)
	assert.Equal(t, "default-token", cred.AccessToken)
	assert.True(t, receivedBasicAuth, "without metadata, should default to Basic auth")
}

// TestClientCredentialsToken_FormEncoded verifies that the token request is
// sent as application/x-www-form-urlencoded (RFC 6749 §4.4.2), not JSON.
// The previous implementation sent JSON which is non-standard.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4.2
// See: https://github.com/panyam/oneauth/issues/72
func TestClientCredentialsToken_FormEncoded(t *testing.T) {
	var receivedContentType string
	var receivedGrantType string
	var receivedScope string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		_ = r.ParseForm()
		receivedGrantType = r.FormValue("grant_type")
		receivedScope = r.FormValue("scope")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OAuth2TokenResponse{
			AccessToken: "form-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	store := newMockCredentialStore()
	c := NewAuthClient(server.URL, store, WithTokenEndpoint("/token"))

	_, err := c.ClientCredentialsToken("my-client", "my-secret", []string{"read", "write"})
	require.NoError(t, err)
	assert.Contains(t, receivedContentType, "application/x-www-form-urlencoded",
		"token request must be form-encoded per RFC 6749 §4.4.2")
	assert.Equal(t, "client_credentials", receivedGrantType)
	assert.Equal(t, "read write", receivedScope)
}

// TestAuthClient_URLNormalization verifies that credentials are matched by base URL regardless of the path component.
func TestAuthClient_URLNormalization(t *testing.T) {
	store := newMockCredentialStore()
	store.creds["http://localhost:8080"] = &ServerCredential{
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	// URL with path should still find credential
	client := NewAuthClient("http://localhost:8080/api/v1", store)

	if !client.IsLoggedIn() {
		t.Error("URL with path should still find credential for base URL")
	}
}
