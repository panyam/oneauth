package client

import (
	"testing"
	"time"
)

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
