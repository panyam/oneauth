package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthClient_Login_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/cli/token" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		body, _ := io.ReadAll(r.Body)
		var req OAuth2TokenRequest
		json.Unmarshal(body, &req)

		if req.GrantType != "password" {
			t.Errorf("expected grant_type=password, got %s", req.GrantType)
		}
		if req.Username != "user@example.com" {
			t.Errorf("expected username=user@example.com, got %s", req.Username)
		}

		json.NewEncoder(w).Encode(OAuth2TokenResponse{
			AccessToken:  "access-token-123",
			RefreshToken: "refresh-token-456",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        "read write",
		})
	}))
	defer server.Close()

	store := newMockCredentialStore()
	client := NewAuthClient(server.URL, store)

	cred, err := client.Login("user@example.com", "password123", "read write")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if cred.AccessToken != "access-token-123" {
		t.Errorf("AccessToken = %v, want access-token-123", cred.AccessToken)
	}
	if cred.RefreshToken != "refresh-token-456" {
		t.Errorf("RefreshToken = %v, want refresh-token-456", cred.RefreshToken)
	}
	if cred.UserEmail != "user@example.com" {
		t.Errorf("UserEmail = %v, want user@example.com", cred.UserEmail)
	}

	// Verify stored in store
	stored, _ := store.GetCredential(server.URL)
	if stored == nil {
		t.Fatal("credential not stored")
	}
	if stored.AccessToken != cred.AccessToken {
		t.Errorf("stored AccessToken = %v, want %v", stored.AccessToken, cred.AccessToken)
	}
}

func TestAuthClient_Login_InvalidCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(OAuth2TokenResponse{
			Error:     "invalid_grant",
			ErrorDesc: "Invalid credentials",
		})
	}))
	defer server.Close()

	store := newMockCredentialStore()
	client := NewAuthClient(server.URL, store)

	_, err := client.Login("user@example.com", "wrong-password", "read write")
	if err == nil {
		t.Fatal("Login() should have failed with invalid credentials")
	}
}

func TestAuthClient_RefreshToken_Success(t *testing.T) {
	var callCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)

		body, _ := io.ReadAll(r.Body)
		var req OAuth2TokenRequest
		json.Unmarshal(body, &req)

		if req.GrantType != "refresh_token" {
			t.Errorf("expected grant_type=refresh_token, got %s", req.GrantType)
		}
		if req.RefreshToken != "old-refresh-token" {
			t.Errorf("expected old refresh token, got %s", req.RefreshToken)
		}

		json.NewEncoder(w).Encode(OAuth2TokenResponse{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
	}))
	defer server.Close()

	store := newMockCredentialStore()
	// Set up credential that's expiring soon
	store.creds[server.URL] = &ServerCredential{
		AccessToken:  "expiring-token",
		RefreshToken: "old-refresh-token",
		ExpiresAt:    time.Now().Add(2 * time.Minute), // Within RefreshThreshold
		UserEmail:    "user@example.com",
	}

	client := NewAuthClient(server.URL, store)

	// GetToken should trigger refresh
	token, err := client.GetToken()
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	if token != "new-access-token" {
		t.Errorf("token = %v, want new-access-token", token)
	}

	// Verify refresh was called
	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("refresh endpoint called %d times, want 1", callCount)
	}

	// Verify new token stored
	stored, _ := store.GetCredential(server.URL)
	if stored.AccessToken != "new-access-token" {
		t.Errorf("stored AccessToken = %v, want new-access-token", stored.AccessToken)
	}
	if stored.RefreshToken != "new-refresh-token" {
		t.Errorf("stored RefreshToken = %v, want new-refresh-token", stored.RefreshToken)
	}
	// User info should be preserved
	if stored.UserEmail != "user@example.com" {
		t.Errorf("stored UserEmail = %v, want user@example.com", stored.UserEmail)
	}
}

func TestAuthClient_Transport_AddsAuthHeader(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := newMockCredentialStore()
	store.creds[server.URL] = &ServerCredential{
		AccessToken: "my-token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	client := NewAuthClient(server.URL, store)

	resp, err := client.HTTPClient().Get(server.URL + "/api/resource")
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	resp.Body.Close()

	if receivedAuth != "Bearer my-token" {
		t.Errorf("Authorization header = %v, want Bearer my-token", receivedAuth)
	}
}

func TestAuthClient_Transport_NoAuthHeader_WhenNoCredential(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := newMockCredentialStore()
	client := NewAuthClient(server.URL, store)

	resp, err := client.HTTPClient().Get(server.URL + "/api/resource")
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	resp.Body.Close()

	if receivedAuth != "" {
		t.Errorf("Authorization header = %v, want empty", receivedAuth)
	}
}

func TestAuthClient_Transport_RetryOn401WithRefresh(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)

		if r.URL.Path == "/auth/cli/token" {
			// Refresh token endpoint
			json.NewEncoder(w).Encode(OAuth2TokenResponse{
				AccessToken:  "refreshed-token",
				RefreshToken: "new-refresh-token",
				ExpiresIn:    3600,
			})
			return
		}

		// First request returns 401, second should succeed
		auth := r.Header.Get("Authorization")
		if count == 1 && auth == "Bearer old-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if auth == "Bearer refreshed-token" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
			return
		}

		t.Errorf("unexpected auth header on request %d: %s", count, auth)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	store := newMockCredentialStore()
	store.creds[server.URL] = &ServerCredential{
		AccessToken:  "old-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour), // Not expired yet
	}

	client := NewAuthClient(server.URL, store)

	resp, err := client.HTTPClient().Get(server.URL + "/api/resource")
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "success" {
		t.Errorf("body = %s, want success", body)
	}
}

func TestAuthClient_Transport_NoRetry_WithoutRefreshToken(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	store := newMockCredentialStore()
	store.creds[server.URL] = &ServerCredential{
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		// No refresh token
	}

	client := NewAuthClient(server.URL, store)

	resp, err := client.HTTPClient().Get(server.URL + "/api/resource")
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}

	// Should only make 1 request (no retry without refresh token)
	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("request count = %d, want 1", requestCount)
	}
}

func TestAuthClient_WithCustomHTTPClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := newMockCredentialStore()
	store.creds[server.URL] = &ServerCredential{
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	customClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	client := NewAuthClient(server.URL, store, WithHTTPClient(customClient))

	// Verify timeout was copied
	if client.HTTPClient().Timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", client.HTTPClient().Timeout)
	}

	// Verify requests still work
	resp, err := client.HTTPClient().Get(server.URL + "/api/resource")
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestAuthClient_WithCustomTokenEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/custom/token" {
			t.Errorf("expected /custom/token, got %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(OAuth2TokenResponse{
			AccessToken: "token",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	store := newMockCredentialStore()
	client := NewAuthClient(server.URL, store, WithTokenEndpoint("/custom/token"))

	_, err := client.Login("user@example.com", "password", "")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
}
