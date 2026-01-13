package oneauth_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/stores/fs"
)

// setupAPIAuthTest creates test stores and APIAuth handler
func setupAPIAuthTest(t *testing.T) (*oa.APIAuth, *fs.FSRefreshTokenStore, *fs.FSAPIKeyStore, string) {
	tmpDir, err := os.MkdirTemp("", "oneauth-apiauth-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create stores
	userStore := fs.NewFSUserStore(tmpDir)
	identityStore := fs.NewFSIdentityStore(tmpDir)
	channelStore := fs.NewFSChannelStore(tmpDir)
	refreshTokenStore := fs.NewFSRefreshTokenStore(tmpDir)
	apiKeyStore := fs.NewFSAPIKeyStore(tmpDir)

	// Create test user
	testEmail := "apitest@example.com"
	testPassword := "password123"
	createUser := oa.NewCreateUserFunc(userStore, identityStore, channelStore)
	_, err = createUser(&oa.Credentials{
		Username: "apiuser",
		Email:    &testEmail,
		Password: testPassword,
	})
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create test user: %v", err)
	}

	apiAuth := &oa.APIAuth{
		RefreshTokenStore:   refreshTokenStore,
		APIKeyStore:         apiKeyStore,
		JWTSecretKey:        "test-secret-key-for-testing-only",
		JWTIssuer:           "oneauth-test",
		ValidateCredentials: oa.NewCredentialsValidator(identityStore, channelStore, userStore),
		GetUserScopes: func(userID string) ([]string, error) {
			return []string{oa.ScopeRead, oa.ScopeWrite, oa.ScopeProfile, oa.ScopeOffline}, nil
		},
	}

	return apiAuth, refreshTokenStore, apiKeyStore, tmpDir
}

func cleanupAPIAuthTest(t *testing.T, tmpDir string) {
	if err := os.RemoveAll(tmpDir); err != nil {
		t.Logf("Warning: failed to cleanup temp dir: %v", err)
	}
}

// TestPasswordGrant tests the password grant login flow
func TestPasswordGrant(t *testing.T) {
	apiAuth, _, _, tmpDir := setupAPIAuthTest(t)
	defer cleanupAPIAuthTest(t, tmpDir)

	tests := []struct {
		name           string
		grantType      string
		username       string
		password       string
		expectedStatus int
		checkToken     bool
	}{
		{
			name:           "successful login",
			grantType:      "password",
			username:       "apitest@example.com",
			password:       "password123",
			expectedStatus: http.StatusOK,
			checkToken:     true,
		},
		{
			name:           "wrong password",
			grantType:      "password",
			username:       "apitest@example.com",
			password:       "wrongpassword",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "non-existent user",
			grantType:      "password",
			username:       "nonexistent@example.com",
			password:       "password123",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "missing credentials",
			grantType:      "password",
			username:       "",
			password:       "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "unsupported grant type",
			grantType:      "authorization_code",
			username:       "apitest@example.com",
			password:       "password123",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody := map[string]string{
				"grant_type": tt.grantType,
				"username":   tt.username,
				"password":   tt.password,
			}
			body, _ := json.Marshal(reqBody)

			req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			apiAuth.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if tt.checkToken && tt.expectedStatus == http.StatusOK {
				var response oa.TokenPair
				if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if response.AccessToken == "" {
					t.Error("Expected access_token in response")
				}
				if response.RefreshToken == "" {
					t.Error("Expected refresh_token in response")
				}
				if response.TokenType != "Bearer" {
					t.Errorf("Expected token_type Bearer, got %s", response.TokenType)
				}
				if response.ExpiresIn <= 0 {
					t.Error("Expected positive expires_in")
				}
			}
		})
	}
}

// TestRefreshTokenGrant tests the refresh token grant flow
func TestRefreshTokenGrant(t *testing.T) {
	apiAuth, _, _, tmpDir := setupAPIAuthTest(t)
	defer cleanupAPIAuthTest(t, tmpDir)

	// First, get tokens via password grant
	loginBody := map[string]string{
		"grant_type": "password",
		"username":   "apitest@example.com",
		"password":   "password123",
	}
	body, _ := json.Marshal(loginBody)
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiAuth.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Login failed: %s", rr.Body.String())
	}

	var loginResponse oa.TokenPair
	json.NewDecoder(rr.Body).Decode(&loginResponse)

	t.Run("successful refresh", func(t *testing.T) {
		refreshBody := map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": loginResponse.RefreshToken,
		}
		body, _ := json.Marshal(refreshBody)
		req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		apiAuth.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", rr.Code, rr.Body.String())
		}

		var refreshResponse oa.TokenPair
		json.NewDecoder(rr.Body).Decode(&refreshResponse)

		if refreshResponse.AccessToken == "" {
			t.Error("Expected new access_token")
		}
		if refreshResponse.RefreshToken == "" {
			t.Error("Expected new refresh_token")
		}
		// New refresh token should be different (rotation)
		if refreshResponse.RefreshToken == loginResponse.RefreshToken {
			t.Error("Refresh token should be rotated")
		}
	})

	t.Run("reuse detection", func(t *testing.T) {
		// Try to use the original (now revoked) refresh token
		refreshBody := map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": loginResponse.RefreshToken,
		}
		body, _ := json.Marshal(refreshBody)
		req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		apiAuth.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for reused token, got %d", rr.Code)
		}
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		refreshBody := map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": "invalid-token",
		}
		body, _ := json.Marshal(refreshBody)
		req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		apiAuth.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}
	})
}

// TestLogout tests the logout endpoints
func TestLogout(t *testing.T) {
	apiAuth, _, _, tmpDir := setupAPIAuthTest(t)
	defer cleanupAPIAuthTest(t, tmpDir)

	// Get tokens
	loginBody := map[string]string{
		"grant_type": "password",
		"username":   "apitest@example.com",
		"password":   "password123",
	}
	body, _ := json.Marshal(loginBody)
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiAuth.ServeHTTP(rr, req)

	var loginResponse oa.TokenPair
	json.NewDecoder(rr.Body).Decode(&loginResponse)

	t.Run("logout single session", func(t *testing.T) {
		logoutBody := map[string]string{
			"refresh_token": loginResponse.RefreshToken,
		}
		body, _ := json.Marshal(logoutBody)
		req := httptest.NewRequest(http.MethodPost, "/api/logout", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		apiAuth.HandleLogout(rr, req)

		if rr.Code != http.StatusNoContent {
			t.Errorf("Expected status 204, got %d", rr.Code)
		}

		// Verify token is revoked
		refreshBody := map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": loginResponse.RefreshToken,
		}
		body, _ = json.Marshal(refreshBody)
		req = httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr = httptest.NewRecorder()
		apiAuth.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for revoked token, got %d", rr.Code)
		}
	})
}

// TestJWTValidation tests the APIMiddleware JWT validation
func TestJWTValidation(t *testing.T) {
	apiAuth, _, apiKeyStore, tmpDir := setupAPIAuthTest(t)
	defer cleanupAPIAuthTest(t, tmpDir)

	// Get tokens
	loginBody := map[string]string{
		"grant_type": "password",
		"username":   "apitest@example.com",
		"password":   "password123",
	}
	body, _ := json.Marshal(loginBody)
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiAuth.ServeHTTP(rr, req)

	var loginResponse oa.TokenPair
	json.NewDecoder(rr.Body).Decode(&loginResponse)

	middleware := &oa.APIMiddleware{
		JWTSecretKey: apiAuth.JWTSecretKey,
		JWTIssuer:    apiAuth.JWTIssuer,
		APIKeyStore:  apiKeyStore,
	}

	// Test handler that returns user info
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := oa.GetUserIDFromAPIContext(r.Context())
		scopes := oa.GetScopesFromAPIContext(r.Context())
		authType := oa.GetAuthTypeFromAPIContext(r.Context())
		json.NewEncoder(w).Encode(map[string]any{
			"user_id":   userID,
			"scopes":    scopes,
			"auth_type": authType,
		})
	})

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		checkUserID    bool
	}{
		{
			name:           "valid JWT",
			authHeader:     "Bearer " + loginResponse.AccessToken,
			expectedStatus: http.StatusOK,
			checkUserID:    true,
		},
		{
			name:           "missing auth header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid auth format",
			authHeader:     "Basic " + loginResponse.AccessToken,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid JWT",
			authHeader:     "Bearer invalid-jwt-token",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rr := httptest.NewRecorder()

			middleware.ValidateToken(testHandler).ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if tt.checkUserID && rr.Code == http.StatusOK {
				var response map[string]any
				json.NewDecoder(rr.Body).Decode(&response)
				if response["user_id"] == "" {
					t.Error("Expected user_id in response")
				}
				if response["auth_type"] != "jwt" {
					t.Errorf("Expected auth_type jwt, got %v", response["auth_type"])
				}
			}
		})
	}
}

// TestScopeEnforcement tests the RequireScopes middleware
func TestScopeEnforcement(t *testing.T) {
	apiAuth, _, apiKeyStore, tmpDir := setupAPIAuthTest(t)
	defer cleanupAPIAuthTest(t, tmpDir)

	// Get tokens with specific scopes
	loginBody := map[string]string{
		"grant_type": "password",
		"username":   "apitest@example.com",
		"password":   "password123",
		"scope":      "read write",
	}
	body, _ := json.Marshal(loginBody)
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiAuth.ServeHTTP(rr, req)

	var loginResponse oa.TokenPair
	json.NewDecoder(rr.Body).Decode(&loginResponse)

	middleware := &oa.APIMiddleware{
		JWTSecretKey: apiAuth.JWTSecretKey,
		JWTIssuer:    apiAuth.JWTIssuer,
		APIKeyStore:  apiKeyStore,
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name           string
		requiredScopes []string
		expectedStatus int
	}{
		{
			name:           "has required scope",
			requiredScopes: []string{"read"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "has multiple required scopes",
			requiredScopes: []string{"read", "write"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing required scope",
			requiredScopes: []string{"admin"},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
			req.Header.Set("Authorization", "Bearer "+loginResponse.AccessToken)
			rr := httptest.NewRecorder()

			middleware.RequireScopes(tt.requiredScopes...)(testHandler).ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

// TestAPIKeyAuthentication tests API key creation and authentication
func TestAPIKeyAuthentication(t *testing.T) {
	apiAuth, _, apiKeyStore, tmpDir := setupAPIAuthTest(t)
	defer cleanupAPIAuthTest(t, tmpDir)

	// Create API key directly for testing
	fullKey, apiKey, err := apiKeyStore.CreateAPIKey("testuser123", "Test Key", []string{oa.ScopeRead, oa.ScopeWrite}, nil)
	if err != nil {
		t.Fatalf("Failed to create API key: %v", err)
	}

	middleware := &oa.APIMiddleware{
		JWTSecretKey: apiAuth.JWTSecretKey,
		JWTIssuer:    apiAuth.JWTIssuer,
		APIKeyStore:  apiKeyStore,
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := oa.GetUserIDFromAPIContext(r.Context())
		authType := oa.GetAuthTypeFromAPIContext(r.Context())
		json.NewEncoder(w).Encode(map[string]any{
			"user_id":   userID,
			"auth_type": authType,
		})
	})

	t.Run("valid API key authentication", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req.Header.Set("Authorization", "Bearer "+fullKey)
		rr := httptest.NewRecorder()

		middleware.ValidateToken(testHandler).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", rr.Code, rr.Body.String())
		}

		var response map[string]any
		json.NewDecoder(rr.Body).Decode(&response)
		if response["user_id"] != apiKey.UserID {
			t.Errorf("Expected user_id %s, got %v", apiKey.UserID, response["user_id"])
		}
		if response["auth_type"] != "api_key" {
			t.Errorf("Expected auth_type api_key, got %v", response["auth_type"])
		}
	})

	t.Run("invalid API key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req.Header.Set("Authorization", "Bearer oa_invalid_key12345")
		rr := httptest.NewRecorder()

		middleware.ValidateToken(testHandler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}
	})
}

// TestAPIKeyManagement tests the API key management endpoints
func TestAPIKeyManagement(t *testing.T) {
	apiAuth, _, apiKeyStore, tmpDir := setupAPIAuthTest(t)
	defer cleanupAPIAuthTest(t, tmpDir)

	// Get tokens for authentication
	loginBody := map[string]string{
		"grant_type": "password",
		"username":   "apitest@example.com",
		"password":   "password123",
	}
	body, _ := json.Marshal(loginBody)
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiAuth.ServeHTTP(rr, req)

	var loginResponse oa.TokenPair
	json.NewDecoder(rr.Body).Decode(&loginResponse)

	// Validate token to get user ID
	userID, _, _ := apiAuth.ValidateAccessToken(loginResponse.AccessToken)

	var createdKeyID string

	t.Run("create API key", func(t *testing.T) {
		createBody := map[string]any{
			"name":   "My API Key",
			"scopes": []string{"read", "write"},
		}
		body, _ := json.Marshal(createBody)
		req := httptest.NewRequest(http.MethodPost, "/api/keys", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(oa.SetUserIDInContext(req.Context(), userID))
		rr := httptest.NewRecorder()

		apiAuth.HandleAPIKeys(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("Expected status 201, got %d. Body: %s", rr.Code, rr.Body.String())
		}

		var response map[string]any
		json.NewDecoder(rr.Body).Decode(&response)
		if response["api_key"] == nil {
			t.Error("Expected api_key in response")
		}
		if response["key_id"] == nil {
			t.Error("Expected key_id in response")
		}
		createdKeyID = response["key_id"].(string)

		// Verify the full key starts with "oa_"
		apiKey := response["api_key"].(string)
		if !strings.HasPrefix(apiKey, "oa_") {
			t.Errorf("API key should start with 'oa_', got: %s", apiKey[:10])
		}
	})

	t.Run("list API keys", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/keys", nil)
		req = req.WithContext(oa.SetUserIDInContext(req.Context(), userID))
		rr := httptest.NewRecorder()

		apiAuth.HandleAPIKeys(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", rr.Code, rr.Body.String())
		}

		var response map[string]any
		json.NewDecoder(rr.Body).Decode(&response)
		apiKeys := response["api_keys"].([]any)
		if len(apiKeys) == 0 {
			t.Error("Expected at least one API key")
		}
	})

	t.Run("revoke API key", func(t *testing.T) {
		if createdKeyID == "" {
			t.Skip("No API key created")
		}

		req := httptest.NewRequest(http.MethodDelete, "/api/keys/"+createdKeyID, nil)
		req = req.WithContext(oa.SetUserIDInContext(req.Context(), userID))
		rr := httptest.NewRecorder()

		apiAuth.HandleRevokeAPIKey(rr, req)

		if rr.Code != http.StatusNoContent {
			t.Errorf("Expected status 204, got %d. Body: %s", rr.Code, rr.Body.String())
		}

		// Verify key is revoked
		key, _ := apiKeyStore.GetAPIKeyByID(createdKeyID)
		if key != nil && !key.Revoked {
			t.Error("Expected key to be revoked")
		}
	})
}

// TestOptionalMiddleware tests the Optional middleware behavior
func TestOptionalMiddleware(t *testing.T) {
	apiAuth, _, apiKeyStore, tmpDir := setupAPIAuthTest(t)
	defer cleanupAPIAuthTest(t, tmpDir)

	middleware := &oa.APIMiddleware{
		JWTSecretKey: apiAuth.JWTSecretKey,
		JWTIssuer:    apiAuth.JWTIssuer,
		APIKeyStore:  apiKeyStore,
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := oa.GetUserIDFromAPIContext(r.Context())
		json.NewEncoder(w).Encode(map[string]any{
			"user_id": userID,
		})
	})

	t.Run("allows unauthenticated requests", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		rr := httptest.NewRecorder()

		middleware.Optional(testHandler).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}

		var response map[string]any
		json.NewDecoder(rr.Body).Decode(&response)
		if response["user_id"] != "" {
			t.Errorf("Expected empty user_id, got %v", response["user_id"])
		}
	})
}

// TestAPITokenExpiry tests that expired tokens are rejected
func TestAPITokenExpiry(t *testing.T) {
	// This test would require creating tokens with short expiry
	// For now, we just verify the validation rejects malformed tokens
	apiAuth, _, apiKeyStore, tmpDir := setupAPIAuthTest(t)
	defer cleanupAPIAuthTest(t, tmpDir)

	middleware := &oa.APIMiddleware{
		JWTSecretKey: apiAuth.JWTSecretKey,
		JWTIssuer:    apiAuth.JWTIssuer,
		APIKeyStore:  apiKeyStore,
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create an expired API key
	expiredTime := time.Now().Add(-1 * time.Hour)
	fullKey, _, err := apiKeyStore.CreateAPIKey("testuser", "Expired Key", []string{"read"}, &expiredTime)
	if err != nil {
		t.Fatalf("Failed to create expired API key: %v", err)
	}

	t.Run("rejects expired API key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req.Header.Set("Authorization", "Bearer "+fullKey)
		rr := httptest.NewRecorder()

		middleware.ValidateToken(testHandler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for expired key, got %d", rr.Code)
		}
	})
}
