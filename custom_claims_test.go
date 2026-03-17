// Tests for custom JWT claims embedding, multi-tenant token validation via KeyStore,
// algorithm confusion prevention, and single-key fallback behavior.
package oneauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	oa "github.com/panyam/oneauth"
)

// TestCustomClaimsFunc_RoundTrip tests that custom claims are embedded in the JWT
// and can be extracted after validation.
func TestCustomClaimsFunc_RoundTrip(t *testing.T) {
	apiAuth := &oa.APIAuth{
		JWTSecretKey: "test-secret-key",
		JWTIssuer:    "test-issuer",
		CustomClaimsFunc: func(userID string, scopes []string) (map[string]any, error) {
			return map[string]any{
				"client_id":     "host-excaliframe",
				"client_domain": "excaliframe.com",
				"max_rooms":     float64(10),
				"max_msg_rate":  float64(30.0),
			}, nil
		},
	}

	// Mint a token using the exported method
	token, _, err := apiAuth.CreateAccessToken("user-123", []string{"read", "write"})
	if err != nil {
		t.Fatalf("CreateAccessToken failed: %v", err)
	}

	// Validate and extract custom claims
	userID, scopes, customClaims, err := apiAuth.ValidateAccessTokenFull(token)
	if err != nil {
		t.Fatalf("ValidateAccessTokenFull failed: %v", err)
	}

	if userID != "user-123" {
		t.Errorf("Expected userID user-123, got %s", userID)
	}
	if len(scopes) != 2 {
		t.Errorf("Expected 2 scopes, got %d", len(scopes))
	}

	// Check custom claims
	if customClaims["client_id"] != "host-excaliframe" {
		t.Errorf("Expected client_id host-excaliframe, got %v", customClaims["client_id"])
	}
	if customClaims["client_domain"] != "excaliframe.com" {
		t.Errorf("Expected client_domain excaliframe.com, got %v", customClaims["client_domain"])
	}
	if customClaims["max_rooms"] != float64(10) {
		t.Errorf("Expected max_rooms 10, got %v", customClaims["max_rooms"])
	}
	if customClaims["max_msg_rate"] != float64(30.0) {
		t.Errorf("Expected max_msg_rate 30, got %v", customClaims["max_msg_rate"])
	}
}

// TestCustomClaimsFunc_Nil tests that nil callback preserves existing behavior
func TestCustomClaimsFunc_Nil(t *testing.T) {
	apiAuth := &oa.APIAuth{
		JWTSecretKey: "test-secret-key",
		JWTIssuer:    "test-issuer",
		// CustomClaimsFunc is nil
	}

	token, _, err := apiAuth.CreateAccessToken("user-123", []string{"read"})
	if err != nil {
		t.Fatalf("CreateAccessToken failed: %v", err)
	}

	userID, scopes, customClaims, err := apiAuth.ValidateAccessTokenFull(token)
	if err != nil {
		t.Fatalf("ValidateAccessTokenFull failed: %v", err)
	}

	if userID != "user-123" {
		t.Errorf("Expected userID user-123, got %s", userID)
	}
	if len(scopes) != 1 || scopes[0] != "read" {
		t.Errorf("Expected scopes [read], got %v", scopes)
	}
	// No custom claims should be present
	if len(customClaims) != 0 {
		t.Errorf("Expected no custom claims, got %v", customClaims)
	}
}

// TestCustomClaimsFunc_Error tests that callback error propagates
func TestCustomClaimsFunc_Error(t *testing.T) {
	apiAuth := &oa.APIAuth{
		JWTSecretKey: "test-secret-key",
		CustomClaimsFunc: func(userID string, scopes []string) (map[string]any, error) {
			return nil, oa.ErrInvalidGrant
		},
	}

	_, _, err := apiAuth.CreateAccessToken("user-123", []string{"read"})
	if err == nil {
		t.Fatal("Expected error from CreateAccessToken when CustomClaimsFunc fails")
	}
}

// TestCustomClaimsFunc_NoOverrideStandard tests that custom claims cannot override standard claims
func TestCustomClaimsFunc_NoOverrideStandard(t *testing.T) {
	apiAuth := &oa.APIAuth{
		JWTSecretKey: "test-secret-key",
		JWTIssuer:    "real-issuer",
		CustomClaimsFunc: func(userID string, scopes []string) (map[string]any, error) {
			return map[string]any{
				"sub":       "evil-user",       // should NOT override
				"iss":       "evil-issuer",     // should NOT override
				"type":      "refresh",         // should NOT override
				"client_id": "legit-host",      // custom claim, should be kept
			}, nil
		},
	}

	token, _, err := apiAuth.CreateAccessToken("real-user", []string{"read"})
	if err != nil {
		t.Fatalf("CreateAccessToken failed: %v", err)
	}

	userID, _, customClaims, err := apiAuth.ValidateAccessTokenFull(token)
	if err != nil {
		t.Fatalf("ValidateAccessTokenFull failed: %v", err)
	}

	// Standard claims should NOT be overridden
	if userID != "real-user" {
		t.Errorf("sub should not be overridden: expected real-user, got %s", userID)
	}

	// Custom claims should be present
	if customClaims["client_id"] != "legit-host" {
		t.Errorf("Expected client_id legit-host, got %v", customClaims["client_id"])
	}
}

// TestMultiTenantValidation_DifferentHosts tests that tokens from different hosts
// are verified with their respective secrets via KeyStore.
func TestMultiTenantValidation_DifferentHosts(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()
	ks.RegisterKey("host-alpha", []byte("alpha-secret"), "HS256")
	ks.RegisterKey("host-beta", []byte("beta-secret"), "HS256")

	// Mint token for host-alpha
	alphaToken := mintTestToken(t, "user-1", "host-alpha", "alpha-secret")
	// Mint token for host-beta
	betaToken := mintTestToken(t, "user-2", "host-beta", "beta-secret")

	middleware := &oa.APIMiddleware{
		KeyStore: ks,
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := oa.GetUserIDFromAPIContext(r.Context())
		json.NewEncoder(w).Encode(map[string]any{"user_id": userID})
	})

	// alpha token should pass
	t.Run("host-alpha token accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req.Header.Set("Authorization", "Bearer "+alphaToken)
		rr := httptest.NewRecorder()
		middleware.ValidateToken(testHandler).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
		}
		var resp map[string]any
		json.NewDecoder(rr.Body).Decode(&resp)
		if resp["user_id"] != "user-1" {
			t.Errorf("Expected user_id user-1, got %v", resp["user_id"])
		}
	})

	// beta token should pass
	t.Run("host-beta token accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req.Header.Set("Authorization", "Bearer "+betaToken)
		rr := httptest.NewRecorder()
		middleware.ValidateToken(testHandler).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
		}
		var resp map[string]any
		json.NewDecoder(rr.Body).Decode(&resp)
		if resp["user_id"] != "user-2" {
			t.Errorf("Expected user_id user-2, got %v", resp["user_id"])
		}
	})
}

// TestMultiTenantValidation_WrongSecret tests that a token signed with wrong secret is rejected
func TestMultiTenantValidation_WrongSecret(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()
	ks.RegisterKey("host-alpha", []byte("alpha-secret"), "HS256")

	// Mint token claiming to be from host-alpha but signed with wrong secret
	wrongToken := mintTestToken(t, "user-1", "host-alpha", "wrong-secret")

	middleware := &oa.APIMiddleware{
		KeyStore: ks,
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer "+wrongToken)
	rr := httptest.NewRecorder()
	middleware.ValidateToken(testHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for wrong secret, got %d", rr.Code)
	}
}

// TestMultiTenantValidation_UnknownClientID tests that a token with unregistered client_id is rejected
func TestMultiTenantValidation_UnknownClientID(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()
	// No hosts registered

	token := mintTestToken(t, "user-1", "unknown-host", "some-secret")

	middleware := &oa.APIMiddleware{
		KeyStore: ks,
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	middleware.ValidateToken(testHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for unknown client_id, got %d", rr.Code)
	}
}

// TestMultiTenantValidation_AlgorithmConfusion tests that a HS256 token is rejected
// when the KeyStore says the client uses HS512
func TestMultiTenantValidation_AlgorithmConfusion(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()
	ks.RegisterKey("host-alpha", []byte("shared-secret"), "HS512") // registered as HS512

	// Mint with HS256 (algorithm mismatch)
	token := mintTestToken(t, "user-1", "host-alpha", "shared-secret")

	middleware := &oa.APIMiddleware{
		KeyStore: ks,
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	middleware.ValidateToken(testHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for algorithm confusion, got %d", rr.Code)
	}
}

// TestMultiTenantValidation_FallbackToSingleKey tests that when KeyStore is nil,
// the middleware falls back to the single JWTSecretKey (backwards compat).
func TestMultiTenantValidation_FallbackToSingleKey(t *testing.T) {
	secret := "single-secret-key"

	// Mint token without client_id (old-style)
	claims := jwt.MapClaims{
		"sub":    "user-1",
		"type":   "access",
		"scopes": []string{"read"},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to mint token: %v", err)
	}

	middleware := &oa.APIMiddleware{
		JWTSecretKey: secret,
		// KeyStore is nil — should fall back to single key
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := oa.GetUserIDFromAPIContext(r.Context())
		json.NewEncoder(w).Encode(map[string]any{"user_id": userID})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rr := httptest.NewRecorder()
	middleware.ValidateToken(testHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 with single-key fallback, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

// TestValidateAccessTokenFull_StandardClaimsExcluded tests that standard JWT claims
// are not included in the customClaims return value
func TestValidateAccessTokenFull_StandardClaimsExcluded(t *testing.T) {
	apiAuth := &oa.APIAuth{
		JWTSecretKey: "test-secret",
		JWTIssuer:    "test-issuer",
		CustomClaimsFunc: func(userID string, scopes []string) (map[string]any, error) {
			return map[string]any{
				"client_id": "my-host",
				"max_rooms": float64(5),
			}, nil
		},
	}

	token, _, err := apiAuth.CreateAccessToken("user-1", []string{"read"})
	if err != nil {
		t.Fatalf("CreateAccessToken failed: %v", err)
	}

	_, _, customClaims, err := apiAuth.ValidateAccessTokenFull(token)
	if err != nil {
		t.Fatalf("ValidateAccessTokenFull failed: %v", err)
	}

	// Standard claims should NOT be in customClaims
	for _, stdClaim := range []string{"sub", "iss", "aud", "exp", "iat", "type", "scopes"} {
		if _, exists := customClaims[stdClaim]; exists {
			t.Errorf("Standard claim %q should not be in customClaims", stdClaim)
		}
	}

	// Custom claims should be present
	if customClaims["client_id"] != "my-host" {
		t.Errorf("Expected client_id my-host, got %v", customClaims["client_id"])
	}
	if customClaims["max_rooms"] != float64(5) {
		t.Errorf("Expected max_rooms 5, got %v", customClaims["max_rooms"])
	}
}

// mintTestToken creates a HS256 JWT with client_id claim for testing multi-tenant validation
func mintTestToken(t *testing.T, userID, clientID, secret string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub":       userID,
		"type":      "access",
		"client_id": clientID,
		"scopes":    []string{"read", "write"},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to mint test token: %v", err)
	}
	return tokenString
}
