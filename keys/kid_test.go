package keys_test

// Tests for kid (Key ID) in JWT headers, KidResolver, KidStore grace periods,
// kid-based JWT verification, and AppRegistrar rotation with grace.

import (
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/utils"
)

// ============================================================================
// Phase 1: kid header in minted JWTs
// ============================================================================

func TestMintResourceToken_HasKid(t *testing.T) {
	secret := "test-secret-for-kid"
	tokenStr, err := admin.MintResourceToken("user-1", "app-1", secret, admin.AppQuota{}, []string{"read"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Parse without verification to inspect header
	parser := jwt.NewParser()
	parsed, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}

	kid, ok := parsed.Header["kid"].(string)
	if !ok || kid == "" {
		t.Fatal("expected kid header in minted JWT")
	}

	// kid should match ComputeKid for the same key
	expectedKid, err := utils.ComputeKid([]byte(secret), "HS256")
	if err != nil {
		t.Fatal(err)
	}
	if kid != expectedKid {
		t.Errorf("kid=%s, want %s", kid, expectedKid)
	}
}

func TestMintResourceTokenWithKey_RSA_HasKid(t *testing.T) {
	privPEM, _, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)

	tokenStr, err := admin.MintResourceTokenWithKey("user-1", "app-rsa", privKey, admin.AppQuota{}, []string{"read"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	parser := jwt.NewParser()
	parsed, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}

	kid, ok := parsed.Header["kid"].(string)
	if !ok || kid == "" {
		t.Fatal("expected kid header in RSA JWT")
	}
	if len(kid) != 43 {
		t.Errorf("kid should be 43 chars (base64url SHA-256), got %d", len(kid))
	}
}

func TestCreateAccessToken_HasKid(t *testing.T) {
	auth := &apiauth.APIAuth{
		JWTSecretKey: "my-secret",
	}
	tokenStr, _, err := auth.CreateAccessToken("user-1", []string{"read"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	parser := jwt.NewParser()
	parsed, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}

	kid, ok := parsed.Header["kid"].(string)
	if !ok || kid == "" {
		t.Fatal("expected kid header in access token JWT")
	}

	expectedKid, _ := utils.ComputeKid([]byte("my-secret"), "HS256")
	if kid != expectedKid {
		t.Errorf("kid=%s, want %s", kid, expectedKid)
	}
}

func TestJWKS_KidMatchesThumbprint(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	privPEM, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	_ = privPEM
	ks.RegisterKey("app-rsa", pubPEM, "RS256")

	handler := &keys.JWKSHandler{KeyStore: ks}
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var jwkSet utils.JWKSet
	json.NewDecoder(rec.Body).Decode(&jwkSet)

	if len(jwkSet.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwkSet.Keys))
	}

	// kid in JWKS should be a thumbprint, not clientID
	jwkKid := jwkSet.Keys[0].Kid
	if jwkKid == "app-rsa" {
		t.Error("JWKS kid should be a thumbprint, not clientID")
	}

	// Verify it matches what ComputeKid produces
	pubKey, _ := utils.DecodeVerifyKey(pubPEM, "RS256")
	expectedKid, _ := utils.ComputeKid(pubKey, "RS256")
	if jwkKid != expectedKid {
		t.Errorf("JWKS kid=%s, expected thumbprint=%s", jwkKid, expectedKid)
	}
}

// ============================================================================
// Phase 2: KidResolver on InMemoryKeyStore
// ============================================================================

func TestInMemoryKeyStore_KidResolver(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	secret := []byte("my-secret")
	ks.RegisterKey("app-1", secret, "HS256")

	// GetCurrentKid should return computed kid
	kid, err := ks.GetCurrentKid("app-1")
	if err != nil {
		t.Fatal(err)
	}
	expectedKid, _ := utils.ComputeKid(secret, "HS256")
	if kid != expectedKid {
		t.Errorf("GetCurrentKid=%s, want %s", kid, expectedKid)
	}

	// GetKeyByKid should return the key record
	rec, err := ks.GetKeyByKid(kid)
	if err != nil {
		t.Fatal(err)
	}
	if string(rec.Key.([]byte)) != string(secret) {
		t.Error("key mismatch")
	}
	if rec.Algorithm != "HS256" {
		t.Errorf("alg=%s, want HS256", rec.Algorithm)
	}
	if rec.ClientID != "app-1" {
		t.Errorf("clientID=%s, want app-1", rec.ClientID)
	}
}

func TestInMemoryKeyStore_KidResolver_NotFound(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	_, err := ks.GetKeyByKid("nonexistent-kid")
	if err != keys.ErrKidNotFound {
		t.Errorf("expected ErrKidNotFound, got %v", err)
	}
}

func TestInMemoryKeyStore_KidUpdatesOnOverwrite(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	ks.RegisterKey("app-1", []byte("old-secret"), "HS256")
	oldKid, _ := ks.GetCurrentKid("app-1")

	ks.RegisterKey("app-1", []byte("new-secret"), "HS256")
	newKid, _ := ks.GetCurrentKid("app-1")

	if oldKid == newKid {
		t.Error("kid should change when key changes")
	}

	// Old kid should no longer resolve
	_, err := ks.GetKeyByKid(oldKid)
	if err != keys.ErrKidNotFound {
		t.Errorf("old kid should not resolve after overwrite, got %v", err)
	}

	// New kid should resolve
	_, err = ks.GetKeyByKid(newKid)
	if err != nil {
		t.Errorf("new kid should resolve: %v", err)
	}
}

func TestInMemoryKeyStore_KidCleanedOnDelete(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	ks.RegisterKey("app-1", []byte("secret"), "HS256")
	kid, _ := ks.GetCurrentKid("app-1")

	ks.DeleteKey("app-1")

	_, err := ks.GetKeyByKid(kid)
	if err != keys.ErrKidNotFound {
		t.Errorf("kid should not resolve after delete, got %v", err)
	}
}

// ============================================================================
// KidStore: grace period for rotated keys
// ============================================================================

func TestKidStore_BasicAddAndLookup(t *testing.T) {
	store := keys.NewKidStore()
	store.Add("kid-1", []byte("secret"), "HS256", "app-1", time.Time{})

	rec, err := store.GetKeyByKid("kid-1")
	if err != nil {
		t.Fatal(err)
	}
	if string(rec.Key.([]byte)) != "secret" || rec.Algorithm != "HS256" || rec.ClientID != "app-1" {
		t.Error("unexpected values from KidStore lookup")
	}
}

func TestKidStore_ExpiredKeyNotReturned(t *testing.T) {
	store := keys.NewKidStore()
	store.Add("kid-old", []byte("old-secret"), "HS256", "app-1", time.Now().Add(-1*time.Hour))

	_, err := store.GetKeyByKid("kid-old")
	if err != keys.ErrKidNotFound {
		t.Errorf("expected ErrKidNotFound for expired key, got %v", err)
	}
}

func TestKidStore_NonExpiredKeyReturned(t *testing.T) {
	store := keys.NewKidStore()
	store.Add("kid-old", []byte("old-secret"), "HS256", "app-1", time.Now().Add(1*time.Hour))

	rec, err := store.GetKeyByKid("kid-old")
	if err != nil {
		t.Fatal(err)
	}
	if string(rec.Key.([]byte)) != "old-secret" {
		t.Error("expected old secret for non-expired key")
	}
}

func TestKidStore_CleanExpired(t *testing.T) {
	store := keys.NewKidStore()
	store.Add("kid-alive", []byte("a"), "HS256", "app-1", time.Now().Add(1*time.Hour))
	store.Add("kid-dead", []byte("b"), "HS256", "app-2", time.Now().Add(-1*time.Hour))

	if store.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", store.Len())
	}

	store.CleanExpired()

	if store.Len() != 1 {
		t.Fatalf("expected 1 entry after cleanup, got %d", store.Len())
	}
}

func TestCompositeKidResolver(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	ks.RegisterKey("app-1", []byte("current-secret"), "HS256")
	currentKid, _ := ks.GetCurrentKid("app-1")

	kidStore := keys.NewKidStore()
	kidStore.Add("old-kid", []byte("old-secret"), "HS256", "app-1", time.Now().Add(1*time.Hour))

	composite := &keys.CompositeKeyLookup{Lookups: []keys.KeyLookup{ks, kidStore}}

	// Current kid resolves via InMemoryKeyStore
	_, err := composite.GetKeyByKid(currentKid)
	if err != nil {
		t.Errorf("current kid should resolve: %v", err)
	}

	// Old kid resolves via KidStore
	rec, err := composite.GetKeyByKid("old-kid")
	if err != nil {
		t.Errorf("old kid should resolve: %v", err)
	}
	if string(rec.Key.([]byte)) != "old-secret" {
		t.Error("expected old secret")
	}

	// Unknown kid fails
	_, err = composite.GetKeyByKid("unknown")
	if err != keys.ErrKidNotFound {
		t.Errorf("expected ErrKidNotFound, got %v", err)
	}
}

// ============================================================================
// Phase 5: kid-based JWT verification in middleware
// ============================================================================

func TestValidateJWT_WithKid(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	secret := []byte("test-secret")
	ks.RegisterKey("app-1", secret, "HS256")

	// Mint token (now includes kid header)
	tokenStr, _ := admin.MintResourceToken("user-1", "app-1", string(secret), admin.AppQuota{}, []string{"read"}, nil)

	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	var gotUserID string
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = apiauth.GetUserIDFromAPIContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if gotUserID != "user-1" {
		t.Errorf("userID=%s, want user-1", gotUserID)
	}
}

func TestValidateJWT_LegacyNoKid(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	secret := []byte("test-secret")
	ks.RegisterKey("app-1", secret, "HS256")

	// Manually create a token WITHOUT kid header (legacy)
	claims := jwt.MapClaims{
		"sub":       "user-1",
		"client_id": "app-1",
		"type":      "access",
		"scopes":    []string{"read"},
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Deliberately no kid header
	tokenStr, _ := token.SignedString(secret)

	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	var gotUserID string
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = apiauth.GetUserIDFromAPIContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("legacy token without kid: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if gotUserID != "user-1" {
		t.Errorf("userID=%s, want user-1", gotUserID)
	}
}

func TestValidateJWT_CrossAppRejectedViaKid(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	ks.RegisterKey("app-a", []byte("secret-a"), "HS256")
	ks.RegisterKey("app-b", []byte("secret-b"), "HS256")

	// Mint with app-a's secret but claim client_id=app-b
	// The kid will be derived from secret-a, so cross-check should fail
	tokenStr, _ := admin.MintResourceToken("user-1", "app-b", "secret-a", admin.AppQuota{}, []string{"read"}, nil)

	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for cross-app token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for cross-app token, got %d", rr.Code)
	}
}

// ============================================================================
// Phase 6: AppRegistrar rotation with grace period
// ============================================================================

func TestAppRegistrar_RotateWithGrace(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	kidStore := keys.NewKidStore()
	registrar := func() *admin.AppRegistrar {
		r := admin.NewAppRegistrar(ks, admin.NewNoAuth())
		r.KidStore = kidStore
		return r
	}()
	regHandler := registrar.Handler()

	// Register app
	body, _ := json.Marshal(map[string]any{"client_domain": "grace-test.com"})
	req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	regHandler.ServeHTTP(rr, req)

	var regResp map[string]any
	json.NewDecoder(rr.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)
	oldSecret := regResp["client_secret"].(string)

	// Mint token with old secret
	oldToken, _ := admin.MintResourceToken("user-1", clientID, oldSecret, admin.AppQuota{}, []string{"read"}, nil)

	// Rotate with grace period
	rotBody, _ := json.Marshal(map[string]any{"grace_period": "1h"})
	req = httptest.NewRequest(http.MethodPost, "/apps/"+clientID+"/rotate", bytes.NewReader(rotBody))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	regHandler.ServeHTTP(rr, req)

	var rotResp map[string]any
	json.NewDecoder(rr.Body).Decode(&rotResp)
	newSecret := rotResp["client_secret"].(string)

	if rotResp["previous_kid"] == nil || rotResp["previous_kid"] == "" {
		t.Error("expected previous_kid in rotation response")
	}
	if rotResp["grace_period"] == nil {
		t.Error("expected grace_period in rotation response")
	}

	// Build composite resolver: KeyStore (current keys) + KidStore (old keys)
	composite := &keys.CompositeKeyLookup{Lookups: []keys.KeyLookup{ks, kidStore}}

	middleware := &apiauth.APIMiddleware{KeyStore: composite}
	okHandler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Old token should still work (grace period active)
	req = httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	rr = httptest.NewRecorder()
	okHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("old token during grace: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// New token should work
	newToken, _ := admin.MintResourceToken("user-1", clientID, newSecret, admin.AppQuota{}, []string{"read"}, nil)
	req = httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+newToken)
	rr = httptest.NewRecorder()
	okHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("new token after rotation: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAppRegistrar_RotateExpiredGrace(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	kidStore := keys.NewKidStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registrar.KidStore = kidStore
	registrar.DefaultGracePeriod = 1 * time.Millisecond // tiny grace for testing
	regHandler := registrar.Handler()

	// Register
	body, _ := json.Marshal(map[string]any{"client_domain": "expire-test.com"})
	req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	regHandler.ServeHTTP(rr, req)

	var regResp map[string]any
	json.NewDecoder(rr.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)
	oldSecret := regResp["client_secret"].(string)

	oldToken, _ := admin.MintResourceToken("user-1", clientID, oldSecret, admin.AppQuota{}, []string{"read"}, nil)

	// Rotate (uses default tiny grace period)
	req = httptest.NewRequest(http.MethodPost, "/apps/"+clientID+"/rotate", nil)
	rr = httptest.NewRecorder()
	regHandler.ServeHTTP(rr, req)

	// Wait for grace period to expire
	time.Sleep(5 * time.Millisecond)

	composite := &keys.CompositeKeyLookup{Lookups: []keys.KeyLookup{ks, kidStore}}
	middleware := &apiauth.APIMiddleware{KeyStore: composite}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for expired grace token")
	}))

	// Old token should now fail (grace expired)
	req = httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("old token after grace expired: expected 401, got %d", rr.Code)
	}
}
