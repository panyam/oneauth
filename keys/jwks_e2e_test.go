package keys_test

// End-to-end tests for the full federated authentication flow: app registration,
// token minting, and middleware validation across HS256, RS256, and ES256 algorithms.
// Includes JWKS-based discovery tests where the resource server fetches public keys
// from the auth server's /.well-known/jwks.json endpoint.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// ============================================================================
// Symmetric (HS256) end-to-end federated flow tests
// ============================================================================

// TestFederated_EndToEnd_HS256 exercises the full symmetric federated flow:
// 1. Register an HS256 app via AppRegistrar HTTP API
// 2. Mint a resource token with the returned client_secret
// 3. Validate the token via APIMiddleware backed by the same KeyStore
func TestFederated_EndToEnd_HS256(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	regHandler := registrar.Handler()

	// --- Step 1: Register app via HTTP ---
	body, _ := json.Marshal(map[string]any{
		"client_name": "e2e-symmetric.com",
		"signing_alg":   "HS256",
	})
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	regHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var regResp map[string]any
	json.NewDecoder(rr.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)
	clientSecret := regResp["client_secret"].(string)

	// --- Step 2: Mint a resource token ---
	tokenStr, err := admin.MintResourceToken(
		"user-alice", clientID, []byte(clientSecret),
		map[string]any{"max_rooms": 10, "max_msg_rate": 30},
		[]string{"collab", "read"}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	// --- Step 3: Validate via APIMiddleware ---
	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	var gotUserID string
	var gotClaims map[string]any
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = apiauth.GetSubjectFromAPIContext(r.Context())
		gotClaims = apiauth.GetCustomClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req = httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("validate: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if gotUserID != "user-alice" {
		t.Errorf("userID = %s, want user-alice", gotUserID)
	}
	if gotClaims["client_id"] != clientID {
		t.Errorf("client_id = %v, want %s", gotClaims["client_id"], clientID)
	}
}

// TestFederated_EndToEnd_HS256_WrongSecret verifies a token minted with
// the wrong secret is rejected by the middleware.
func TestFederated_EndToEnd_HS256_WrongSecret(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	regHandler := registrar.Handler()

	body, _ := json.Marshal(map[string]any{"client_name": "wrong-secret.com"})
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	regHandler.ServeHTTP(rr, req)

	var regResp map[string]any
	json.NewDecoder(rr.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)

	// Mint with wrong secret
	tokenStr, _ := admin.MintResourceToken("user-eve", clientID, []byte("totally-wrong-secret"), nil, []string{"read"}, nil)

	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for wrong secret")
	}))

	req = httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestFederated_EndToEnd_HS256_CrossAppRejection verifies that a token minted
// by app A is rejected when presented with app B's client_id (different secret).
func TestFederated_EndToEnd_HS256_CrossAppRejection(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	regHandler := registrar.Handler()

	// Register two apps
	var clientIDs [2]string
	var secrets [2]string
	for i, domain := range []string{"app-a.com", "app-b.com"} {
		body, _ := json.Marshal(map[string]any{"client_name": domain})
		req := httptest.NewRequest(http.MethodPost, "/apps/dcr", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		regHandler.ServeHTTP(rr, req)
		var resp map[string]any
		json.NewDecoder(rr.Body).Decode(&resp)
		clientIDs[i] = resp["client_id"].(string)
		secrets[i] = resp["client_secret"].(string)
	}

	// Mint token with app A's secret but claim app B's client_id
	tokenStr, _ := admin.MintResourceToken("user-1", clientIDs[1], []byte(secrets[0]), nil, []string{"read"}, nil)

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

// TestFederated_EndToEnd_HS256_SecretRotation verifies that after rotating
// an app's secret, old tokens fail and new tokens succeed.
func TestFederated_EndToEnd_HS256_SecretRotation(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	regHandler := registrar.Handler()

	// Register
	body, _ := json.Marshal(map[string]any{"client_name": "rotate-e2e.com"})
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	regHandler.ServeHTTP(rr, req)
	var regResp map[string]any
	json.NewDecoder(rr.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)
	oldSecret := regResp["client_secret"].(string)

	// Mint with old secret
	oldToken, _ := admin.MintResourceToken("user-1", clientID, []byte(oldSecret), nil, []string{"read"}, nil)

	// Rotate
	req = httptest.NewRequest(http.MethodPost, "/apps/"+clientID+"/rotate", nil)
	rr = httptest.NewRecorder()
	regHandler.ServeHTTP(rr, req)
	var rotResp map[string]any
	json.NewDecoder(rr.Body).Decode(&rotResp)
	newSecret := rotResp["client_secret"].(string)

	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	okHandler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Old token should fail
	req = httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	rr = httptest.NewRecorder()
	okHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("old token after rotation: expected 401, got %d", rr.Code)
	}

	// New token should succeed
	newToken, _ := admin.MintResourceToken("user-1", clientID, []byte(newSecret), nil, []string{"read"}, nil)
	req = httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+newToken)
	rr = httptest.NewRecorder()
	okHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("new token after rotation: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestFederated_EndToEnd_RS256_ViaRegistrar exercises the full asymmetric flow
// against a KeyStore populated directly (post-#189 DCR uses JWKS rather than
// the legacy /apps/register PEM-string surface; direct PutKey is the simplest
// setup for this e2e validation slice).
func TestFederated_EndToEnd_RS256_ViaRegistrar(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()

	privPEM, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)

	clientID := "e2e-asymmetric.com"
	if _, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID:  clientID,
		Key:       pubPEM,
		Algorithm: "RS256",
	}}); err != nil {
		t.Fatalf("PutKey: %v", err)
	}

	// Mint with private key
	tokenStr, _ := admin.MintResourceToken("alice", clientID, privKey, map[string]any{"max_rooms": 5}, []string{"read"}, nil)

	// Validate via middleware
	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	var gotUserID string
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = apiauth.GetSubjectFromAPIContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("validate: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if gotUserID != "alice" {
		t.Errorf("userID = %s, want alice", gotUserID)
	}
}

// ============================================================================
// JWKS end-to-end tests (asymmetric keys via JWKS discovery)
// ============================================================================

// TestJWKS_EndToEnd_RS256 exercises the full federated flow with no external servers:
// 1. Register an RS256 app in an in-memory KeyStore
// 2. Serve JWKS from that KeyStore via httptest
// 3. Create a JWKSKeyStore pointing at the httptest server
// 4. Mint a token with the app's private key
// 5. Validate the token using APIMiddleware backed by the JWKSKeyStore
func TestJWKS_EndToEnd_RS256(t *testing.T) {
	// --- Auth server side: register app ---
	authKeyStore := keys.NewInMemoryKeyStore()
	privPEM, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	_, _ = authKeyStore.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app_rsa_e2e", Key: pubPEM, Algorithm: "RS256"}})

	// Also register an HS256 app (should NOT appear in JWKS)
	_, _ = authKeyStore.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app_hmac_e2e", Key: []byte("secret123"), Algorithm: "HS256"}})

	// --- Auth server side: serve JWKS ---
	jwksHandler := &keys.JWKSHandler{KeyStore: authKeyStore}
	authServer := httptest.NewServer(http.HandlerFunc(jwksHandler.ServeHTTP))
	defer authServer.Close()

	// --- Resource server side: fetch keys via JWKS ---
	resourceKeyStore := keys.NewJWKSKeyStore(authServer.URL, keys.WithMinRefreshGap(0))
	if err := resourceKeyStore.Start(); err != nil {
		t.Fatal(err)
	}
	defer resourceKeyStore.Stop()

	// --- App side: mint a resource token ---
	tokenStr, err := admin.MintResourceToken(
		"alice", "app_rsa_e2e", privKey,
		map[string]any{"max_rooms": 10, "max_msg_rate": 50},
		[]string{"collab", "read"}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	// --- Resource server side: validate the token ---
	middleware := &apiauth.APIMiddleware{KeyStore: resourceKeyStore}
	var gotUserID string
	var gotClaims map[string]any
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = apiauth.GetSubjectFromAPIContext(r.Context())
		gotClaims = apiauth.GetCustomClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if gotUserID != "alice" {
		t.Errorf("userID = %s, want alice", gotUserID)
	}
	if gotClaims["client_id"] != "app_rsa_e2e" {
		t.Errorf("client_id = %v, want app_rsa_e2e", gotClaims["client_id"])
	}
}

// TestJWKS_EndToEnd_ES256 exercises the same flow with ECDSA keys.
func TestJWKS_EndToEnd_ES256(t *testing.T) {
	authKeyStore := keys.NewInMemoryKeyStore()
	privPEM, pubPEM, err := utils.GenerateECDSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	_, _ = authKeyStore.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app_ec_e2e", Key: pubPEM, Algorithm: "ES256"}})

	jwksHandler := &keys.JWKSHandler{KeyStore: authKeyStore}
	authServer := httptest.NewServer(http.HandlerFunc(jwksHandler.ServeHTTP))
	defer authServer.Close()

	resourceKeyStore := keys.NewJWKSKeyStore(authServer.URL, keys.WithMinRefreshGap(0))
	resourceKeyStore.Start()
	defer resourceKeyStore.Stop()

	tokenStr, err := admin.MintResourceToken(
		"bob", "app_ec_e2e", privKey,
		map[string]any{"max_rooms": 5},
		[]string{"write"}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	middleware := &apiauth.APIMiddleware{KeyStore: resourceKeyStore}
	var gotUserID string
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = apiauth.GetSubjectFromAPIContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if gotUserID != "bob" {
		t.Errorf("userID = %s, want bob", gotUserID)
	}
}

// TestJWKS_EndToEnd_HS256Excluded verifies HS256 tokens cannot be validated
// via JWKS (since HS256 secrets are never exposed).
func TestJWKS_EndToEnd_HS256Excluded(t *testing.T) {
	authKeyStore := keys.NewInMemoryKeyStore()
	_, _ = authKeyStore.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app_hmac", Key: []byte("supersecret"), Algorithm: "HS256"}})

	jwksHandler := &keys.JWKSHandler{KeyStore: authKeyStore}
	authServer := httptest.NewServer(http.HandlerFunc(jwksHandler.ServeHTTP))
	defer authServer.Close()

	// Verify JWKS returns empty keys
	resp, _ := http.Get(authServer.URL)
	var jwkSet utils.JWKSet
	json.NewDecoder(resp.Body).Decode(&jwkSet)
	resp.Body.Close()
	if len(jwkSet.Keys) != 0 {
		t.Fatalf("expected 0 keys in JWKS, got %d", len(jwkSet.Keys))
	}

	// JWKSKeyStore can't validate HS256 tokens
	resourceKeyStore := keys.NewJWKSKeyStore(authServer.URL, keys.WithMinRefreshGap(0))
	resourceKeyStore.Start()
	defer resourceKeyStore.Stop()

	tokenStr, _ := admin.MintResourceToken("user1", "app_hmac", []byte("supersecret"), nil, []string{"read"}, nil)

	middleware := &apiauth.APIMiddleware{KeyStore: resourceKeyStore}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for HS256 token via JWKS")
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for HS256 via JWKS, got %d", rr.Code)
	}
}

// TestJWKS_EndToEnd_WrongPrivateKey verifies that a token signed with
// a different private key is rejected even though the JWKS has a valid key.
func TestJWKS_EndToEnd_WrongPrivateKey(t *testing.T) {
	authKeyStore := keys.NewInMemoryKeyStore()
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	_, _ = authKeyStore.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app_rsa", Key: pubPEM, Algorithm: "RS256"}})

	// Mint with a DIFFERENT private key
	otherPrivPEM, _, _ := utils.GenerateRSAKeyPair(2048)
	otherPrivKey, _ := utils.ParsePrivateKeyPEM(otherPrivPEM)

	jwksHandler := &keys.JWKSHandler{KeyStore: authKeyStore}
	authServer := httptest.NewServer(http.HandlerFunc(jwksHandler.ServeHTTP))
	defer authServer.Close()

	resourceKeyStore := keys.NewJWKSKeyStore(authServer.URL, keys.WithMinRefreshGap(0))
	resourceKeyStore.Start()
	defer resourceKeyStore.Stop()

	tokenStr, _ := admin.MintResourceToken("eve", "app_rsa", otherPrivKey, nil, []string{"read"}, nil)

	middleware := &apiauth.APIMiddleware{KeyStore: resourceKeyStore}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for forged token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong private key, got %d", rr.Code)
	}
}

// TestJWKS_EndToEnd_MixedAlgorithms verifies RS256 and ES256 apps
// coexist in the same JWKS and both validate correctly.
func TestJWKS_EndToEnd_MixedAlgorithms(t *testing.T) {
	authKeyStore := keys.NewInMemoryKeyStore()

	rsaPrivPEM, rsaPubPEM, _ := utils.GenerateRSAKeyPair(2048)
	rsaPrivKey, _ := utils.ParsePrivateKeyPEM(rsaPrivPEM)
	_, _ = authKeyStore.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app_rsa_mix", Key: rsaPubPEM, Algorithm: "RS256"}})

	ecPrivPEM, ecPubPEM, _ := utils.GenerateECDSAKeyPair()
	ecPrivKey, _ := utils.ParsePrivateKeyPEM(ecPrivPEM)
	_, _ = authKeyStore.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app_ec_mix", Key: ecPubPEM, Algorithm: "ES256"}})

	// Also HS256 (should be invisible to JWKS)
	_, _ = authKeyStore.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app_hs_mix", Key: []byte("secret"), Algorithm: "HS256"}})

	jwksHandler := &keys.JWKSHandler{KeyStore: authKeyStore}
	authServer := httptest.NewServer(http.HandlerFunc(jwksHandler.ServeHTTP))
	defer authServer.Close()

	resourceKeyStore := keys.NewJWKSKeyStore(authServer.URL, keys.WithMinRefreshGap(0))
	resourceKeyStore.Start()
	defer resourceKeyStore.Stop()

	middleware := &apiauth.APIMiddleware{KeyStore: resourceKeyStore}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name     string
		userID   string
		clientID string
		key      any
	}{
		{"RS256", "alice", "app_rsa_mix", rsaPrivKey},
		{"ES256", "bob", "app_ec_mix", ecPrivKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenStr, _ := admin.MintResourceToken(tt.userID, tt.clientID, tt.key, nil, []string{"read"}, nil)
			req := httptest.NewRequest(http.MethodGet, "/resource", nil)
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
			}
		})
	}
}
