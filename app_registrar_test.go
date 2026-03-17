package oneauth_test

// Tests for the AppRegistrar HTTP API: app registration (HS256/RS256), listing, retrieval,
// deletion, secret/key rotation, admin auth enforcement, and input validation.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/utils"
)

func setupRegistrar(t *testing.T) (*oa.AppRegistrar, *oa.InMemoryKeyStore) {
	t.Helper()
	ks := oa.NewInMemoryKeyStore()
	reg := &oa.AppRegistrar{
		KeyStore: ks,
		Auth:     oa.NewNoAuth(),
	}
	return reg, ks
}

// TestAppRegistrar_Register verifies that registering an HS256 app returns a client_id and
// client_secret, and that the key is correctly stored in the KeyStore.
func TestAppRegistrar_Register(t *testing.T) {
	reg, ks := setupRegistrar(t)
	handler := reg.Handler()

	body, _ := json.Marshal(map[string]any{
		"client_domain": "excaliframe.com",
		"signing_alg":   "HS256",
		"max_rooms":     10,
		"max_msg_rate":  30.0,
	})

	req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)

	clientID, ok := resp["client_id"].(string)
	if !ok || clientID == "" {
		t.Fatal("Expected non-empty client_id in response")
	}
	secret, ok := resp["client_secret"].(string)
	if !ok || secret == "" {
		t.Fatal("Expected non-empty client_secret in response")
	}

	// Verify key was stored
	key, err := ks.GetVerifyKey(clientID)
	if err != nil {
		t.Fatalf("Key should be stored: %v", err)
	}
	if string(key.([]byte)) != secret {
		t.Error("Stored key should match returned secret")
	}

	alg, _ := ks.GetExpectedAlg(clientID)
	if alg != "HS256" {
		t.Errorf("Expected alg HS256, got %s", alg)
	}
}

// TestAppRegistrar_Register_DefaultAlg verifies that omitting signing_alg defaults to HS256.
func TestAppRegistrar_Register_DefaultAlg(t *testing.T) {
	reg, _ := setupRegistrar(t)
	handler := reg.Handler()

	body, _ := json.Marshal(map[string]any{
		"client_domain": "example.com",
	})

	req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)

	// Should default to HS256
	if resp["signing_alg"] != "HS256" {
		t.Errorf("Expected default alg HS256, got %v", resp["signing_alg"])
	}
}

// TestAppRegistrar_ListApps verifies that GET /apps returns all registered apps.
func TestAppRegistrar_ListApps(t *testing.T) {
	reg, _ := setupRegistrar(t)
	handler := reg.Handler()

	// Register two apps
	for _, domain := range []string{"alpha.com", "beta.com"} {
		body, _ := json.Marshal(map[string]any{"client_domain": domain})
		req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("Register %s failed: %d %s", domain, rr.Code, rr.Body.String())
		}
	}

	// List
	req := httptest.NewRequest(http.MethodGet, "/apps", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	apps, ok := resp["apps"].([]any)
	if !ok {
		t.Fatal("Expected apps array in response")
	}
	if len(apps) != 2 {
		t.Errorf("Expected 2 apps, got %d", len(apps))
	}
}

// TestAppRegistrar_GetApp verifies that GET /apps/{id} returns app metadata
// without exposing the client_secret.
func TestAppRegistrar_GetApp(t *testing.T) {
	reg, _ := setupRegistrar(t)
	handler := reg.Handler()

	// Register
	body, _ := json.Marshal(map[string]any{
		"client_domain": "excaliframe.com",
		"max_rooms":     5,
	})
	req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	var regResp map[string]any
	json.NewDecoder(rr.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)

	// Get
	req = httptest.NewRequest(http.MethodGet, "/apps/"+clientID, nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["client_id"] != clientID {
		t.Errorf("Expected client_id %s, got %v", clientID, resp["client_id"])
	}
	if resp["client_domain"] != "excaliframe.com" {
		t.Errorf("Expected domain excaliframe.com, got %v", resp["client_domain"])
	}
	// Secret should NOT be returned in GET
	if _, exists := resp["client_secret"]; exists {
		t.Error("GET should not return client_secret")
	}
}

// TestAppRegistrar_GetApp_NotFound verifies that GET /apps/{id} returns 404 for unknown apps.
func TestAppRegistrar_GetApp_NotFound(t *testing.T) {
	reg, _ := setupRegistrar(t)
	handler := reg.Handler()

	req := httptest.NewRequest(http.MethodGet, "/apps/nonexistent", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", rr.Code)
	}
}

// TestAppRegistrar_DeleteApp verifies that deleting an app removes it from the KeyStore.
func TestAppRegistrar_DeleteApp(t *testing.T) {
	reg, ks := setupRegistrar(t)
	handler := reg.Handler()

	// Register
	body, _ := json.Marshal(map[string]any{"client_domain": "delete-me.com"})
	req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	var regResp map[string]any
	json.NewDecoder(rr.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)

	// Delete
	req = httptest.NewRequest(http.MethodDelete, "/apps/"+clientID, nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	// Should be gone from KeyStore
	_, err := ks.GetVerifyKey(clientID)
	if err != oa.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound after delete, got %v", err)
	}
}

// TestAppRegistrar_DeleteApp_NotFound verifies that deleting a nonexistent app returns 404.
func TestAppRegistrar_DeleteApp_NotFound(t *testing.T) {
	reg, _ := setupRegistrar(t)
	handler := reg.Handler()

	req := httptest.NewRequest(http.MethodDelete, "/apps/nonexistent", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", rr.Code)
	}
}

// TestAppRegistrar_RotateSecret verifies that rotating an HS256 app's secret produces
// a new secret and updates the KeyStore.
func TestAppRegistrar_RotateSecret(t *testing.T) {
	reg, ks := setupRegistrar(t)
	handler := reg.Handler()

	// Register
	body, _ := json.Marshal(map[string]any{"client_domain": "rotate-me.com"})
	req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	var regResp map[string]any
	json.NewDecoder(rr.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)
	oldSecret := regResp["client_secret"].(string)

	// Rotate
	req = httptest.NewRequest(http.MethodPost, "/apps/"+clientID+"/rotate", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var rotResp map[string]any
	json.NewDecoder(rr.Body).Decode(&rotResp)
	newSecret := rotResp["client_secret"].(string)

	if newSecret == oldSecret {
		t.Error("New secret should differ from old secret")
	}
	if newSecret == "" {
		t.Error("New secret should not be empty")
	}

	// KeyStore should have the new secret
	key, _ := ks.GetVerifyKey(clientID)
	if string(key.([]byte)) != newSecret {
		t.Error("KeyStore should have the rotated secret")
	}
}

// TestAppRegistrar_RotateSecret_NotFound verifies that rotating a nonexistent app returns 404.
func TestAppRegistrar_RotateSecret_NotFound(t *testing.T) {
	reg, _ := setupRegistrar(t)
	handler := reg.Handler()

	req := httptest.NewRequest(http.MethodPost, "/apps/nonexistent/rotate", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", rr.Code)
	}
}

// TestAppRegistrar_AdminAuth_APIKey tests that admin auth is enforced
func TestAppRegistrar_AdminAuth_APIKey(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()
	reg := &oa.AppRegistrar{
		KeyStore: ks,
		Auth:     oa.NewAPIKeyAuth("super-secret-admin-key"),
	}
	handler := reg.Handler()

	body, _ := json.Marshal(map[string]any{"client_domain": "test.com"})

	// No auth header — should be 401
	t.Run("no auth header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", rr.Code)
		}
	})

	// Wrong key — should be 403
	t.Run("wrong key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Key", "wrong-key")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected 403, got %d", rr.Code)
		}
	})

	// Correct key — should succeed
	t.Run("correct key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Key", "super-secret-admin-key")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			t.Errorf("Expected 201, got %d. Body: %s", rr.Code, rr.Body.String())
		}
	})
}

// TestAppRegistrar_AdminAuth_ReadEndpoints tests that GET endpoints also require auth
func TestAppRegistrar_AdminAuth_ReadEndpoints(t *testing.T) {
	ks := oa.NewInMemoryKeyStore()
	reg := &oa.AppRegistrar{
		KeyStore: ks,
		Auth:     oa.NewAPIKeyAuth("admin-key"),
	}
	handler := reg.Handler()

	// List without auth
	req := httptest.NewRequest(http.MethodGet, "/apps", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("List without auth: expected 401, got %d", rr.Code)
	}

	// List with auth
	req = httptest.NewRequest(http.MethodGet, "/apps", nil)
	req.Header.Set("X-Admin-Key", "admin-key")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("List with auth: expected 200, got %d", rr.Code)
	}
}

// TestAppRegistrar_Register_RS256 verifies that registering an RS256 app stores the public key
// in the KeyStore and does not return a client_secret.
func TestAppRegistrar_Register_RS256(t *testing.T) {
	reg, ks := setupRegistrar(t)
	handler := reg.Handler()

	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)

	body, _ := json.Marshal(map[string]any{
		"client_domain": "asymmetric-app.com",
		"signing_alg":   "RS256",
		"public_key":    string(pubPEM),
	})

	req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)

	// Should have client_id but NOT client_secret
	if resp["client_id"] == nil || resp["client_id"] == "" {
		t.Fatal("Expected non-empty client_id")
	}
	if _, hasSecret := resp["client_secret"]; hasSecret {
		t.Error("RS256 registration should not return client_secret")
	}
	if resp["signing_alg"] != "RS256" {
		t.Errorf("Expected signing_alg RS256, got %v", resp["signing_alg"])
	}

	// Verify key stored as PEM bytes
	clientID := resp["client_id"].(string)
	key, _ := ks.GetVerifyKey(clientID)
	if string(key.([]byte)) != string(pubPEM) {
		t.Error("Stored key should be the public key PEM")
	}
	alg, _ := ks.GetExpectedAlg(clientID)
	if alg != "RS256" {
		t.Errorf("Expected alg RS256, got %s", alg)
	}
}

// TestAppRegistrar_Register_RS256_MissingPublicKey verifies that RS256 registration
// without a public_key field returns 400.
func TestAppRegistrar_Register_RS256_MissingPublicKey(t *testing.T) {
	reg, _ := setupRegistrar(t)
	handler := reg.Handler()

	body, _ := json.Marshal(map[string]any{
		"client_domain": "no-key.com",
		"signing_alg":   "RS256",
		// no public_key
	})

	req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

// TestAppRegistrar_Register_RS256_InvalidPEM verifies that RS256 registration
// with an invalid PEM string returns 400.
func TestAppRegistrar_Register_RS256_InvalidPEM(t *testing.T) {
	reg, _ := setupRegistrar(t)
	handler := reg.Handler()

	body, _ := json.Marshal(map[string]any{
		"client_domain": "bad-pem.com",
		"signing_alg":   "RS256",
		"public_key":    "not-a-valid-pem",
	})

	req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

// TestAppRegistrar_RotateKey_RS256 verifies that rotating an RS256 app's public key
// updates the KeyStore and does not return a client_secret.
func TestAppRegistrar_RotateKey_RS256(t *testing.T) {
	reg, ks := setupRegistrar(t)
	handler := reg.Handler()

	// Register with RS256
	_, pubPEM1, _ := utils.GenerateRSAKeyPair(2048)
	body, _ := json.Marshal(map[string]any{
		"client_domain": "rotate-asym.com",
		"signing_alg":   "RS256",
		"public_key":    string(pubPEM1),
	})
	req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	var regResp map[string]any
	json.NewDecoder(rr.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)

	// Rotate with new public key
	_, pubPEM2, _ := utils.GenerateRSAKeyPair(2048)
	rotBody, _ := json.Marshal(map[string]any{
		"public_key": string(pubPEM2),
	})
	req = httptest.NewRequest(http.MethodPost, "/apps/"+clientID+"/rotate", bytes.NewReader(rotBody))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var rotResp map[string]any
	json.NewDecoder(rr.Body).Decode(&rotResp)

	// Should NOT have client_secret
	if _, hasSecret := rotResp["client_secret"]; hasSecret {
		t.Error("RS256 rotation should not return client_secret")
	}

	// KeyStore should have the new key
	key, _ := ks.GetVerifyKey(clientID)
	if string(key.([]byte)) != string(pubPEM2) {
		t.Error("KeyStore should have the rotated public key")
	}
}

// TestAppRegistrar_RotateKey_RS256_MissingKey verifies that rotating an RS256 app
// without providing a new public_key returns 400.
func TestAppRegistrar_RotateKey_RS256_MissingKey(t *testing.T) {
	reg, _ := setupRegistrar(t)
	handler := reg.Handler()

	// Register with RS256
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	body, _ := json.Marshal(map[string]any{
		"client_domain": "rotate-fail.com",
		"signing_alg":   "RS256",
		"public_key":    string(pubPEM),
	})
	req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	var regResp map[string]any
	json.NewDecoder(rr.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)

	// Rotate without public_key — should fail
	req = httptest.NewRequest(http.MethodPost, "/apps/"+clientID+"/rotate", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}
