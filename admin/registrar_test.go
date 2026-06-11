package admin_test

// Tests for the AppRegistrar HTTP API: app registration (HS256/RS256), listing, retrieval,
// deletion, secret/key rotation, admin auth enforcement, and input validation.

import (
	"context"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/keys"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setupRegistrar(t *testing.T) (*admin.AppRegistrar, *keys.InMemoryKeyStore) {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	reg := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	return reg, ks
}

// TestAppRegistrar_Register verifies that registering an HS256 app returns a client_id and
// client_secret, and that the key is correctly stored in the KeyStore.
func TestAppRegistrar_Register(t *testing.T) {
	reg, ks := setupRegistrar(t)
	handler := reg.Handler()

	body, _ := json.Marshal(map[string]any{
		"client_name": "excaliframe.com",
		"signing_alg":   "HS256",
	})

	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", bytes.NewReader(body))
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
	keyResp_, err := ks.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: clientID}); var key any; if keyResp_ != nil { key = keyResp_.Record.Key }
	if err != nil {
		t.Fatalf("Key should be stored: %v", err)
	}
	if string(key.([]byte)) != secret {
		t.Error("Stored key should match returned secret")
	}

	algResp_, _ := ks.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: clientID}); var alg string; if algResp_ != nil { alg = algResp_.Record.Algorithm }
	if alg != "HS256" {
		t.Errorf("Expected alg HS256, got %s", alg)
	}
}


// TestAppRegistrar_ListApps verifies that GET /apps returns all registered apps.
func TestAppRegistrar_ListApps(t *testing.T) {
	reg, _ := setupRegistrar(t)
	handler := reg.Handler()

	// Register two apps
	for _, domain := range []string{"alpha.com", "beta.com"} {
		body, _ := json.Marshal(map[string]any{"client_name": domain})
		req := httptest.NewRequest(http.MethodPost, "/apps/dcr", bytes.NewReader(body))
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
		"client_name": "excaliframe.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", bytes.NewReader(body))
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
	body, _ := json.Marshal(map[string]any{"client_name": "delete-me.com"})
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", bytes.NewReader(body))
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
	_Resp_, err := ks.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: clientID}); var _ any; if _Resp_ != nil { _ = _Resp_.Record.Key }
	if err != keys.ErrKeyNotFound {
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
	body, _ := json.Marshal(map[string]any{"client_name": "rotate-me.com"})
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", bytes.NewReader(body))
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
	keyResp_, _ := ks.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: clientID}); var key any; if keyResp_ != nil { key = keyResp_.Record.Key }
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

// TestAppRegistrar_AdminAuth_ReadEndpoints tests that GET endpoints also require auth
func TestAppRegistrar_AdminAuth_ReadEndpoints(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	reg := &admin.AppRegistrar{
		KeyStore: ks,
		Auth:     admin.NewAPIKeyAuth("admin-key"),
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

// RS256 registration / rotation coverage lives in dcr_test.go — RFC 7591
// DCR is the only registration path.
