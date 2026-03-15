package oneauth_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	oa "github.com/panyam/oneauth"
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
