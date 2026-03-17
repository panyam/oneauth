package oneauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/panyam/oneauth/utils"
)

func TestJWKSHandler_MixedKeys(t *testing.T) {
	ks := NewInMemoryKeyStore()

	// Register HS256 key (should NOT appear)
	ks.RegisterKey("app_hmac", []byte("secret"), "HS256")

	// Register RS256 key (should appear)
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	ks.RegisterKey("app_rsa", pubPEM, "RS256")

	handler := &JWKSHandler{KeyStore: ks}
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var jwkSet utils.JWKSet
	if err := json.NewDecoder(rec.Body).Decode(&jwkSet); err != nil {
		t.Fatal(err)
	}
	if len(jwkSet.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwkSet.Keys))
	}
	if jwkSet.Keys[0].Kid != "app_rsa" {
		t.Errorf("expected kid=app_rsa, got %s", jwkSet.Keys[0].Kid)
	}
	if jwkSet.Keys[0].Kty != "RSA" {
		t.Errorf("expected kty=RSA, got %s", jwkSet.Keys[0].Kty)
	}
}

func TestJWKSHandler_RSAAndECDSA(t *testing.T) {
	ks := NewInMemoryKeyStore()

	_, rsaPub, _ := utils.GenerateRSAKeyPair(2048)
	ks.RegisterKey("app_rsa", rsaPub, "RS256")

	_, ecPub, _ := utils.GenerateECDSAKeyPair()
	ks.RegisterKey("app_ec", ecPub, "ES256")

	handler := &JWKSHandler{KeyStore: ks}
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var jwkSet utils.JWKSet
	json.NewDecoder(rec.Body).Decode(&jwkSet)

	if len(jwkSet.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(jwkSet.Keys))
	}

	found := map[string]bool{}
	for _, k := range jwkSet.Keys {
		found[k.Kid] = true
	}
	if !found["app_rsa"] || !found["app_ec"] {
		t.Errorf("expected both app_rsa and app_ec, got %v", found)
	}
}

func TestJWKSHandler_EmptyStore(t *testing.T) {
	ks := NewInMemoryKeyStore()
	handler := &JWKSHandler{KeyStore: ks}
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var jwkSet utils.JWKSet
	json.NewDecoder(rec.Body).Decode(&jwkSet)

	if len(jwkSet.Keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(jwkSet.Keys))
	}
}

func TestJWKSHandler_CacheControl(t *testing.T) {
	ks := NewInMemoryKeyStore()
	handler := &JWKSHandler{KeyStore: ks, CacheMaxAge: 1800}
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	cc := rec.Header().Get("Cache-Control")
	if cc != "public, max-age=1800" {
		t.Errorf("expected 'public, max-age=1800', got '%s'", cc)
	}
}

func TestJWKSHandler_ContentType(t *testing.T) {
	ks := NewInMemoryKeyStore()
	handler := &JWKSHandler{KeyStore: ks}
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected 'application/json', got '%s'", ct)
	}
}
