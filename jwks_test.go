package oneauth

// Tests for JWKSHandler: serving the /.well-known/jwks.json endpoint with correct
// key filtering (asymmetric only), response format, Cache-Control, and Content-Type headers.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/panyam/oneauth/utils"
)

// TestJWKSHandler_MixedKeys verifies that JWKSHandler exposes only asymmetric keys (RS256)
// and excludes symmetric keys (HS256) from the JWKS response.
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
	// kid is now a computed thumbprint, not the clientID
	if jwkSet.Keys[0].Kid == "" {
		t.Error("expected non-empty kid")
	}
	if jwkSet.Keys[0].Kid == "app_rsa" {
		t.Error("kid should be a thumbprint, not the clientID")
	}
	if jwkSet.Keys[0].Kty != "RSA" {
		t.Errorf("expected kty=RSA, got %s", jwkSet.Keys[0].Kty)
	}
}

// TestJWKSHandler_RSAAndECDSA verifies that JWKSHandler includes both RSA and ECDSA
// public keys in the JWKS response.
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

	// Verify we got 2 keys with distinct non-empty thumbprint kids
	kids := map[string]bool{}
	for _, k := range jwkSet.Keys {
		if k.Kid == "" {
			t.Error("expected non-empty kid")
		}
		kids[k.Kid] = true
	}
	if len(kids) != 2 {
		t.Errorf("expected 2 distinct kids, got %d", len(kids))
	}
}

// TestJWKSHandler_EmptyStore verifies that JWKSHandler returns an empty keys array
// when no keys are registered.
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

// TestJWKSHandler_CacheControl verifies that JWKSHandler sets the Cache-Control header
// based on the configured CacheMaxAge.
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

// TestJWKSHandler_ContentType verifies that JWKSHandler responds with application/json content type.
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
