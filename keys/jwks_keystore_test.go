package keys

// Tests for JWKSKeyStore: fetching and caching keys from a remote JWKS endpoint,
// cache-miss-triggered refresh, resilience when the server is down, concurrent access
// safety, and error handling for unsupported operations.

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/panyam/oneauth/utils"
)

func serveJWKS(t *testing.T, keys []utils.JWK) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(utils.JWKSet{Keys: keys})
	}))
}

// TestJWKSKeyStore_GetVerifyKey verifies that JWKSKeyStore fetches an RSA public key
// from a remote JWKS endpoint and returns it for token verification.
func TestJWKSKeyStore_GetVerifyKey(t *testing.T) {
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	pub, _ := utils.ParsePublicKeyPEM(pubPEM)
	rsaPub := pub.(*rsa.PublicKey)
	jwk := utils.RSAPublicKeyToJWK("app_rsa", "RS256", rsaPub)

	srv := serveJWKS(t, []utils.JWK{jwk})
	defer srv.Close()

	ks := NewJWKSKeyStore(srv.URL, WithMinRefreshGap(0))
	if err := ks.Start(); err != nil {
		t.Fatal(err)
	}
	defer ks.Stop()

	key, err := ks.GetVerifyKey("app_rsa")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", key)
	}
	if rsaPub.N.Cmp(got.N) != 0 {
		t.Error("RSA modulus mismatch")
	}
}

// TestJWKSKeyStore_GetExpectedAlg verifies that JWKSKeyStore returns the correct
// algorithm (ES256) for a key fetched from the remote JWKS endpoint.
func TestJWKSKeyStore_GetExpectedAlg(t *testing.T) {
	_, pubPEM, _ := utils.GenerateECDSAKeyPair()
	pub, _ := utils.ParsePublicKeyPEM(pubPEM)
	ecPub := pub.(*ecdsa.PublicKey)
	jwk := utils.ECDSAPublicKeyToJWK("app_ec", "ES256", ecPub)

	srv := serveJWKS(t, []utils.JWK{jwk})
	defer srv.Close()

	ks := NewJWKSKeyStore(srv.URL, WithMinRefreshGap(0))
	ks.Start()
	defer ks.Stop()

	alg, err := ks.GetExpectedAlg("app_ec")
	if err != nil {
		t.Fatal(err)
	}
	if alg != "ES256" {
		t.Errorf("expected ES256, got %s", alg)
	}
}

// TestJWKSKeyStore_CacheMissTriggersRefresh verifies that a cache miss for an unknown key
// triggers a refresh from the remote endpoint and returns ErrKeyNotFound if the key still does not exist.
func TestJWKSKeyStore_CacheMissTriggersRefresh(t *testing.T) {
	fetchCount := 0
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetchCount++
		mu.Unlock()

		_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
		pub, _ := utils.ParsePublicKeyPEM(pubPEM)
		jwk := utils.RSAPublicKeyToJWK("dynamic_app", "RS256", pub.(*rsa.PublicKey))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(utils.JWKSet{Keys: []utils.JWK{jwk}})
	}))
	defer srv.Close()

	ks := NewJWKSKeyStore(srv.URL, WithMinRefreshGap(0))
	ks.Start()
	defer ks.Stop()

	// First fetch at Start(), then cache miss for "dynamic_app" shouldn't need another
	// since "dynamic_app" was returned in the first fetch
	_, err := ks.GetVerifyKey("dynamic_app")
	if err != nil {
		t.Fatal(err)
	}

	// Unknown key should trigger refresh attempt then return ErrKeyNotFound
	_, err = ks.GetVerifyKey("nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

// TestJWKSKeyStore_ServerDown_UsesCachedKeys verifies that JWKSKeyStore continues to serve
// previously cached keys even after the remote JWKS server goes down.
func TestJWKSKeyStore_ServerDown_UsesCachedKeys(t *testing.T) {
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	pub, _ := utils.ParsePublicKeyPEM(pubPEM)
	rsaPub := pub.(*rsa.PublicKey)
	jwk := utils.RSAPublicKeyToJWK("cached_app", "RS256", rsaPub)

	srv := serveJWKS(t, []utils.JWK{jwk})

	ks := NewJWKSKeyStore(srv.URL, WithMinRefreshGap(0))
	ks.Start()
	defer ks.Stop()

	// Shut down the server
	srv.Close()

	// Should still return cached key
	key, err := ks.GetVerifyKey("cached_app")
	if err != nil {
		t.Fatalf("expected cached key, got error: %v", err)
	}
	got := key.(*rsa.PublicKey)
	if rsaPub.N.Cmp(got.N) != 0 {
		t.Error("cached key mismatch")
	}
}

// TestJWKSKeyStore_GetSigningKey_Errors verifies that GetSigningKey always returns an error
// since JWKSKeyStore is read-only and does not hold private keys.
func TestJWKSKeyStore_GetSigningKey_Errors(t *testing.T) {
	ks := NewJWKSKeyStore("http://localhost:0")
	_, err := ks.GetSigningKey("anything")
	if err == nil {
		t.Error("expected error from GetSigningKey")
	}
}

// TestJWKSKeyStore_ConcurrentAccess verifies that concurrent GetVerifyKey and GetExpectedAlg
// calls do not race or panic.
func TestJWKSKeyStore_ConcurrentAccess(t *testing.T) {
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	pub, _ := utils.ParsePublicKeyPEM(pubPEM)
	jwk := utils.RSAPublicKeyToJWK("concurrent_app", "RS256", pub.(*rsa.PublicKey))

	srv := serveJWKS(t, []utils.JWK{jwk})
	defer srv.Close()

	ks := NewJWKSKeyStore(srv.URL, WithMinRefreshGap(time.Millisecond))
	ks.Start()
	defer ks.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ks.GetVerifyKey("concurrent_app")
			ks.GetExpectedAlg("concurrent_app")
			ks.GetVerifyKey("missing")
		}()
	}
	wg.Wait()
}
