package keys

// Tests for JWKSKeyStore: fetching and caching keys from a remote JWKS endpoint,
// cache-miss-triggered refresh, resilience when the server is down, concurrent access
// safety.

import (
	"context"
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

func TestJWKSKeyStore_GetKeyByKid_RSA(t *testing.T) {
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

	resp, err := ks.GetKeyByKid(context.Background(), &GetKeyByKidRequest{Kid: "app_rsa"})
	if err != nil {
		t.Fatal(err)
	}
	rec := resp.Record
	got, ok := rec.Key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", rec.Key)
	}
	if rsaPub.N.Cmp(got.N) != 0 {
		t.Error("RSA modulus mismatch")
	}
	if rec.Algorithm != "RS256" {
		t.Errorf("expected RS256, got %s", rec.Algorithm)
	}
}

func TestJWKSKeyStore_GetKey_AlwaysNotFound(t *testing.T) {
	// JWKSKeyStore.GetKey by clientID must always return ErrKeyNotFound.
	ks := NewJWKSKeyStore("http://localhost:0")
	_, err := ks.GetKey(context.Background(), &GetKeyRequest{ClientID: "anything"})
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

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

	if _, err := ks.GetKeyByKid(context.Background(), &GetKeyByKidRequest{Kid: "dynamic_app"}); err != nil {
		t.Fatal(err)
	}

	if _, err := ks.GetKeyByKid(context.Background(), &GetKeyByKidRequest{Kid: "nonexistent"}); err != ErrKidNotFound {
		t.Errorf("expected ErrKidNotFound, got %v", err)
	}
}

func TestJWKSKeyStore_ServerDown_UsesCachedKeys(t *testing.T) {
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	pub, _ := utils.ParsePublicKeyPEM(pubPEM)
	rsaPub := pub.(*rsa.PublicKey)
	jwk := utils.RSAPublicKeyToJWK("cached_app", "RS256", rsaPub)

	srv := serveJWKS(t, []utils.JWK{jwk})

	ks := NewJWKSKeyStore(srv.URL, WithMinRefreshGap(0))
	ks.Start()
	defer ks.Stop()

	srv.Close()

	resp, err := ks.GetKeyByKid(context.Background(), &GetKeyByKidRequest{Kid: "cached_app"})
	if err != nil {
		t.Fatalf("expected cached key, got error: %v", err)
	}
	got := resp.Record.Key.(*rsa.PublicKey)
	if rsaPub.N.Cmp(got.N) != 0 {
		t.Error("cached key mismatch")
	}
}

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
			ks.GetKeyByKid(context.Background(), &GetKeyByKidRequest{Kid: "concurrent_app"})
			ks.GetKeyByKid(context.Background(), &GetKeyByKidRequest{Kid: "missing"})
		}()
	}
	wg.Wait()
}
