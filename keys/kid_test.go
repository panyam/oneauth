package keys_test

// Tests for kid (Key ID) in JWT headers, KidResolver, KidStore grace periods,
// kid-based JWT verification, and AppRegistrar rotation with grace.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

func putKidKey(t *testing.T, ks keys.KeyStorage, rec *keys.KeyRecord) {
	t.Helper()
	if _, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: rec}); err != nil {
		t.Fatalf("PutKey failed: %v", err)
	}
}

func currentKid(t *testing.T, ks keys.KeyStorage, clientID string) string {
	t.Helper()
	resp, err := ks.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: clientID})
	if err != nil {
		t.Fatalf("GetKey(%s) failed: %v", clientID, err)
	}
	return resp.Record.Kid
}

func TestMintResourceToken_HasKid(t *testing.T) {
	secret := "test-secret-for-kid"
	tokenStr, err := admin.MintResourceToken("user-1", "app-1", secret, admin.AppQuota{}, []string{"read"}, nil)
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
		t.Fatal("expected kid header in minted JWT")
	}
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
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	putKidKey(t, ks, &keys.KeyRecord{ClientID: "app-rsa", Key: pubPEM, Algorithm: "RS256"})

	handler := &keys.JWKSHandler{KeyStore: ks}
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var jwkSet utils.JWKSet
	json.NewDecoder(rec.Body).Decode(&jwkSet)

	if len(jwkSet.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwkSet.Keys))
	}

	jwkKid := jwkSet.Keys[0].Kid
	if jwkKid == "app-rsa" {
		t.Error("JWKS kid should be a thumbprint, not clientID")
	}
	pubKey, _ := utils.DecodeVerifyKey(pubPEM, "RS256")
	expectedKid, _ := utils.ComputeKid(pubKey, "RS256")
	if jwkKid != expectedKid {
		t.Errorf("JWKS kid=%s, expected thumbprint=%s", jwkKid, expectedKid)
	}
}

func TestInMemoryKeyStore_KidResolver(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	secret := []byte("my-secret")
	putKidKey(t, ks, &keys.KeyRecord{ClientID: "app-1", Key: secret, Algorithm: "HS256"})

	kid := currentKid(t, ks, "app-1")
	expectedKid, _ := utils.ComputeKid(secret, "HS256")
	if kid != expectedKid {
		t.Errorf("kid=%s, want %s", kid, expectedKid)
	}

	resp, err := ks.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: kid})
	if err != nil {
		t.Fatal(err)
	}
	rec := resp.Record
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
	_, err := ks.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: "nonexistent-kid"})
	if err != keys.ErrKidNotFound {
		t.Errorf("expected ErrKidNotFound, got %v", err)
	}
}

func TestInMemoryKeyStore_KidUpdatesOnOverwrite(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	putKidKey(t, ks, &keys.KeyRecord{ClientID: "app-1", Key: []byte("old-secret"), Algorithm: "HS256"})
	oldKid := currentKid(t, ks, "app-1")

	putKidKey(t, ks, &keys.KeyRecord{ClientID: "app-1", Key: []byte("new-secret"), Algorithm: "HS256"})
	newKid := currentKid(t, ks, "app-1")

	if oldKid == newKid {
		t.Error("kid should change when key changes")
	}

	if _, err := ks.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: oldKid}); err != keys.ErrKidNotFound {
		t.Errorf("old kid should not resolve after overwrite, got %v", err)
	}
	if _, err := ks.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: newKid}); err != nil {
		t.Errorf("new kid should resolve: %v", err)
	}
}

func TestInMemoryKeyStore_KidCleanedOnDelete(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	putKidKey(t, ks, &keys.KeyRecord{ClientID: "app-1", Key: []byte("secret"), Algorithm: "HS256"})
	kid := currentKid(t, ks, "app-1")

	if _, err := ks.DeleteKey(context.Background(), &keys.DeleteKeyRequest{ClientID: "app-1"}); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	if _, err := ks.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: kid}); err != keys.ErrKidNotFound {
		t.Errorf("kid should not resolve after delete, got %v", err)
	}
}

func addKidEntry(t *testing.T, store *keys.KidStore, req *keys.AddKidRequest) {
	t.Helper()
	if _, err := store.Add(context.Background(), req); err != nil {
		t.Fatalf("KidStore.Add failed: %v", err)
	}
}

func TestKidStore_BasicAddAndLookup(t *testing.T) {
	store := keys.NewKidStore()
	addKidEntry(t, store, &keys.AddKidRequest{Kid: "kid-1", Key: []byte("secret"), Algorithm: "HS256", ClientID: "app-1"})

	resp, err := store.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: "kid-1"})
	if err != nil {
		t.Fatal(err)
	}
	rec := resp.Record
	if string(rec.Key.([]byte)) != "secret" || rec.Algorithm != "HS256" || rec.ClientID != "app-1" {
		t.Error("unexpected values from KidStore lookup")
	}
}

func TestKidStore_ExpiredKeyNotReturned(t *testing.T) {
	store := keys.NewKidStore()
	addKidEntry(t, store, &keys.AddKidRequest{Kid: "kid-old", Key: []byte("old-secret"), Algorithm: "HS256", ClientID: "app-1", ExpiresAt: time.Now().Add(-1 * time.Hour)})

	_, err := store.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: "kid-old"})
	if err != keys.ErrKidNotFound {
		t.Errorf("expected ErrKidNotFound for expired key, got %v", err)
	}
}

func TestKidStore_NonExpiredKeyReturned(t *testing.T) {
	store := keys.NewKidStore()
	addKidEntry(t, store, &keys.AddKidRequest{Kid: "kid-old", Key: []byte("old-secret"), Algorithm: "HS256", ClientID: "app-1", ExpiresAt: time.Now().Add(1 * time.Hour)})

	resp, err := store.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: "kid-old"})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Record.Key.([]byte)) != "old-secret" {
		t.Error("expected old secret for non-expired key")
	}
}

func TestKidStore_CleanExpired(t *testing.T) {
	store := keys.NewKidStore()
	addKidEntry(t, store, &keys.AddKidRequest{Kid: "kid-alive", Key: []byte("a"), Algorithm: "HS256", ClientID: "app-1", ExpiresAt: time.Now().Add(1 * time.Hour)})
	addKidEntry(t, store, &keys.AddKidRequest{Kid: "kid-dead", Key: []byte("b"), Algorithm: "HS256", ClientID: "app-2", ExpiresAt: time.Now().Add(-1 * time.Hour)})

	if store.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", store.Len())
	}

	if _, err := store.CleanExpired(context.Background(), &keys.CleanExpiredRequest{}); err != nil {
		t.Fatalf("CleanExpired failed: %v", err)
	}

	if store.Len() != 1 {
		t.Fatalf("expected 1 entry after cleanup, got %d", store.Len())
	}
}

func TestCompositeKidResolver(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	putKidKey(t, ks, &keys.KeyRecord{ClientID: "app-1", Key: []byte("current-secret"), Algorithm: "HS256"})
	curKid := currentKid(t, ks, "app-1")

	kidStore := keys.NewKidStore()
	addKidEntry(t, kidStore, &keys.AddKidRequest{Kid: "old-kid", Key: []byte("old-secret"), Algorithm: "HS256", ClientID: "app-1", ExpiresAt: time.Now().Add(1 * time.Hour)})

	composite := &keys.CompositeKeyLookup{Lookups: []keys.KeyLookup{ks, kidStore}}

	if _, err := composite.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: curKid}); err != nil {
		t.Errorf("current kid should resolve: %v", err)
	}

	resp, err := composite.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: "old-kid"})
	if err != nil {
		t.Errorf("old kid should resolve: %v", err)
	} else if string(resp.Record.Key.([]byte)) != "old-secret" {
		t.Error("expected old secret")
	}

	if _, err := composite.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: "unknown"}); err != keys.ErrKidNotFound {
		t.Errorf("expected ErrKidNotFound, got %v", err)
	}
}

func TestValidateJWT_WithKid(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	secret := []byte("test-secret")
	putKidKey(t, ks, &keys.KeyRecord{ClientID: "app-1", Key: secret, Algorithm: "HS256"})

	tokenStr, _ := admin.MintResourceToken("user-1", "app-1", string(secret), admin.AppQuota{}, []string{"read"}, nil)

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
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if gotUserID != "user-1" {
		t.Errorf("userID=%s, want user-1", gotUserID)
	}
}

func TestValidateJWT_LegacyNoKid(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	secret := []byte("test-secret")
	putKidKey(t, ks, &keys.KeyRecord{ClientID: "app-1", Key: secret, Algorithm: "HS256"})

	claims := jwt.MapClaims{
		"sub":       "user-1",
		"client_id": "app-1",
		"type":      "access",
		"scopes":    []string{"read"},
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := token.SignedString(secret)

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
		t.Fatalf("legacy token without kid: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if gotUserID != "user-1" {
		t.Errorf("userID=%s, want user-1", gotUserID)
	}
}

func TestValidateJWT_CrossAppRejectedViaKid(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	putKidKey(t, ks, &keys.KeyRecord{ClientID: "app-a", Key: []byte("secret-a"), Algorithm: "HS256"})
	putKidKey(t, ks, &keys.KeyRecord{ClientID: "app-b", Key: []byte("secret-b"), Algorithm: "HS256"})

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

func TestAppRegistrar_RotateWithGrace(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	kidStore := keys.NewKidStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registrar.KidStore = kidStore
	regHandler := registrar.Handler()

	body, _ := json.Marshal(map[string]any{"client_domain": "grace-test.com"})
	req := httptest.NewRequest(http.MethodPost, "/apps/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	regHandler.ServeHTTP(rr, req)

	var regResp map[string]any
	json.NewDecoder(rr.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)
	oldSecret := regResp["client_secret"].(string)

	oldToken, _ := admin.MintResourceToken("user-1", clientID, oldSecret, admin.AppQuota{}, []string{"read"}, nil)

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

	composite := &keys.CompositeKeyLookup{Lookups: []keys.KeyLookup{ks, kidStore}}
	middleware := &apiauth.APIMiddleware{KeyStore: composite}
	okHandler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req = httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	rr = httptest.NewRecorder()
	okHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("old token during grace: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

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
	registrar.DefaultGracePeriod = 1 * time.Millisecond
	regHandler := registrar.Handler()

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

	req = httptest.NewRequest(http.MethodPost, "/apps/"+clientID+"/rotate", nil)
	rr = httptest.NewRecorder()
	regHandler.ServeHTTP(rr, req)

	time.Sleep(5 * time.Millisecond)

	composite := &keys.CompositeKeyLookup{Lookups: []keys.KeyLookup{ks, kidStore}}
	middleware := &apiauth.APIMiddleware{KeyStore: composite}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for expired grace token")
	}))

	req = httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("old token after grace expired: expected 401, got %d", rr.Code)
	}
}
