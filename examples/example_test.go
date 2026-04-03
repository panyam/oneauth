package examples_test

// Runnable Example* functions demonstrating OneAuth's federated authentication flows.
// Each example is fully self-contained: in-memory stores, httptest servers, real HTTP calls.
// Run with: go test -run Example -v ./examples/

import (
	"bytes"
	"crypto/rsa"
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// ExampleAppRegistrar_hs256FederatedFlow demonstrates the full HS256 lifecycle:
// register an app via HTTP, mint a resource token, and validate it on a resource server.
func ExampleAppRegistrar_hs256FederatedFlow() {
	// Auth server with AppRegistrar
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	authServer := httptest.NewServer(registrar.Handler())
	defer authServer.Close()

	// Register an HS256 app via HTTP
	body, _ := json.Marshal(map[string]any{
		"client_domain": "myapp.example.com",
		"signing_alg":   "HS256",
	})
	resp, _ := http.Post(authServer.URL+"/apps/register", "application/json", bytes.NewReader(body))
	var regResp map[string]any
	json.NewDecoder(resp.Body).Decode(&regResp)
	resp.Body.Close()

	clientID := regResp["client_id"].(string)
	clientSecret := regResp["client_secret"].(string)
	fmt.Println("registered:", clientID != "" && clientSecret != "")

	// App mints a resource token for user "alice"
	token, err := admin.MintResourceToken("alice", clientID, clientSecret,
		admin.AppQuota{MaxRooms: 10}, []string{"read", "write"})
	fmt.Println("token_minted:", err == nil && token != "")

	// Resource server validates tokens using the same KeyStore
	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	resSrv := httptest.NewServer(middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"user":"%s"}`, apiauth.GetUserIDFromAPIContext(r.Context()))
	})))
	defer resSrv.Close()

	// Call resource server with the token
	req, _ := http.NewRequest("GET", resSrv.URL+"/data", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, _ := http.DefaultClient.Do(req)
	resBody, _ := io.ReadAll(res.Body)
	res.Body.Close()

	fmt.Println("resource_status:", res.StatusCode)
	var resData map[string]string
	json.Unmarshal(resBody, &resData)
	fmt.Println("user:", resData["user"])

	// Output:
	// registered: true
	// token_minted: true
	// resource_status: 200
	// user: alice
}

// ExampleAppRegistrar_rs256WithJWKS demonstrates the asymmetric (RS256) flow:
// register with a public key, serve JWKS, and let the resource server discover
// keys automatically via the /.well-known/jwks.json endpoint.
func ExampleAppRegistrar_rs256WithJWKS() {
	// Auth server: AppRegistrar + JWKS endpoint
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	jwksHandler := &keys.JWKSHandler{KeyStore: ks}

	mux := http.NewServeMux()
	mux.Handle("/apps/", registrar.Handler())
	mux.Handle("/.well-known/jwks.json", jwksHandler)
	authServer := httptest.NewServer(mux)
	defer authServer.Close()

	// Generate RSA key pair; register with the public key
	privPEM, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)

	body, _ := json.Marshal(map[string]any{
		"client_domain": "myapp.example.com",
		"signing_alg":   "RS256",
		"public_key":    string(pubPEM),
	})
	resp, _ := http.Post(authServer.URL+"/apps/register", "application/json", bytes.NewReader(body))
	var regResp map[string]any
	json.NewDecoder(resp.Body).Decode(&regResp)
	resp.Body.Close()

	clientID := regResp["client_id"].(string)
	fmt.Println("registered:", clientID != "")
	fmt.Println("no_secret:", regResp["client_secret"] == nil)

	// Verify JWKS serves the public key
	jwksResp, _ := http.Get(authServer.URL + "/.well-known/jwks.json")
	var jwkSet utils.JWKSet
	json.NewDecoder(jwksResp.Body).Decode(&jwkSet)
	jwksResp.Body.Close()
	fmt.Println("jwks_keys:", len(jwkSet.Keys))

	// Resource server discovers keys via JWKS
	resKeyStore := keys.NewJWKSKeyStore(authServer.URL+"/.well-known/jwks.json", keys.WithMinRefreshGap(0))
	resKeyStore.Start()
	defer resKeyStore.Stop()

	middleware := &apiauth.APIMiddleware{KeyStore: resKeyStore}
	resSrv := httptest.NewServer(middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"user":"%s"}`, apiauth.GetUserIDFromAPIContext(r.Context()))
	})))
	defer resSrv.Close()

	// App mints token with its private key
	token, _ := admin.MintResourceTokenWithKey("bob", clientID, privKey, admin.AppQuota{}, []string{"read"})

	req, _ := http.NewRequest("GET", resSrv.URL+"/data", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, _ := http.DefaultClient.Do(req)
	resBody, _ := io.ReadAll(res.Body)
	res.Body.Close()

	fmt.Println("resource_status:", res.StatusCode)
	var resData map[string]string
	json.Unmarshal(resBody, &resData)
	fmt.Println("user:", resData["user"])

	// Output:
	// registered: true
	// no_secret: true
	// jwks_keys: 1
	// resource_status: 200
	// user: bob
}

// ExampleAPIMiddleware_kidBasedLookup demonstrates kid (Key ID) headers in JWTs
// and how the middleware uses kid-based key lookup for multi-app validation.
func ExampleAPIMiddleware_kidBasedLookup() {
	ks := keys.NewInMemoryKeyStore()

	// Register an HS256 app and an RS256 app in the same KeyStore
	ks.RegisterKey("app-hs256", []byte("my-secret"), "HS256")
	privPEM, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	ks.RegisterKey("app-rs256", pubPEM, "RS256")

	// Mint tokens — both get kid headers automatically
	hsToken, _ := admin.MintResourceToken("alice", "app-hs256", "my-secret", admin.AppQuota{}, []string{"read"})
	rsToken, _ := admin.MintResourceTokenWithKey("bob", "app-rs256", privKey, admin.AppQuota{}, []string{"read"})

	// Verify kid headers are present
	parser := jwt.NewParser()
	hsParsed, _, _ := parser.ParseUnverified(hsToken, jwt.MapClaims{})
	rsParsed, _, _ := parser.ParseUnverified(rsToken, jwt.MapClaims{})
	fmt.Println("hs256_has_kid:", hsParsed.Header["kid"] != nil && hsParsed.Header["kid"] != "")
	fmt.Println("rs256_has_kid:", rsParsed.Header["kid"] != nil && rsParsed.Header["kid"] != "")

	// Validate both via middleware (kid-based lookup)
	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, tc := range []struct{ name, token string }{
		{"hs256", hsToken},
		{"rs256", rsToken},
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/resource", nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		handler.ServeHTTP(rr, req)
		fmt.Printf("%s_valid: %v\n", tc.name, rr.Code == http.StatusOK)
	}

	// Demonstrate kid-based lookup directly
	kid := hsParsed.Header["kid"].(string)
	rec, _ := ks.GetKeyByKid(kid)
	fmt.Println("kid_lookup_alg:", rec.Algorithm)

	// Output:
	// hs256_has_kid: true
	// rs256_has_kid: true
	// hs256_valid: true
	// rs256_valid: true
	// kid_lookup_alg: HS256
}

// ExampleCompositeKeyLookup_keyRotationGracePeriod demonstrates key rotation
// with a grace period: old tokens continue to work during the grace window,
// then fail after it expires.
func ExampleCompositeKeyLookup_keyRotationGracePeriod() {
	ks := keys.NewInMemoryKeyStore()
	kidStore := keys.NewKidStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registrar.KidStore = kidStore
	registrar.DefaultGracePeriod = 50 * time.Millisecond
	regHandler := registrar.Handler()

	// Register an app
	body, _ := json.Marshal(map[string]any{"client_domain": "example.com"})
	req := httptest.NewRequest("POST", "/apps/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	regHandler.ServeHTTP(rr, req)

	var regResp map[string]any
	json.NewDecoder(rr.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)
	oldSecret := regResp["client_secret"].(string)

	// Mint token with old secret
	oldToken, _ := admin.MintResourceToken("alice", clientID, oldSecret, admin.AppQuota{}, []string{"read"})

	// Rotate key (uses DefaultGracePeriod of 50ms)
	req = httptest.NewRequest("POST", "/apps/"+clientID+"/rotate", nil)
	rr = httptest.NewRecorder()
	regHandler.ServeHTTP(rr, req)

	var rotResp map[string]any
	json.NewDecoder(rr.Body).Decode(&rotResp)
	newSecret := rotResp["client_secret"].(string)
	newToken, _ := admin.MintResourceToken("alice", clientID, newSecret, admin.AppQuota{}, []string{"read"})

	// Build composite: current keys + grace period keys
	composite := &keys.CompositeKeyLookup{Lookups: []keys.KeyLookup{ks, kidStore}}
	middleware := &apiauth.APIMiddleware{KeyStore: composite}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	checkToken := func(token string) int {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/resource", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	// During grace period: old token still works
	fmt.Println("old_token_during_grace:", checkToken(oldToken))
	fmt.Println("new_token:", checkToken(newToken))

	// Wait for grace period to expire
	time.Sleep(60 * time.Millisecond)

	// After grace: old token fails
	fmt.Println("old_token_after_grace:", checkToken(oldToken))

	// Output:
	// old_token_during_grace: 200
	// new_token: 200
	// old_token_after_grace: 401
}

// ExampleAPIMiddleware_crossAppIsolation demonstrates that cross-app token forgery
// is rejected: a token signed by app A but claiming app B's client_id is denied
// because the kid owner doesn't match the client_id claim.
func ExampleAPIMiddleware_crossAppIsolation() {
	ks := keys.NewInMemoryKeyStore()
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	regHandler := registrar.Handler()

	// Register two HS256 apps
	var clientIDs [2]string
	var secrets [2]string
	for i, domain := range []string{"app-a.com", "app-b.com"} {
		body, _ := json.Marshal(map[string]any{"client_domain": domain})
		req := httptest.NewRequest("POST", "/apps/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		regHandler.ServeHTTP(rr, req)
		var resp map[string]any
		json.NewDecoder(rr.Body).Decode(&resp)
		clientIDs[i] = resp["client_id"].(string)
		secrets[i] = resp["client_secret"].(string)
	}

	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	checkToken := func(token string) int {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/resource", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	// Cross-app forgery: mint with app A's secret but claim app B's client_id.
	// The kid is derived from app A's secret, so kid owner != client_id claim.
	crossToken, _ := admin.MintResourceToken("eve", clientIDs[1], secrets[0], admin.AppQuota{}, []string{"read"})
	fmt.Println("cross_app_token:", checkToken(crossToken))

	// Correct token: app A's secret with app A's client_id
	correctToken, _ := admin.MintResourceToken("alice", clientIDs[0], secrets[0], admin.AppQuota{}, []string{"read"})
	fmt.Println("correct_token:", checkToken(correctToken))

	// Output:
	// cross_app_token: 401
	// correct_token: 200
}

// ExampleJWKSHandler_securityProperties demonstrates the JWKS security guarantees:
// - Only public key components are served (no private fields)
// - HS256 symmetric secrets are excluded
// - Every JWK includes key_ops: ["verify"] restricting usage
// - The JWK struct structurally cannot carry private key fields (d, p, q, etc.)
func ExampleJWKSHandler_securityProperties() {
	ks := keys.NewInMemoryKeyStore()

	// Register one HS256 (symmetric) and one RS256 (asymmetric) app
	ks.RegisterKey("app-secret", []byte("my-hs256-secret"), "HS256")
	_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	ks.RegisterKey("app-public", pubPEM, "RS256")

	// Serve JWKS
	jwksHandler := &keys.JWKSHandler{KeyStore: ks}
	srv := httptest.NewServer(http.HandlerFunc(jwksHandler.ServeHTTP))
	defer srv.Close()

	resp, _ := http.Get(srv.URL)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Parse as raw JSON to inspect every field
	var raw map[string]any
	json.Unmarshal(body, &raw)
	jwksKeys := raw["keys"].([]any)

	// Only asymmetric key appears (HS256 secret excluded)
	fmt.Println("jwks_key_count:", len(jwksKeys))

	// Inspect the RSA key entry
	rsaKey := jwksKeys[0].(map[string]any)
	fmt.Println("kty:", rsaKey["kty"])
	fmt.Println("alg:", rsaKey["alg"])
	fmt.Println("use:", rsaKey["use"])
	fmt.Println("has_kid:", rsaKey["kid"] != nil && rsaKey["kid"] != "")
	fmt.Println("has_n:", rsaKey["n"] != nil)
	fmt.Println("has_e:", rsaKey["e"] != nil)

	// key_ops restricts to verification only
	keyOps := rsaKey["key_ops"].([]any)
	fmt.Println("key_ops:", keyOps[0])

	// Private key fields are structurally absent
	for _, field := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if rsaKey[field] != nil {
			fmt.Printf("LEAK: %s found\n", field)
		}
	}
	fmt.Println("private_fields_absent: true")

	// Output:
	// jwks_key_count: 1
	// kty: RSA
	// alg: RS256
	// use: sig
	// has_kid: true
	// has_n: true
	// has_e: true
	// key_ops: verify
	// private_fields_absent: true
}

// ExampleJWKSHandler_multiAlgorithm demonstrates that HS256 and RS256 apps
// coexist in the same KeyStore, but only asymmetric keys appear in JWKS.
// RS256 tokens validate via JWKS; HS256 tokens are rejected (secrets never exposed).
func ExampleJWKSHandler_multiAlgorithm() {
	ks := keys.NewInMemoryKeyStore()

	// Register one HS256 app and one RS256 app
	ks.RegisterKey("app-hmac", []byte("shared-secret"), "HS256")
	privPEM, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	ks.RegisterKey("app-rsa", pubPEM, "RS256")

	ids, _ := ks.ListKeyIDs()
	fmt.Println("total_apps:", len(ids))

	// Serve JWKS (only asymmetric keys appear)
	jwksHandler := &keys.JWKSHandler{KeyStore: ks}
	authServer := httptest.NewServer(http.HandlerFunc(jwksHandler.ServeHTTP))
	defer authServer.Close()

	resp, _ := http.Get(authServer.URL)
	var jwkSet utils.JWKSet
	json.NewDecoder(resp.Body).Decode(&jwkSet)
	resp.Body.Close()
	fmt.Println("jwks_keys:", len(jwkSet.Keys))

	// Resource server uses JWKS for key discovery
	resKeyStore := keys.NewJWKSKeyStore(authServer.URL, keys.WithMinRefreshGap(0))
	resKeyStore.Start()
	defer resKeyStore.Stop()

	middleware := &apiauth.APIMiddleware{KeyStore: resKeyStore}
	resSrv := httptest.NewServer(middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer resSrv.Close()

	// RS256 token validates via JWKS
	rsToken, _ := admin.MintResourceTokenWithKey("alice", "app-rsa", privKey, admin.AppQuota{}, []string{"read"})
	req, _ := http.NewRequest("GET", resSrv.URL, nil)
	req.Header.Set("Authorization", "Bearer "+rsToken)
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	fmt.Println("rs256_via_jwks:", res.StatusCode)

	// HS256 token fails via JWKS (secrets are never exposed)
	hsToken, _ := admin.MintResourceToken("bob", "app-hmac", "shared-secret", admin.AppQuota{}, []string{"read"})
	req, _ = http.NewRequest("GET", resSrv.URL, nil)
	req.Header.Set("Authorization", "Bearer "+hsToken)
	res, _ = http.DefaultClient.Do(req)
	res.Body.Close()
	fmt.Println("hs256_via_jwks:", res.StatusCode)

	// Output:
	// total_apps: 2
	// jwks_keys: 1
	// rs256_via_jwks: 200
	// hs256_via_jwks: 401
}

// ExampleAPIMiddleware_algorithmConfusionPrevention demonstrates the classic
// JWT algorithm confusion attack (CVE-2015-9235) and how OneAuth prevents it.
//
// The attack: An RS256 app registers a public key. The attacker knows this
// public key (it's public, served via JWKS). The attacker crafts a JWT with
// alg:HS256 and signs it using the RSA public key bytes as the HMAC secret.
// A naive server would read alg:HS256 from the header, grab the stored key
// bytes, and verify the HMAC — which passes because the attacker used those
// same bytes to sign.
//
// OneAuth's defense: The middleware checks that the token's alg header matches
// the KeyRecord.Algorithm stored for that client. Since the store says "RS256"
// but the token says "HS256", the mismatch is caught before any signature
// verification happens.
//
//	Normal flow (safe):
//	  App signs JWT with RSA private key → alg: RS256
//	  Middleware: token alg "RS256" == stored alg "RS256" → verify RSA sig ✓
//
//	Attack flow (blocked):
//	  Attacker signs JWT with RSA public key as HMAC → alg: HS256
//	  Middleware: token alg "HS256" != stored alg "RS256" → REJECT ✗
func ExampleAPIMiddleware_algorithmConfusionPrevention() {
	// Setup: RS256 app with public key in KeyStore
	privKey, _ := rsa.GenerateKey(cryptorand.Reader, 2048)
	pubPEM, _ := utils.EncodePublicKeyPEM(&privKey.PublicKey)

	ks := keys.NewInMemoryKeyStore()
	ks.RegisterKey("app-rsa", pubPEM, "RS256")

	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	checkToken := func(label, token string) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/resource", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(rr, req)
		fmt.Printf("%s: %d\n", label, rr.Code)
	}

	// 1. Legitimate RS256 token — signed with the private key
	legit := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "alice", "client_id": "app-rsa", "type": "access",
		"scopes": []string{"read"}, "exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	if kid, err := utils.ComputeKid(&privKey.PublicKey, "RS256"); err == nil {
		legit.Header["kid"] = kid
	}
	legitToken, _ := legit.SignedString(privKey)
	checkToken("legitimate_rs256", legitToken)

	// 2. Algorithm confusion attack — signed with public key bytes as HMAC secret
	attack := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "attacker", "client_id": "app-rsa", "type": "access",
		"scopes": []string{"admin"}, "exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	attackToken, _ := attack.SignedString(pubPEM) // using public key as HMAC secret!
	checkToken("alg_confusion_attack", attackToken)

	// 3. alg:none attack — no signature at all
	none := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "attacker", "client_id": "app-rsa", "type": "access",
		"scopes": []string{"admin"}, "exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	noneToken, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	checkToken("alg_none_attack", noneToken)

	// Output:
	// legitimate_rs256: 200
	// alg_confusion_attack: 401
	// alg_none_attack: 401
}
