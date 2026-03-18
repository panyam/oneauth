package examples_test

// Runnable Example* functions demonstrating OneAuth's federated authentication flows.
// Each example is fully self-contained: in-memory stores, httptest servers, real HTTP calls.
// Run with: go test -run Example -v ./examples/

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/utils"
)

// ExampleAppRegistrar_hs256FederatedFlow demonstrates the full HS256 lifecycle:
// register an app via HTTP, mint a resource token, and validate it on a resource server.
func ExampleAppRegistrar_hs256FederatedFlow() {
	// Auth server with AppRegistrar
	ks := oa.NewInMemoryKeyStore()
	registrar := &oa.AppRegistrar{KeyStore: ks, Auth: oa.NewNoAuth()}
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
	token, err := oa.MintResourceToken("alice", clientID, clientSecret,
		oa.AppQuota{MaxRooms: 10}, []string{"read", "write"})
	fmt.Println("token_minted:", err == nil && token != "")

	// Resource server validates tokens using the same KeyStore
	middleware := &oa.APIMiddleware{KeyStore: ks}
	resSrv := httptest.NewServer(middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"user":"%s"}`, oa.GetUserIDFromAPIContext(r.Context()))
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
	ks := oa.NewInMemoryKeyStore()
	registrar := &oa.AppRegistrar{KeyStore: ks, Auth: oa.NewNoAuth()}
	jwksHandler := &oa.JWKSHandler{KeyStore: ks}

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
	resKeyStore := oa.NewJWKSKeyStore(authServer.URL+"/.well-known/jwks.json", oa.WithMinRefreshGap(0))
	resKeyStore.Start()
	defer resKeyStore.Stop()

	middleware := &oa.APIMiddleware{KeyStore: resKeyStore}
	resSrv := httptest.NewServer(middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"user":"%s"}`, oa.GetUserIDFromAPIContext(r.Context()))
	})))
	defer resSrv.Close()

	// App mints token with its private key
	token, _ := oa.MintResourceTokenWithKey("bob", clientID, privKey, oa.AppQuota{}, []string{"read"})

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
	ks := oa.NewInMemoryKeyStore()

	// Register an HS256 app and an RS256 app in the same KeyStore
	ks.RegisterKey("app-hs256", []byte("my-secret"), "HS256")
	privPEM, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	ks.RegisterKey("app-rs256", pubPEM, "RS256")

	// Mint tokens — both get kid headers automatically
	hsToken, _ := oa.MintResourceToken("alice", "app-hs256", "my-secret", oa.AppQuota{}, []string{"read"})
	rsToken, _ := oa.MintResourceTokenWithKey("bob", "app-rs256", privKey, oa.AppQuota{}, []string{"read"})

	// Verify kid headers are present
	parser := jwt.NewParser()
	hsParsed, _, _ := parser.ParseUnverified(hsToken, jwt.MapClaims{})
	rsParsed, _, _ := parser.ParseUnverified(rsToken, jwt.MapClaims{})
	fmt.Println("hs256_has_kid:", hsParsed.Header["kid"] != nil && hsParsed.Header["kid"] != "")
	fmt.Println("rs256_has_kid:", rsParsed.Header["kid"] != nil && rsParsed.Header["kid"] != "")

	// Validate both via middleware (kid-based lookup)
	middleware := &oa.APIMiddleware{KeyStore: ks}
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
	ks := oa.NewInMemoryKeyStore()
	kidStore := oa.NewKidStore()
	registrar := &oa.AppRegistrar{
		KeyStore:           ks,
		Auth:               oa.NewNoAuth(),
		KidStore:           kidStore,
		DefaultGracePeriod: 50 * time.Millisecond,
	}
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
	oldToken, _ := oa.MintResourceToken("alice", clientID, oldSecret, oa.AppQuota{}, []string{"read"})

	// Rotate key (uses DefaultGracePeriod of 50ms)
	req = httptest.NewRequest("POST", "/apps/"+clientID+"/rotate", nil)
	rr = httptest.NewRecorder()
	regHandler.ServeHTTP(rr, req)

	var rotResp map[string]any
	json.NewDecoder(rr.Body).Decode(&rotResp)
	newSecret := rotResp["client_secret"].(string)
	newToken, _ := oa.MintResourceToken("alice", clientID, newSecret, oa.AppQuota{}, []string{"read"})

	// Build composite: current keys + grace period keys
	composite := &oa.CompositeKeyLookup{Lookups: []oa.KeyLookup{ks, kidStore}}
	middleware := &oa.APIMiddleware{KeyStore: composite}
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
	ks := oa.NewInMemoryKeyStore()
	registrar := &oa.AppRegistrar{KeyStore: ks, Auth: oa.NewNoAuth()}
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

	middleware := &oa.APIMiddleware{KeyStore: ks}
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
	crossToken, _ := oa.MintResourceToken("eve", clientIDs[1], secrets[0], oa.AppQuota{}, []string{"read"})
	fmt.Println("cross_app_token:", checkToken(crossToken))

	// Correct token: app A's secret with app A's client_id
	correctToken, _ := oa.MintResourceToken("alice", clientIDs[0], secrets[0], oa.AppQuota{}, []string{"read"})
	fmt.Println("correct_token:", checkToken(correctToken))

	// Output:
	// cross_app_token: 401
	// correct_token: 200
}

// ExampleJWKSHandler_multiAlgorithm demonstrates that HS256 and RS256 apps
// coexist in the same KeyStore, but only asymmetric keys appear in JWKS.
// RS256 tokens validate via JWKS; HS256 tokens are rejected (secrets never exposed).
func ExampleJWKSHandler_multiAlgorithm() {
	ks := oa.NewInMemoryKeyStore()

	// Register one HS256 app and one RS256 app
	ks.RegisterKey("app-hmac", []byte("shared-secret"), "HS256")
	privPEM, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
	privKey, _ := utils.ParsePrivateKeyPEM(privPEM)
	ks.RegisterKey("app-rsa", pubPEM, "RS256")

	ids, _ := ks.ListKeyIDs()
	fmt.Println("total_apps:", len(ids))

	// Serve JWKS (only asymmetric keys appear)
	jwksHandler := &oa.JWKSHandler{KeyStore: ks}
	authServer := httptest.NewServer(http.HandlerFunc(jwksHandler.ServeHTTP))
	defer authServer.Close()

	resp, _ := http.Get(authServer.URL)
	var jwkSet utils.JWKSet
	json.NewDecoder(resp.Body).Decode(&jwkSet)
	resp.Body.Close()
	fmt.Println("jwks_keys:", len(jwkSet.Keys))

	// Resource server uses JWKS for key discovery
	resKeyStore := oa.NewJWKSKeyStore(authServer.URL, oa.WithMinRefreshGap(0))
	resKeyStore.Start()
	defer resKeyStore.Stop()

	middleware := &oa.APIMiddleware{KeyStore: resKeyStore}
	resSrv := httptest.NewServer(middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer resSrv.Close()

	// RS256 token validates via JWKS
	rsToken, _ := oa.MintResourceTokenWithKey("alice", "app-rsa", privKey, oa.AppQuota{}, []string{"read"})
	req, _ := http.NewRequest("GET", resSrv.URL, nil)
	req.Header.Set("Authorization", "Bearer "+rsToken)
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	fmt.Println("rs256_via_jwks:", res.StatusCode)

	// HS256 token fails via JWKS (secrets are never exposed)
	hsToken, _ := oa.MintResourceToken("bob", "app-hmac", "shared-secret", oa.AppQuota{}, []string{"read"})
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
