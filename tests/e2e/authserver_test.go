package e2e_test

// Auth server wiring for e2e tests. Mirrors cmd/oneauth-server/main.go
// but uses in-memory stores and no templates.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/httpauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/localauth"
	fsstore "github.com/panyam/oneauth/stores/fs"
	"golang.org/x/oauth2"
)

// buildAuthServer wires up and starts the auth server.
func (e *TestEnv) buildAuthServer(t *testing.T) {
	t.Helper()

	// Stores
	e.KeyStore = keys.NewInMemoryKeyStore()
	e.Blacklist = core.NewInMemoryBlacklist()
	tmpDir := t.TempDir()

	userStore := fsstore.NewFSUserStore(tmpDir)
	identityStore := fsstore.NewFSIdentityStore(tmpDir)
	channelStore := fsstore.NewFSChannelStore(tmpDir)
	tokenStore := fsstore.NewFSTokenStore(tmpDir)
	refreshTokenStore := fsstore.NewFSRefreshTokenStore(tmpDir)

	// AppRegistrar
	e.registrar = admin.NewAppRegistrar(e.KeyStore, admin.NewAPIKeyAuth(e.AdminKey))

	// LocalAuth (JSON-mode HandleUser for tests — no templates needed)
	e.localAuth = &localauth.LocalAuth{
		ValidateCredentials: localauth.NewCredentialsValidator(identityStore, channelStore, userStore),
		CreateUser:          localauth.NewCreateUserFunc(userStore, identityStore, channelStore),
		EmailSender:         &core.ConsoleEmailSender{},
		TokenStore:          tokenStore,
		BaseURL:             "http://test",
		SignupPolicy:        &core.PolicyEmailOnly,
		VerifyEmail:         localauth.NewVerifyEmailFunc(identityStore, tokenStore),
		UpdatePassword:      localauth.NewUpdatePasswordFunc(identityStore, channelStore),
		HandleUser: func(authtype, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"success": true, "user": userInfo})
		},
	}

	// APIAuth
	e.apiAuth = &apiauth.APIAuth{
		RefreshTokenStore:   refreshTokenStore,
		JWTSecretKey:        e.JWTSecret,
		JWTIssuer:           testJWTIssuer,
		ValidateCredentials: e.localAuth.ValidateCredentials,
		Blacklist:           e.Blacklist,
		ClientKeyStore:      e.KeyStore, // Enables client_credentials grant
	}

	// CSRF
	csrf := &httpauth.CSRFMiddleware{}

	// Mux
	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("GET /_ah/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Browser auth (with CSRF) — stub HTML forms for tests
	mux.Handle("GET /auth/signup", csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<form><input name="csrf_token" value="%s"></form>`, httpauth.CSRFToken(r))
	})))
	mux.Handle("POST /auth/signup", csrf.Protect(http.HandlerFunc(e.localAuth.HandleSignup)))
	mux.Handle("GET /auth/login", csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<form><input name="csrf_token" value="%s"></form>`, httpauth.CSRFToken(r))
	})))
	mux.Handle("POST /auth/login", csrf.Protect(http.HandlerFunc(e.localAuth.ServeHTTP)))

	// Authorization endpoint stub for auth code + PKCE e2e tests (#71).
	// Auto-approves and redirects — no login UI needed for in-process tests.
	// Stores the PKCE challenge for verification at the token endpoint.
	var storedPKCEChallenge, storedRedirectURI, storedState string
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("response_type") != "code" {
			http.Error(w, "invalid response_type", http.StatusBadRequest)
			return
		}
		if q.Get("code_challenge_method") != "S256" {
			http.Error(w, "invalid code_challenge_method", http.StatusBadRequest)
			return
		}
		storedPKCEChallenge = q.Get("code_challenge")
		storedState = q.Get("state")
		storedRedirectURI = q.Get("redirect_uri")

		redirectURL := fmt.Sprintf("%s?code=e2e-auth-code&state=%s",
			storedRedirectURI, storedState)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	// Standards-compliant token endpoint for e2e tests.
	// Handles authorization_code (with PKCE) and client_credentials grants.
	// Supports client_secret_basic and client_secret_post auth methods (#72).
	// This is separate from /api/token (which uses JSON and legacy oneauth behavior).
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		grantType := r.FormValue("grant_type")
		switch grantType {
		case "authorization_code":
			// Verify PKCE
			verifier := r.FormValue("code_verifier")
			hash := sha256.Sum256([]byte(verifier))
			computed := base64.RawURLEncoding.EncodeToString(hash[:])
			if computed != storedPKCEChallenge {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "invalid_grant", "error_description": "PKCE verification failed"})
				return
			}

			if r.FormValue("code") != "e2e-auth-code" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "e2e-authcode-token",
				"refresh_token": "e2e-refresh-token",
				"token_type":    "Bearer",
				"expires_in":    900,
			})

		case "client_credentials":
			// Extract client credentials: Basic auth header or form body
			clientID := r.FormValue("client_id")
			clientSecret := r.FormValue("client_secret")
			if basicUser, basicPass, ok := r.BasicAuth(); ok {
				clientID = basicUser
				clientSecret = basicPass
			}

			if clientID == "" || clientSecret == "" {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "invalid_client", "error_description": "missing credentials"})
				return
			}

			// Validate against KeyStore
			rec, err := e.KeyStore.GetKey(clientID)
			keyBytes, _ := rec.Key.([]byte)
			if err != nil || rec == nil || string(keyBytes) != clientSecret {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "invalid_client", "error_description": "bad credentials"})
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "e2e-cc-token-" + clientID,
				"token_type":   "Bearer",
				"expires_in":   3600,
			})

		default:
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
		}
	})

	// API endpoints
	mux.HandleFunc("POST /api/token", e.apiAuth.ServeHTTP)
	mux.HandleFunc("POST /api/logout", e.apiAuth.HandleLogout)

	// JWT-protected endpoints
	apiMW := &apiauth.APIMiddleware{
		JWTSecretKey: e.JWTSecret,
		JWTIssuer:    testJWTIssuer,
		Blacklist:    e.Blacklist,
	}
	mux.Handle("GET /api/me", apiMW.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"user_id": apiauth.GetUserIDFromAPIContext(r.Context()),
			"scopes":  apiauth.GetScopesFromAPIContext(r.Context()),
		})
	})))
	mux.Handle("GET /api/sessions", apiMW.ValidateToken(http.HandlerFunc(e.apiAuth.HandleListSessions)))
	mux.Handle("POST /api/logout-all", apiMW.ValidateToken(http.HandlerFunc(e.apiAuth.HandleLogoutAll)))

	// Token revocation
	mux.Handle("POST /api/revoke", apiMW.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if len(auth) > 7 {
			tokenStr := auth[7:]
			parser := jwt.NewParser()
			parsed, _, _ := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
			if parsed != nil {
				if claims, ok := parsed.Claims.(jwt.MapClaims); ok {
					if jti, ok := claims["jti"].(string); ok && jti != "" {
						exp, _ := claims.GetExpirationTime()
						if exp != nil {
							e.Blacklist.Revoke(jti, exp.Time)
						} else {
							e.Blacklist.Revoke(jti, time.Now().Add(core.TokenExpiryAccessToken))
						}
					}
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})))

	// App registration (with body limit)
	mux.Handle("/apps/", httpauth.LimitBody(httpauth.DefaultMaxBodySize)(e.registrar.Handler()))
	mux.Handle("/apps", httpauth.LimitBody(httpauth.DefaultMaxBodySize)(e.registrar.Handler()))

	// Token Introspection (RFC 7662)
	introspectionHandler := &apiauth.IntrospectionHandler{
		Auth:           e.apiAuth,
		ClientKeyStore: e.KeyStore,
	}
	mux.Handle("POST /oauth/introspect", introspectionHandler)

	// Token Revocation (RFC 7009)
	revocationHandler := &apiauth.RevocationHandler{
		Auth:           e.apiAuth,
		ClientKeyStore: e.KeyStore,
	}
	mux.Handle("POST /oauth/revoke", revocationHandler)

	// JWKS
	jwksHandler := &keys.JWKSHandler{KeyStore: e.KeyStore}
	mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler.ServeHTTP)

	// AS Metadata / OIDC Discovery (RFC 8414) — populated after server starts
	// (needs the server URL for endpoint URLs). See below.

	e.AuthServer = httptest.NewServer(mux)
	t.Cleanup(e.AuthServer.Close)

	// Now that we know the server URL, register the OIDC discovery endpoint.
	// Uses a dynamic handler since the URL is only known after httptest.NewServer.
	baseURL := e.AuthServer.URL
	asMetaHandler := apiauth.NewASMetadataHandler(&apiauth.ASServerMetadata{
		Issuer:                         baseURL,
		AuthorizationEndpoint:          baseURL + "/authorize",
		TokenEndpoint:                  baseURL + "/oauth/token",
		JWKSURI:                        baseURL + "/.well-known/jwks.json",
		IntrospectionEndpoint:          baseURL + "/oauth/introspect",
		RevocationEndpoint:            baseURL + "/oauth/revoke",
		RegistrationEndpoint:           baseURL + "/apps/register",
		ScopesSupported:                []string{"read", "write", "admin"},
		GrantTypesSupported:            []string{"authorization_code", "password", "refresh_token", "client_credentials"},
		ResponseTypesSupported:         []string{"code", "token"},
		TokenEndpointAuthMethods:       []string{"client_secret_post", "client_secret_basic"},
		SubjectTypesSupported:          []string{"public"},
		CodeChallengeMethodsSupported:  []string{"S256"},
	})
	// Register on the existing mux (before server start the mux is already wired)
	mux.Handle("GET /.well-known/openid-configuration", asMetaHandler)
}
