package e2e_test

// Auth server wiring for e2e tests. Mirrors cmd/oneauth-server/main.go
// but uses in-memory stores and no templates.

import (
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

	// JWKS
	jwksHandler := &keys.JWKSHandler{KeyStore: e.KeyStore}
	mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler.ServeHTTP)

	e.AuthServer = httptest.NewServer(mux)
	t.Cleanup(e.AuthServer.Close)
}
