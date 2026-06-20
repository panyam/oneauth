package e2e_test

// Auth server wiring for e2e tests. Mirrors cmd/oneauth-server/main.go
// but uses in-memory stores and no templates.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// readCloserFromForm re-encodes a parsed form back to a body the
// downstream handler can re-parse. Used by the /oauth/token dispatch
// when delegating to APIAuth.ServeHTTP after the outer handler has
// already called r.ParseForm.
func readCloserFromForm(form url.Values) io.ReadCloser {
	return io.NopCloser(strings.NewReader(form.Encode()))
}

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
		EmailSender:         &localauth.ConsoleEmailSender{},
		TokenStore:          tokenStore,
		BaseURL:             "http://test",
		SignupPolicy:        &localauth.PolicyEmailOnly,
		VerifyEmail:         localauth.NewVerifyEmailFunc(identityStore, tokenStore),
		UpdatePassword:      localauth.NewUpdatePasswordFunc(identityStore, channelStore),
		HandleUser: func(authtype, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"success": true, "user": userInfo})
		},
	}

	// OIDC Back-Channel Logout 1.0 sender wiring (issue 261). Built
	// BEFORE OneAuth so the hooks can close over it. The dispatcher is
	// opt-in: if no client registers backchannel_logout_uri the hook
	// is a no-op. AllowPrivateHosts is set because RS-side receivers
	// in these tests run via httptest.NewServer (127.0.0.1).
	e.bclDispatcher = &apiauth.BCLDispatcher{
		Issuer: apiauth.NewJWTLogoutTokenIssuer(apiauth.JWTLogoutTokenIssuerConfig{
			SigningKey: []byte(e.JWTSecret),
			SigningAlg: "HS256",
			Issuer:     testJWTIssuer,
		}),
		Apps:              e.registrar,
		RefreshStore:      refreshTokenStore,
		SyncForTest:       true,
		AllowPrivateHosts: true,
	}
	e.registrar.AllowPrivateBCLHosts = true // tests register loopback receivers

	tokenHooks := apiauth.TokenHooks{
		OnSubjectRevoked: func(subject, sid string, clientIDs []string) {
			e.bclDispatcher.Dispatch(context.Background(), &apiauth.DispatchRequest{
				Subject:   subject,
				SID:       sid,
				ClientIDs: clientIDs,
			})
		},
		OnTokenRevoked: func(subject, sid, clientID string) {
			if clientID == "" {
				return
			}
			e.bclDispatcher.Dispatch(context.Background(), &apiauth.DispatchRequest{
				Subject:   subject,
				SID:       sid,
				ClientIDs: []string{clientID},
			})
		},
	}

	// OneAuth — hooks already populated so the Revoker + Sessions
	// handler snapshot them at construction time.
	e.oa = apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:               e.KeyStore,
		SigningKey:             []byte(e.JWTSecret),
		SigningAlg:             "HS256",
		Issuer:                 testJWTIssuer,
		RefreshStore:           refreshTokenStore,
		Blacklist:              e.Blacklist,
		ValidateCredentials:    e.localAuth.ValidateCredentials,
		AuthorizationCodeStore: core.NewInMemoryAuthorizationCodeStore(),
		Hooks:                  apiauth.Hooks{Token: tokenHooks},
	})
	// ROPC is opt-in post-#294. The e2e suite POSTs grant_type=password
	// (helpers_test.go login flow) so wire the granter explicitly.
	// Strict-2.1 e2e coverage lives in a separate test below.
	e.oa.PasswordGranter = apiauth.NewPasswordGranter(apiauth.PasswordGranterConfig{
		Issuer:              e.oa.Issuer,
		ValidateCredentials: e.localAuth.ValidateCredentials,
	})
	e.tokenEndpoint = apiauth.NewTokenEndpointHandler(e.oa)
	e.sessions = e.oa.SessionsHTTPHandler()

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

	// RFC 6749 §4.1 /authorize endpoint wired via the library helper
	// (#297). Auto-approves "e2e-user" so the headless tests can drive
	// the redirect → code → token chain without a login UI.
	apiauth.MountAuthorize(mux, apiauth.AuthorizeMountConfig{
		OneAuth:              e.oa,
		IssuerURL:            testJWTIssuer,
		EmitIssParameter:     true,
		SubjectFromRequest:   func(r *http.Request) string { return "" },
		CSRFTokenFromRequest: func(r *http.Request) string { return "" },
		AutoApproveSubject:   "e2e-user",
	})

	// Standards-compliant token endpoint for e2e tests.
	// Handles authorization_code (delegated to APIAuth.ServeHTTP — uses
	// the same AuthorizationCodeStore the /authorize mount writes into)
	// and client_credentials grants.
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
			// Delegate to APIAuth.ServeHTTP so the redemption uses the
			// same AuthorizationCodeStore that MountAuthorize writes
			// into. APIAuth.ServeHTTP re-parses the form body — set the
			// request body back to the original encoded form so the
			// downstream call sees the same fields.
			r.Body = readCloserFromForm(r.PostForm)
			r.ContentLength = -1
			e.tokenEndpoint.ServeHTTP(w, r)
			return

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
			resp, err := e.KeyStore.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: clientID})
			var keyBytes []byte
			if resp != nil && resp.Record != nil {
				keyBytes, _ = resp.Record.Key.([]byte)
			}
			if err != nil || resp == nil || resp.Record == nil || string(keyBytes) != clientSecret {
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
	mux.HandleFunc("POST /api/token", e.tokenEndpoint.ServeHTTP)
	mux.HandleFunc("POST /api/logout", e.sessions.HandleLogout)

	// JWT-protected endpoints
	apiMW := &apiauth.APIMiddleware{
		JWTSecretKey: e.JWTSecret,
		JWTIssuer:    testJWTIssuer,
		Blacklist:    e.Blacklist,
	}
	mux.Handle("GET /api/me", apiMW.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"user_id": apiauth.GetSubjectFromAPIContext(r.Context()),
			"scopes":  apiauth.GetScopesFromAPIContext(r.Context()),
		})
	})))
	mux.Handle("GET /api/sessions", apiMW.ValidateToken(http.HandlerFunc(e.sessions.HandleListSessions)))
	mux.Handle("POST /api/logout-all", apiMW.ValidateToken(http.HandlerFunc(e.sessions.HandleLogoutAll)))

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
	introspectionHandler := e.oa.IntrospectionHTTPHandler()
	mux.Handle("POST /oauth/introspect", introspectionHandler)

	// Token Revocation (RFC 7009)
	revocationHandler := e.oa.RevocationHTTPHandler()
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
	bclSupported := true
	bclSessionSupported := true
	asMetaHandler := apiauth.NewASMetadataHandler(&apiauth.ASServerMetadata{
		Issuer:                            baseURL,
		AuthorizationEndpoint:             baseURL + "/authorize",
		TokenEndpoint:                     baseURL + "/oauth/token",
		JWKSURI:                           baseURL + "/.well-known/jwks.json",
		IntrospectionEndpoint:             baseURL + "/oauth/introspect",
		RevocationEndpoint:                baseURL + "/oauth/revoke",
		RegistrationEndpoint:              baseURL + "/apps/dcr",
		ScopesSupported:                   []string{"read", "write", "admin"},
		GrantTypesSupported:               []string{"authorization_code", "password", "refresh_token", "client_credentials"},
		ResponseTypesSupported:            []string{"code", "token"},
		TokenEndpointAuthMethods:          []string{"client_secret_post", "client_secret_basic"},
		SubjectTypesSupported:             []string{"public"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		BackchannelLogoutSupported:        &bclSupported,
		BackchannelLogoutSessionSupported: &bclSessionSupported,
	})
	// Register on the existing mux (before server start the mux is already wired)
	mux.Handle("GET /.well-known/openid-configuration", asMetaHandler)
}
