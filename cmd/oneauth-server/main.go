package main

import (
	"context"
	"crypto"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/datastore"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/httpauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/localauth"
	"github.com/panyam/oneauth/utils"
	"golang.org/x/oauth2"
	fsstore "github.com/panyam/oneauth/stores/fs"
	gaestore "github.com/panyam/oneauth/stores/gae"
	gormstore "github.com/panyam/oneauth/stores/gorm"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// issuerClientID is the keystore client_id under which the asymmetric issuer
// signing key is registered when JWT.SigningAlg is RS256/ES256. The JWKS
// handler iterates all asymmetric keys in the keystore — this constant gives
// the issuer's identity a stable, recognizable name in admin tooling.
const issuerClientID = "oneauth-issuer"

//go:embed templates/*.html
var templateFS embed.FS

// pageTemplates maps page name → template set (layout + that page's content block).
// Each page is parsed separately so their {{define "content"}} blocks don't collide.
var pageTemplates map[string]*template.Template

func init() {
	pageTemplates = make(map[string]*template.Template)
	pages := []string{
		"index.html", "login.html", "signup.html", "dashboard.html",
		"forgot_password.html", "reset_password.html",
	}
	for _, page := range pages {
		t := template.Must(template.ParseFS(templateFS, "templates/layout.html", "templates/"+page))
		pageTemplates[page] = t
	}
}

func main() {
	configPath := flag.String("config", "oneauth-server.yaml", "Path to config file")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Build KeyStore (optionally wrapped with encryption)
	keyStore, db, err := buildKeyStore(cfg)
	if err != nil {
		log.Fatalf("Failed to create KeyStore: %v", err)
	}

	// Build AdminAuth
	adminAuth, err := buildAdminAuth(cfg)
	if err != nil {
		log.Fatalf("Failed to create AdminAuth: %v", err)
	}

	// Build user stores (for auth pages)
	stores, err := buildUserStores(cfg, db)
	if err != nil {
		log.Fatalf("Failed to create user stores: %v", err)
	}

	// Build AppRegistrar with the configured AppRegistrationStore (issue 167).
	appStore, err := buildAppStore(cfg, db)
	if err != nil {
		log.Fatalf("Failed to create AppStore: %v", err)
	}
	registrar := admin.NewAppRegistrarWithStore(keyStore, adminAuth, appStore)

	// Build LocalAuth
	localAuth := &localauth.LocalAuth{
		ValidateCredentials: localauth.NewCredentialsValidator(stores.identityStore, stores.channelStore, stores.userStore),
		CreateUser:          localauth.NewCreateUserFunc(stores.userStore, stores.identityStore, stores.channelStore),
		EmailSender:         &core.ConsoleEmailSender{},
		TokenStore:          stores.tokenStore,
		BaseURL:             fmt.Sprintf("http://localhost:%s", cfg.Server.Port),
		SignupPolicy:        &core.PolicyEmailOnly,
		HandleUser:          makeHandleUser(cfg),
		VerifyEmail:         localauth.NewVerifyEmailFunc(stores.identityStore, stores.tokenStore),
		UpdatePassword:      localauth.NewUpdatePasswordFunc(stores.identityStore, stores.channelStore),
		// Redirect-mode for forgot/reset password
		ForgotPasswordURL: "/auth/forgot-password",
		ResetPasswordURL:  "/auth/reset-password",
		OnLoginError: func(err *core.AuthError, w http.ResponseWriter, r *http.Request) bool {
			renderTemplate(w, "login.html", map[string]any{"Title": "Login", "Error": err.Message, "CSRFField": httpauth.CSRFTemplateField(r)})
			return true
		},
		OnSignupError: func(err *core.AuthError, w http.ResponseWriter, r *http.Request) bool {
			renderTemplate(w, "signup.html", map[string]any{"Title": "Sign Up", "Error": err.Message, "CSRFField": httpauth.CSRFTemplateField(r)})
			return true
		},
	}

	// Token blacklist for immediate access token revocation
	blacklist := core.NewInMemoryBlacklist()

	// Build APIAuth (for API token endpoint).
	apiAuth := &apiauth.APIAuth{
		RefreshTokenStore:   stores.refreshTokenStore,
		JWTSecretKey:        cfg.JWT.SecretKey,
		JWTIssuer:           cfg.JWT.Issuer,
		ValidateCredentials: localAuth.ValidateCredentials,
		Blacklist:           blacklist,
		ClientKeyStore:      keyStore, // enables client_credentials grant
	}

	// Wire asymmetric signing if configured (issue 184). The public half is
	// registered in the keystore under a stable client_id so the JWKS handler
	// exposes it — remote resource servers can then validate tokens without
	// any shared secret.
	if alg := cfg.JWT.SigningAlg; alg == "RS256" || alg == "ES256" {
		priv, pubPEM, err := loadOrGenerateSigningKey(cfg.JWT, alg)
		if err != nil {
			log.Fatalf("Failed to load/generate %s signing key: %v", alg, err)
		}
		apiAuth.JWTSigningAlg = alg
		apiAuth.JWTSigningKey = priv
		// JWTVerifyKey is the parsed public key. utils.DecodeVerifyKey
		// accepts the same PEM bytes the keystore stores, so we round-trip.
		pubKey, err := utils.DecodeVerifyKey(pubPEM, alg)
		if err != nil {
			log.Fatalf("Failed to parse issuer public key: %v", err)
		}
		apiAuth.JWTVerifyKey = pubKey

		// Register the public key in the keystore so JWKS exposes it.
		// kid is auto-derived from the key material by the keystore.
		if err := keyStore.PutKey(&keys.KeyRecord{
			ClientID:  issuerClientID,
			Key:       pubPEM,
			Algorithm: alg,
		}); err != nil {
			log.Fatalf("Failed to register issuer public key: %v", err)
		}
		log.Printf("Asymmetric token signing enabled (alg=%s, public key registered as %q for JWKS)", alg, issuerClientID)
	}

	// CSRF middleware for browser form endpoints
	csrf := &httpauth.CSRFMiddleware{Secure: cfg.TLS.Enabled}

	// Wire up HTTP server
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("GET /_ah/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Landing page
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCookie(r, cfg.JWT.SecretKey)
		services := []map[string]string{
			{"Name": "DrawApp", "Description": "Drawing collaboration app", "URL": "http://localhost:3001"},
			{"Name": "ChatApp", "Description": "Chat collaboration app", "URL": "http://localhost:3002"},
			{"Name": "Resource Server A", "Description": "JWT-validating resource server", "URL": "http://localhost:4001"},
			{"Name": "Resource Server B", "Description": "JWT-validating resource server", "URL": "http://localhost:4002"},
		}
		renderTemplate(w, "index.html", map[string]any{"Title": "Home", "User": user, "Services": services})
	})

	// Auth pages (browser) — wrapped with CSRF protection
	mux.Handle("GET /auth/login", csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "login.html", map[string]any{"Title": "Login", "CSRFField": httpauth.CSRFTemplateField(r)})
	})))
	mux.Handle("POST /auth/login", csrf.Protect(http.HandlerFunc(localAuth.ServeHTTP)))

	mux.Handle("GET /auth/signup", csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "signup.html", map[string]any{"Title": "Sign Up", "CSRFField": httpauth.CSRFTemplateField(r)})
	})))
	mux.Handle("POST /auth/signup", csrf.Protect(http.HandlerFunc(localAuth.HandleSignup)))

	mux.Handle("GET /auth/forgot-password", csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent := r.URL.Query().Get("sent") == "true"
		renderTemplate(w, "forgot_password.html", map[string]any{"Title": "Forgot Password", "Sent": sent, "CSRFField": httpauth.CSRFTemplateField(r)})
	})))
	mux.Handle("POST /auth/forgot-password", csrf.Protect(http.HandlerFunc(localAuth.HandleForgotPassword)))

	mux.Handle("GET /auth/reset-password", csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		success := r.URL.Query().Get("success") == "true"
		token := r.URL.Query().Get("token")
		errMsg := r.URL.Query().Get("error")
		renderTemplate(w, "reset_password.html", map[string]any{
			"Title": "Reset Password", "Token": token, "Success": success, "Error": errMsg,
			"CSRFField": httpauth.CSRFTemplateField(r),
		})
	})))
	mux.Handle("POST /auth/reset-password", csrf.Protect(http.HandlerFunc(localAuth.HandleResetPassword)))

	mux.HandleFunc("GET /auth/verify-email", localAuth.HandleVerifyEmail)

	mux.HandleFunc("GET /auth/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "oa_token", MaxAge: -1, Path: "/"})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// Dashboard (requires auth cookie)
	mux.HandleFunc("GET /dashboard", func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCookie(r, cfg.JWT.SecretKey)
		if user == "" {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}
		userID := getUserIDFromCookie(r, cfg.JWT.SecretKey)
		email := getUserEmailFromCookie(r, cfg.JWT.SecretKey)

		// Get registered apps from registrar
		var apps []*admin.AppRegistration
		registrar.RLockApps(func(a map[string]*admin.AppRegistration) {
			for _, reg := range a {
				apps = append(apps, reg)
			}
		})

		renderTemplate(w, "dashboard.html", map[string]any{
			"Title": "Dashboard", "User": user, "UserID": userID,
			"UserEmail": email, "Apps": apps,
		})
	})

	// API token endpoint
	mux.HandleFunc("POST /api/token", apiAuth.ServeHTTP)
	mux.HandleFunc("POST /api/logout", apiAuth.HandleLogout)

	// JWT-protected API endpoints
	apiMiddleware := &apiauth.APIMiddleware{
		JWTSecretKey: cfg.JWT.SecretKey,
		JWTIssuer:    cfg.JWT.Issuer,
		Blacklist:    blacklist,
	}
	mux.Handle("GET /api/me", apiMiddleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := apiauth.GetUserIDFromAPIContext(r.Context())
		scopes := apiauth.GetScopesFromAPIContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"user_id": userID,
			"scopes":  scopes,
		})
	})))
	mux.Handle("GET /api/sessions", apiMiddleware.ValidateToken(http.HandlerFunc(apiAuth.HandleListSessions)))
	mux.Handle("POST /api/logout-all", apiMiddleware.ValidateToken(http.HandlerFunc(apiAuth.HandleLogoutAll)))

	// Token revocation endpoint — revokes the caller's access token via blacklist
	mux.Handle("POST /api/revoke", apiMiddleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract jti from the validated token (already in context after middleware)
		auth := r.Header.Get("Authorization")
		if len(auth) > 7 {
			tokenStr := auth[7:] // strip "Bearer "
			parser := jwt.NewParser()
			parsed, _, _ := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
			if parsed != nil {
				if claims, ok := parsed.Claims.(jwt.MapClaims); ok {
					if jti, ok := claims["jti"].(string); ok && jti != "" {
						exp, _ := claims.GetExpirationTime()
						if exp != nil {
							blacklist.Revoke(jti, exp.Time)
						} else {
							blacklist.Revoke(jti, time.Now().Add(core.TokenExpiryAccessToken))
						}
					}
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})))

	// App registration API (wrapped with body size limit)
	mux.Handle("/apps/", httpauth.LimitBody(httpauth.DefaultMaxBodySize)(registrar.Handler()))
	mux.Handle("/apps", httpauth.LimitBody(httpauth.DefaultMaxBodySize)(registrar.Handler()))

	// Token Introspection (RFC 7662) — authenticated via KeyStore
	introspectionHandler := apiauth.NewIntrospectionHandler(apiAuth, keyStore)
	mux.Handle("POST /oauth/introspect", introspectionHandler)

	// JWKS endpoint (public — no auth required)
	jwksHandler := &keys.JWKSHandler{KeyStore: keyStore}
	mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler.ServeHTTP)

	// AS Metadata / OIDC Discovery (RFC 8414).
	//
	// Issuer is the canonical externally-visible URL — used as the OIDC `iss`
	// claim on every minted token AND as the `issuer` in discovery metadata.
	// When cfg.Server.PublicURL is set, use it verbatim (correct behind
	// reverse proxies and when bind host is 0.0.0.0). Otherwise fall back to
	// scheme://host:port — works for loopback dev but breaks for 0.0.0.0
	// because clients connect via localhost / a routable address. See 184.
	baseURL := cfg.Server.PublicURL
	if baseURL == "" {
		scheme := "http"
		if cfg.TLS.Enabled {
			scheme = "https"
		}
		baseURL = fmt.Sprintf("%s://%s:%s", scheme, cfg.Server.Host, cfg.Server.Port)
	}
	apiauth.MountASMetadata(mux, &apiauth.ASServerMetadata{
		Issuer:                             baseURL,
		TokenEndpoint:                      baseURL + "/api/token",
		JWKSURI:                            baseURL + "/.well-known/jwks.json",
		IntrospectionEndpoint:              baseURL + "/oauth/introspect",
		RevocationEndpoint:                 baseURL + "/oauth/revoke",
		RegistrationEndpoint:               baseURL + "/apps/register",
		GrantTypesSupported:                        []string{"password", "refresh_token", "client_credentials"},
		ResponseTypesSupported:                     []string{"token"},
		TokenEndpointAuthMethods:                   []string{"client_secret_post", "client_secret_basic", "private_key_jwt"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"RS256", "ES256"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		SubjectTypesSupported:              []string{"public"},
		AuthorizationDetailsTypesSupported: cfg.JWT.AuthorizationDetailsTypes,
	})

	addr := cfg.Server.Host + ":" + cfg.Server.Port
	log.Printf("oneauth-server listening on %s (keystore=%s, user_stores=%s, auth=%s)",
		addr, cfg.KeyStore.Type, cfg.UserStores.Type, cfg.AdminAuth.Type)

	secHeaders := httpauth.SecurityHeadersWithConfig(httpauth.SecurityHeadersConfig{
		HSTSMaxAge:            31536000,
		HSTSIncludeSubDomains: true,
		FrameOptions:          "DENY",
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		PermissionsPolicy:     "camera=(), microphone=(), geolocation=()",
		CrossOriginEmbedderPolicy: "credentialless",
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginResourcePolicy: "same-origin",
	})
	handler := secHeaders(mux)

	if cfg.TLS.Enabled {
		log.Fatal(http.ListenAndServeTLS(addr, cfg.TLS.Cert, cfg.TLS.Key, handler))
	} else {
		log.Fatal(http.ListenAndServe(addr, handler))
	}
}

// userStores holds all the store instances needed for auth.
type userStores struct {
	userStore         core.UserStore
	identityStore     core.IdentityStore
	channelStore      core.ChannelStore
	tokenStore        core.TokenStore
	refreshTokenStore core.RefreshTokenStore
	cleanupPath       string // temp dir to remove on shutdown (memory mode)
}

// Cleanup removes the temp directory if this was created in memory mode.
func (s *userStores) Cleanup() {
	if s.cleanupPath != "" {
		os.RemoveAll(s.cleanupPath)
		log.Printf("Cleaned up ephemeral data at %s", s.cleanupPath)
	}
}

func buildUserStores(cfg *Config, db *gorm.DB) (*userStores, error) {
	switch cfg.UserStores.Type {
	case "memory":
		path, err := os.MkdirTemp("", "oneauth-memory-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp dir: %w", err)
		}
		log.Printf("Using ephemeral user stores at %s (will be cleaned up on exit)", path)
		return &userStores{
			userStore:         fsstore.NewFSUserStore(path),
			identityStore:     fsstore.NewFSIdentityStore(path),
			channelStore:      fsstore.NewFSChannelStore(path),
			tokenStore:        fsstore.NewFSTokenStore(path),
			refreshTokenStore: fsstore.NewFSRefreshTokenStore(path),
			cleanupPath:       path,
		}, nil

	case "gorm":
		if db == nil {
			return nil, fmt.Errorf("user_stores type=gorm requires keystore type=gorm (shared database)")
		}
		if err := gormstore.AutoMigrate(db); err != nil {
			return nil, fmt.Errorf("failed to run user store migrations: %w", err)
		}
		log.Println("Using GORM user stores (shared database with keystore)")
		return &userStores{
			userStore:         gormstore.NewUserStore(db),
			identityStore:     gormstore.NewIdentityStore(db),
			channelStore:      gormstore.NewChannelStore(db),
			tokenStore:        gormstore.NewTokenStore(db),
			refreshTokenStore: gormstore.NewRefreshTokenStore(db),
		}, nil

	default: // "fs"
		path := cfg.UserStores.FS.Path
		log.Printf("Using filesystem user stores at %s", path)
		return &userStores{
			userStore:         fsstore.NewFSUserStore(path),
			identityStore:     fsstore.NewFSIdentityStore(path),
			channelStore:      fsstore.NewFSChannelStore(path),
			tokenStore:        fsstore.NewFSTokenStore(path),
			refreshTokenStore: fsstore.NewFSRefreshTokenStore(path),
		}, nil
	}
}

func buildKeyStore(cfg *Config) (keys.KeyStorage, *gorm.DB, error) {
	var store keys.KeyStorage
	var db *gorm.DB

	switch cfg.KeyStore.Type {
	case "memory":
		log.Println("Using in-memory KeyStore (not persistent)")
		store = keys.NewInMemoryKeyStore()

	case "fs":
		log.Printf("Using filesystem KeyStore at %s", cfg.KeyStore.FS.Path)
		store = fsstore.NewFSKeyStore(cfg.KeyStore.FS.Path)

	case "gorm":
		var err error
		db, err = openGORM(cfg.KeyStore.GORM)
		if err != nil {
			return nil, nil, err
		}
		if err := gormstore.AutoMigrate(db); err != nil {
			return nil, nil, err
		}
		log.Printf("Using GORM KeyStore (driver=%s)", cfg.KeyStore.GORM.Driver)
		store = gormstore.NewKeyStore(db)

	case "gae":
		ctx := context.Background()
		client, err := datastore.NewClient(ctx, cfg.KeyStore.GAE.Project)
		if err != nil {
			return nil, nil, err
		}
		log.Printf("Using GAE Datastore KeyStore (project=%s, namespace=%s)", cfg.KeyStore.GAE.Project, cfg.KeyStore.GAE.Namespace)
		store = gaestore.NewKeyStore(client, cfg.KeyStore.GAE.Namespace)

	default:
		log.Fatalf("Unknown keystore type: %s", cfg.KeyStore.Type)
		return nil, nil, nil
	}

	// Wrap with encryption if a master key is configured
	if cfg.KeyStore.MasterKey != "" {
		encrypted, err := keys.NewEncryptedKeyStorage(store, cfg.KeyStore.MasterKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create EncryptedKeyStore: %w", err)
		}
		log.Println("KeyStore encryption enabled (AES-256-GCM)")
		store = encrypted
	} else {
		log.Println("WARNING: ONEAUTH_MASTER_KEY not set — HS256 secrets stored in plaintext")
	}

	return store, db, nil
}

// buildAppStore builds the admin.AppRegistrationStore that AppRegistrar uses
// to persist client registrations across restarts (issue 167; closes parent
// 20). Mirrors buildKeyStore: memory for tests/dev, fs for single-node, gorm
// for production multi-node. Reuses an existing GORM DB connection passed
// from buildKeyStore when both are configured for the same database; opens
// a fresh one otherwise.
// loadOrGenerateSigningKey resolves the asymmetric issuer signing key per
// JWT config. Returns the parsed private key (for token signing) and the
// PEM-encoded public key (for keystore registration → JWKS exposure).
//
// Resolution rules:
//   - PrivateKeyPath set → load from file (production path).
//   - PrivateKeyPath empty + EphemeralSigningKey true → generate a fresh
//     RSA-2048 keypair (test/dev convenience). Logs prominent warning that
//     tokens will be invalidated on every restart.
//   - Both empty → error. Misconfiguration must fail loudly so production
//     deployments don't silently get ephemeral keys.
//
// ES256 is accepted as alg but currently only RSA generation is implemented
// for the ephemeral path; ES256 deployments must supply PrivateKeyPath.
func loadOrGenerateSigningKey(cfg JWTConfig, alg string) (priv crypto.PrivateKey, pubPEM []byte, err error) {
	if cfg.PrivateKeyPath != "" {
		data, err := os.ReadFile(cfg.PrivateKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", cfg.PrivateKeyPath, err)
		}
		priv, err = utils.ParsePrivateKeyPEM(data)
		if err != nil {
			return nil, nil, fmt.Errorf("parse private key: %w", err)
		}
		signer, ok := priv.(crypto.Signer)
		if !ok {
			return nil, nil, fmt.Errorf("private key does not implement crypto.Signer")
		}
		pubPEM, err = utils.EncodePublicKeyPEM(signer.Public())
		if err != nil {
			return nil, nil, fmt.Errorf("encode public key: %w", err)
		}
		log.Printf("Loaded %s signing key from %s", alg, cfg.PrivateKeyPath)
		return priv, pubPEM, nil
	}
	if !cfg.EphemeralSigningKey {
		return nil, nil, fmt.Errorf("jwt.signing_alg=%s requires either jwt.private_key_path or jwt.ephemeral_signing_key=true", alg)
	}
	// Test/dev path: ephemeral RSA keypair. Loud warning — tokens go
	// stale on restart, JWKS rotates.
	log.Printf("WARNING: jwt.ephemeral_signing_key=true — generating fresh RSA-2048 keypair. " +
		"Tokens issued by this instance will be INVALID after restart. Use jwt.private_key_path in production.")
	privPEM, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate RSA keypair: %w", err)
	}
	priv, err = utils.ParsePrivateKeyPEM(privPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse generated private key: %w", err)
	}
	return priv, pubPEM, nil
}

func buildAppStore(cfg *Config, sharedDB *gorm.DB) (admin.AppRegistrationStore, error) {
	switch cfg.AppStore.Type {
	case "memory":
		log.Println("Using in-memory AppStore (registrations lost on restart)")
		return admin.NewInMemoryAppStore(), nil

	case "fs":
		log.Printf("Using filesystem AppStore at %s", cfg.AppStore.FS.Path)
		return fsstore.NewFSAppStore(cfg.AppStore.FS.Path), nil

	case "gorm":
		// Reuse the keystore's DB connection if config matches, otherwise
		// open a fresh one. Reuse keeps the connection pool small for
		// deployments using one DB for both stores; separate is the
		// honest fallback when the configs differ.
		db := sharedDB
		if db == nil || cfg.KeyStore.GORM.DSN != cfg.AppStore.GORM.DSN || cfg.KeyStore.GORM.Driver != cfg.AppStore.GORM.Driver {
			fresh, err := openGORM(cfg.AppStore.GORM)
			if err != nil {
				return nil, err
			}
			db = fresh
		}
		if err := gormstore.AutoMigrate(db); err != nil {
			return nil, err
		}
		log.Printf("Using GORM AppStore (driver=%s)", cfg.AppStore.GORM.Driver)
		return gormstore.NewAppStore(db), nil

	default:
		return nil, fmt.Errorf("unknown app_store type: %s", cfg.AppStore.Type)
	}
}

func openGORM(cfg GORMConfig) (*gorm.DB, error) {
	switch cfg.Driver {
	case "postgres":
		return gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{})
	default:
		log.Fatalf("Unsupported GORM driver: %s (only postgres is supported in the reference server)", cfg.Driver)
		return nil, nil
	}
}

func buildAdminAuth(cfg *Config) (admin.AdminAuth, error) {
	switch cfg.AdminAuth.Type {
	case "none":
		log.Println("WARNING: Admin auth disabled (type=none). Do not use in production!")
		return admin.NewNoAuth(), nil

	case "api-key":
		key := cfg.AdminAuth.APIKey.Key
		if key == "" {
			// Try fetching from Secret Manager
			var err error
			key, err = fetchSecretManagerKey(cfg)
			if err != nil {
				log.Fatalf("admin_auth.api_key.key is required. Set ADMIN_API_KEY env var, create a Secret Manager secret, or generate one:\n  export ADMIN_API_KEY=\"$(openssl rand -hex 32)\"\nSecret Manager error: %v", err)
			}
			log.Println("Admin API key loaded from Secret Manager")
		}
		return admin.NewAPIKeyAuth(key), nil

	default:
		log.Fatalf("Unknown admin_auth type: %s", cfg.AdminAuth.Type)
		return nil, nil
	}
}

// makeHandleUser returns a HandleUserFunc that sets a JWT cookie for browser sessions.
func makeHandleUser(cfg *Config) core.HandleUserFunc {
	return func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
		email, _ := userInfo["email"].(string)
		username, _ := userInfo["username"].(string)
		displayName := email
		if username != "" {
			displayName = username
		}

		// Determine user ID — look it up from userInfo if available
		userID, _ := userInfo["user_id"].(string)
		if userID == "" {
			userID = displayName
		}

		// Create a JWT cookie for browser sessions
		if cfg.JWT.SecretKey != "" {
			claims := jwt.MapClaims{
				"sub":   userID,
				"email": email,
				"name":  displayName,
				"iat":   time.Now().Unix(),
				"exp":   time.Now().Add(24 * time.Hour).Unix(),
			}
			if cfg.JWT.Issuer != "" {
				claims["iss"] = cfg.JWT.Issuer
			}
			jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := jwtToken.SignedString([]byte(cfg.JWT.SecretKey))
			if err != nil {
				log.Printf("Failed to sign JWT: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     "oa_token",
				Value:    tokenString,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   86400,
			})
		}

		// Check if this is an API request (Accept: application/json)
		if r.Header.Get("Accept") == "application/json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"user":    userInfo,
			})
			return
		}

		// Browser: redirect to dashboard
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

// getUserFromCookie extracts display name from the JWT cookie.
func getUserFromCookie(r *http.Request, secretKey string) string {
	cookie, err := r.Cookie("oa_token")
	if err != nil {
		return ""
	}
	claims := parseJWTCookie(cookie.Value, secretKey)
	if claims == nil {
		return ""
	}
	if name, ok := claims["name"].(string); ok {
		return name
	}
	return ""
}

func getUserIDFromCookie(r *http.Request, secretKey string) string {
	cookie, err := r.Cookie("oa_token")
	if err != nil {
		return ""
	}
	claims := parseJWTCookie(cookie.Value, secretKey)
	if claims == nil {
		return ""
	}
	if sub, ok := claims["sub"].(string); ok {
		return sub
	}
	return ""
}

func getUserEmailFromCookie(r *http.Request, secretKey string) string {
	cookie, err := r.Cookie("oa_token")
	if err != nil {
		return ""
	}
	claims := parseJWTCookie(cookie.Value, secretKey)
	if claims == nil {
		return ""
	}
	if email, ok := claims["email"].(string); ok {
		return email
	}
	return ""
}

func parseJWTCookie(tokenString, secretKey string) jwt.MapClaims {
	if secretKey == "" {
		return nil
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(secretKey), nil
	})
	if err != nil || !token.Valid {
		return nil
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}
	return claims
}

func renderTemplate(w http.ResponseWriter, name string, data any) {
	t, ok := pageTemplates[name]
	if !ok {
		log.Printf("Template not found: %s", name)
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("Template error (%s): %v", name, err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// fetchSecretManagerKey attempts to load the admin API key from Google Secret Manager.
func fetchSecretManagerKey(cfg *Config) (string, error) {
	secretName := os.Getenv("ADMIN_API_KEY_SECRET")
	if secretName == "" {
		project := cfg.KeyStore.GAE.Project
		if project == "" {
			return "", fmt.Errorf("no GCP_PROJECT configured for Secret Manager lookup")
		}
		secretName = fmt.Sprintf("projects/%s/secrets/oneauth-admin-key/versions/latest", project)
	}

	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create Secret Manager client: %w", err)
	}
	defer client.Close()

	result, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName,
	})
	if err != nil {
		return "", fmt.Errorf("failed to access secret %s: %w", secretName, err)
	}
	return string(result.Payload.Data), nil
}
