package main

import (
	"context"
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
	oa "github.com/panyam/oneauth"
	"golang.org/x/oauth2"
	fsstore "github.com/panyam/oneauth/stores/fs"
	gaestore "github.com/panyam/oneauth/stores/gae"
	gormstore "github.com/panyam/oneauth/stores/gorm"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

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

	// Build AppRegistrar
	registrar := &oa.AppRegistrar{
		KeyStore: keyStore,
		Auth:     adminAuth,
	}

	// Build LocalAuth
	localAuth := &oa.LocalAuth{
		ValidateCredentials: oa.NewCredentialsValidator(stores.identityStore, stores.channelStore, stores.userStore),
		CreateUser:          oa.NewCreateUserFunc(stores.userStore, stores.identityStore, stores.channelStore),
		EmailSender:         &oa.ConsoleEmailSender{},
		TokenStore:          stores.tokenStore,
		BaseURL:             fmt.Sprintf("http://localhost:%s", cfg.Server.Port),
		SignupPolicy:        &oa.PolicyEmailOnly,
		HandleUser:          makeHandleUser(cfg),
		VerifyEmail:         oa.NewVerifyEmailFunc(stores.identityStore, stores.tokenStore),
		UpdatePassword:      oa.NewUpdatePasswordFunc(stores.identityStore, stores.channelStore),
		// Redirect-mode for forgot/reset password
		ForgotPasswordURL: "/auth/forgot-password",
		ResetPasswordURL:  "/auth/reset-password",
		OnLoginError: func(err *oa.AuthError, w http.ResponseWriter, r *http.Request) bool {
			renderTemplate(w, "login.html", map[string]any{"Title": "Login", "Error": err.Message})
			return true
		},
		OnSignupError: func(err *oa.AuthError, w http.ResponseWriter, r *http.Request) bool {
			renderTemplate(w, "signup.html", map[string]any{"Title": "Sign Up", "Error": err.Message})
			return true
		},
	}

	// Build APIAuth (for API token endpoint)
	apiAuth := &oa.APIAuth{
		RefreshTokenStore:   stores.refreshTokenStore,
		JWTSecretKey:        cfg.JWT.SecretKey,
		JWTIssuer:           cfg.JWT.Issuer,
		ValidateCredentials: localAuth.ValidateCredentials,
	}

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

	// Auth pages (browser)
	mux.HandleFunc("GET /auth/login", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "login.html", map[string]any{"Title": "Login"})
	})
	mux.HandleFunc("POST /auth/login", localAuth.ServeHTTP)

	mux.HandleFunc("GET /auth/signup", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "signup.html", map[string]any{"Title": "Sign Up"})
	})
	mux.HandleFunc("POST /auth/signup", localAuth.HandleSignup)

	mux.HandleFunc("GET /auth/forgot-password", func(w http.ResponseWriter, r *http.Request) {
		sent := r.URL.Query().Get("sent") == "true"
		renderTemplate(w, "forgot_password.html", map[string]any{"Title": "Forgot Password", "Sent": sent})
	})
	mux.HandleFunc("POST /auth/forgot-password", localAuth.HandleForgotPassword)

	mux.HandleFunc("GET /auth/reset-password", func(w http.ResponseWriter, r *http.Request) {
		success := r.URL.Query().Get("success") == "true"
		token := r.URL.Query().Get("token")
		errMsg := r.URL.Query().Get("error")
		renderTemplate(w, "reset_password.html", map[string]any{
			"Title": "Reset Password", "Token": token, "Success": success, "Error": errMsg,
		})
	})
	mux.HandleFunc("POST /auth/reset-password", localAuth.HandleResetPassword)

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
		var apps []*oa.AppRegistration
		registrar.RLockApps(func(a map[string]*oa.AppRegistration) {
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

	// App registration API
	mux.Handle("/apps/", registrar.Handler())
	mux.Handle("/apps", registrar.Handler())

	// JWKS endpoint (public — no auth required)
	jwksHandler := &oa.JWKSHandler{KeyStore: keyStore}
	mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler.ServeHTTP)

	addr := cfg.Server.Host + ":" + cfg.Server.Port
	log.Printf("oneauth-server listening on %s (keystore=%s, user_stores=%s, auth=%s)",
		addr, cfg.KeyStore.Type, cfg.UserStores.Type, cfg.AdminAuth.Type)

	if cfg.TLS.Enabled {
		log.Fatal(http.ListenAndServeTLS(addr, cfg.TLS.Cert, cfg.TLS.Key, mux))
	} else {
		log.Fatal(http.ListenAndServe(addr, mux))
	}
}

// userStores holds all the store instances needed for auth.
type userStores struct {
	userStore         oa.UserStore
	identityStore     oa.IdentityStore
	channelStore      oa.ChannelStore
	tokenStore        oa.TokenStore
	refreshTokenStore oa.RefreshTokenStore
}

func buildUserStores(cfg *Config, db *gorm.DB) (*userStores, error) {
	switch cfg.UserStores.Type {
	case "gorm":
		if db == nil {
			return nil, fmt.Errorf("user_stores type=gorm requires keystore type=gorm (shared database)")
		}
		// Run migrations for all user tables
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

func buildKeyStore(cfg *Config) (oa.WritableKeyStore, *gorm.DB, error) {
	var store oa.WritableKeyStore
	var db *gorm.DB

	switch cfg.KeyStore.Type {
	case "memory":
		log.Println("Using in-memory KeyStore (not persistent)")
		store = oa.NewInMemoryKeyStore()

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
		encrypted, err := oa.NewEncryptedKeyStore(store, cfg.KeyStore.MasterKey)
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

func openGORM(cfg GORMConfig) (*gorm.DB, error) {
	switch cfg.Driver {
	case "postgres":
		return gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{})
	default:
		log.Fatalf("Unsupported GORM driver: %s (only postgres is supported in the reference server)", cfg.Driver)
		return nil, nil
	}
}

func buildAdminAuth(cfg *Config) (oa.AdminAuth, error) {
	switch cfg.AdminAuth.Type {
	case "none":
		log.Println("WARNING: Admin auth disabled (type=none). Do not use in production!")
		return oa.NewNoAuth(), nil

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
		return oa.NewAPIKeyAuth(key), nil

	default:
		log.Fatalf("Unknown admin_auth type: %s", cfg.AdminAuth.Type)
		return nil, nil
	}
}

// makeHandleUser returns a HandleUserFunc that sets a JWT cookie for browser sessions.
func makeHandleUser(cfg *Config) oa.HandleUserFunc {
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
