package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/httpauth"
	"github.com/panyam/oneauth/localauth"
	fsstore "github.com/panyam/oneauth/stores/fs"
	"golang.org/x/oauth2"
)

//go:embed templates/*.html
var templateFS embed.FS

var pageTemplates map[string]*template.Template

func init() {
	pageTemplates = make(map[string]*template.Template)
	for _, page := range []string{"home.html", "login.html", "signup.html"} {
		t := template.Must(template.ParseFS(templateFS, "templates/layout.html", "templates/"+page))
		pageTemplates[page] = t
	}
}

// appCredentials holds the credentials obtained from oneauth-server registration.
type appCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	ClientDomain string `json:"client_domain"`
}

func main() {
	name := flag.String("name", envOrDefault("APP_NAME", "hostapp"), "App name")
	port := flag.String("port", envOrDefault("PORT", "3001"), "Port to listen on")
	dataDir := flag.String("data", envOrDefault("DATA_DIR", "./data"), "Data directory")
	oaServerURL := flag.String("oneauth-url", envOrDefault("ONEAUTH_URL", "http://localhost:8080"), "OneAuth server URL")
	oaAdminKey := flag.String("admin-key", envOrDefault("ONEAUTH_ADMIN_KEY", ""), "OneAuth admin API key")
	flag.Parse()

	appDataDir := filepath.Join(*dataDir, *name)

	// Load or register app credentials
	creds, err := loadOrRegisterApp(appDataDir, *name, *oaServerURL, *oaAdminKey)
	if err != nil {
		log.Printf("[%s] WARNING: App registration failed: %v (resource token minting will not work)", *name, err)
		creds = &appCredentials{} // Allow server to start without registration
	} else {
		log.Printf("[%s] App registered: client_id=%s", *name, creds.ClientID)
	}

	// Set up FS-backed user stores for this app's own users
	userStore := fsstore.NewFSUserStore(appDataDir)
	identityStore := fsstore.NewFSIdentityStore(appDataDir)
	channelStore := fsstore.NewFSChannelStore(appDataDir)

	// JWT secret for this app's browser sessions (derived from client_secret or random)
	sessionSecret := creds.ClientSecret
	if sessionSecret == "" {
		sessionSecret = "demo-session-secret-" + *name
	}

	// Build LocalAuth for this app's own users
	localAuth := &localauth.LocalAuth{
		ValidateCredentials: localauth.NewCredentialsValidator(identityStore, channelStore, userStore),
		CreateUser:          localauth.NewCreateUserFunc(userStore, identityStore, channelStore),
		SignupPolicy:        &core.PolicyEmailOnly,
		HandleUser: func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			email, _ := userInfo["email"].(string)
			// Create session JWT
			claims := jwt.MapClaims{
				"sub":   email,
				"email": email,
				"app":   *name,
				"iat":   time.Now().Unix(),
				"exp":   time.Now().Add(24 * time.Hour).Unix(),
			}
			jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := jwtToken.SignedString([]byte(sessionSecret))
			if err != nil {
				http.Error(w, "Session error", http.StatusInternalServerError)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name: "app_token", Value: tokenString,
				Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 86400,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
		},
		OnLoginError: func(err *core.AuthError, w http.ResponseWriter, r *http.Request) bool {
			renderTemplate(w, "login.html", map[string]any{"Title": "Login — " + *name, "App": *name, "Error": err.Message, "CSRFField": httpauth.CSRFTemplateField(r)})
			return true
		},
		OnSignupError: func(err *core.AuthError, w http.ResponseWriter, r *http.Request) bool {
			renderTemplate(w, "signup.html", map[string]any{"Title": "Sign Up — " + *name, "App": *name, "Error": err.Message, "CSRFField": httpauth.CSRFTemplateField(r)})
			return true
		},
	}

	// CSRF middleware for browser form endpoints
	csrf := &httpauth.CSRFMiddleware{}

	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "app": *name})
	})

	// Home page
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		user := getUserFromCookie(r, sessionSecret)
		if user == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		renderTemplate(w, "home.html", map[string]any{
			"Title":    *name,
			"App":      *name,
			"User":     user,
			"ClientID": creds.ClientID,
		})
	})

	// Login — CSRF-protected
	mux.Handle("GET /login", csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "login.html", map[string]any{"Title": "Login — " + *name, "App": *name, "CSRFField": httpauth.CSRFTemplateField(r)})
	})))
	mux.Handle("POST /login", csrf.Protect(http.HandlerFunc(localAuth.ServeHTTP)))

	// Signup — CSRF-protected
	mux.Handle("GET /signup", csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "signup.html", map[string]any{"Title": "Sign Up — " + *name, "App": *name, "CSRFField": httpauth.CSRFTemplateField(r)})
	})))
	mux.Handle("POST /signup", csrf.Protect(http.HandlerFunc(localAuth.HandleSignup)))

	// Logout
	mux.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "app_token", MaxAge: -1, Path: "/"})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	// Mint resource token
	mux.HandleFunc("POST /resource-token", func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCookie(r, sessionSecret)
		if user == "" {
			http.Error(w, `{"error":"Not authenticated"}`, http.StatusUnauthorized)
			return
		}
		if creds.ClientID == "" || creds.ClientSecret == "" {
			http.Error(w, `{"error":"App not registered with OneAuth"}`, http.StatusServiceUnavailable)
			return
		}

		token, err := admin.MintResourceToken(
			user,
			creds.ClientID,
			creds.ClientSecret,
			admin.AppQuota{MaxRooms: 10, MaxMsgRate: 100},
			[]string{"collab"}, nil,
		)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"token":     token,
			"client_id": creds.ClientID,
			"user_id":   user,
			"app":       *name,
		})
	})

	addr := ":" + *port
	log.Printf("[%s] Demo app listening on %s (oneauth=%s)", *name, addr, *oaServerURL)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// verifyCredentials checks if the auth server still knows about this client_id.
func verifyCredentials(creds *appCredentials, oaURL, adminKey string) bool {
	req, err := http.NewRequest("GET", oaURL+"/apps/"+creds.ClientID, nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-Admin-Key", adminKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// loadOrRegisterApp loads saved app credentials or registers with oneauth-server.
// If cached credentials exist but the auth server doesn't recognize them
// (e.g. database was reset), re-registers automatically.
func loadOrRegisterApp(dataDir, appName, oaURL, adminKey string) (*appCredentials, error) {
	credsFile := filepath.Join(dataDir, "app_credentials.json")

	// Try loading existing credentials
	if data, err := os.ReadFile(credsFile); err == nil {
		var creds appCredentials
		if err := json.Unmarshal(data, &creds); err == nil && creds.ClientID != "" {
			if verifyCredentials(&creds, oaURL, adminKey) {
				return &creds, nil
			}
			log.Printf("Cached credentials for %s are stale (auth server doesn't recognize client_id %s), re-registering", appName, creds.ClientID)
			os.Remove(credsFile)
		}
	}

	if adminKey == "" {
		return nil, fmt.Errorf("ONEAUTH_ADMIN_KEY not set, cannot register app")
	}

	// Register with oneauth-server
	reqBody, _ := json.Marshal(map[string]any{
		"client_domain": appName + ".localhost",
		"signing_alg":   "HS256",
		"max_rooms":     50,
		"max_msg_rate":  200,
	})

	req, err := http.NewRequest("POST", oaURL+"/apps/register", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Key", adminKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to contact oneauth-server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration failed (status %d): %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	creds := &appCredentials{
		ClientID:     result["client_id"].(string),
		ClientSecret: result["client_secret"].(string),
		ClientDomain: appName + ".localhost",
	}

	// Save credentials
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	if err := os.WriteFile(credsFile, data, 0600); err != nil {
		log.Printf("Warning: failed to save credentials: %v", err)
	}

	return creds, nil
}

func getUserFromCookie(r *http.Request, secretKey string) string {
	cookie, err := r.Cookie("app_token")
	if err != nil {
		return ""
	}
	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(secretKey), nil
	})
	if err != nil || !token.Valid {
		return ""
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ""
	}
	if email, ok := claims["email"].(string); ok {
		return email
	}
	if sub, ok := claims["sub"].(string); ok {
		return sub
	}
	return ""
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

func envOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
