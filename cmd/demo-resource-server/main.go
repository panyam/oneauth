package main

import (
	"embed"
	"encoding/json"
	"flag"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	oa "github.com/panyam/oneauth"
	gormstore "github.com/panyam/oneauth/stores/gorm"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates *template.Template

func init() {
	templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))
}

// validationEntry records a recent JWT validation attempt.
type validationEntry struct {
	Time     time.Time `json:"time"`
	UserID   string    `json:"user_id,omitempty"`
	ClientID string    `json:"client_id,omitempty"`
	Valid    bool      `json:"valid"`
	Error    string    `json:"error,omitempty"`
}

func main() {
	name := flag.String("name", envOrDefault("RESOURCE_SERVER_NAME", "resource-server"), "Resource server name")
	port := flag.String("port", envOrDefault("PORT", "4001"), "Port to listen on")
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "PostgreSQL DSN for shared KeyStore")
	jwksURL := flag.String("jwks-url", os.Getenv("JWKS_URL"), "JWKS URL for public key discovery (alternative to DATABASE_URL)")
	flag.Parse()

	// Connect to KeyStore: JWKS URL (preferred) → PostgreSQL → in-memory fallback
	var keyStore oa.KeyLookup
	if *jwksURL != "" {
		ks := oa.NewJWKSKeyStore(*jwksURL)
		if err := ks.Start(); err != nil {
			log.Fatalf("Failed to start JWKS KeyStore: %v", err)
		}
		defer ks.Stop()
		keyStore = ks
		log.Printf("[%s] Using JWKS KeyStore from %s", *name, *jwksURL)
	} else if *dsn != "" {
		db, err := gorm.Open(postgres.Open(*dsn), &gorm.Config{})
		if err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}
		var ks oa.KeyLookup = gormstore.NewKeyStore(db)
		// Wrap with encryption if master key is set (must match oneauth-server's key
		// so HS256 secrets encrypted by the server can be decrypted here)
		if masterKey := os.Getenv("ONEAUTH_MASTER_KEY"); masterKey != "" {
			encrypted, err := oa.NewEncryptedKeyStorage(gormstore.NewKeyStore(db), masterKey)
			if err != nil {
				log.Fatalf("Failed to create EncryptedKeyStore: %v", err)
			}
			ks = encrypted
			log.Printf("[%s] KeyStore encryption enabled (AES-256-GCM)", *name)
		}
		keyStore = ks
		log.Printf("[%s] Connected to shared KeyStore via PostgreSQL", *name)
	} else {
		log.Printf("[%s] WARNING: No JWKS_URL or DATABASE_URL set — using empty in-memory KeyStore (no validation possible)", *name)
		keyStore = oa.NewInMemoryKeyStore()
	}

	// Validation log (ring buffer of recent validations)
	var (
		logMu      sync.Mutex
		logEntries []validationEntry
	)
	addEntry := func(e validationEntry) {
		logMu.Lock()
		defer logMu.Unlock()
		logEntries = append(logEntries, e)
		if len(logEntries) > 100 {
			logEntries = logEntries[len(logEntries)-100:]
		}
	}
	getEntries := func() []validationEntry {
		logMu.Lock()
		defer logMu.Unlock()
		out := make([]validationEntry, len(logEntries))
		copy(out, logEntries)
		// Reverse (most recent first)
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
		return out
	}

	// APIMiddleware for JWT validation
	middleware := &oa.APIMiddleware{
		KeyStore:        keyStore,
		TokenQueryParam: "token",
	}

	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "resource_server": *name})
	})

	// Status page
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		entries := getEntries()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		templates.ExecuteTemplate(w, "layout", map[string]any{
			"Title":          *name + " — Status",
			"ResourceServer": *name,
			"Entries":        entries,
			"Page":           "status",
		})
	})

	// Test page (paste a JWT)
	mux.HandleFunc("GET /test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		templates.ExecuteTemplate(w, "layout", map[string]any{
			"Title":          *name + " — Test JWT",
			"ResourceServer": *name,
			"Page":           "test",
		})
	})

	// Validate endpoint
	validateHandler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := oa.GetUserIDFromAPIContext(r.Context())
		customClaims := oa.GetCustomClaimsFromContext(r.Context())
		clientID, _ := customClaims["client_id"].(string)

		addEntry(validationEntry{
			Time:     time.Now(),
			UserID:   userID,
			ClientID: clientID,
			Valid:    true,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"valid":           true,
			"user_id":         userID,
			"custom_claims":   customClaims,
			"resource_server": *name,
		})
	}))

	mux.HandleFunc("POST /validate", func(w http.ResponseWriter, r *http.Request) {
		// Wrap with error logging
		wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			validateHandler.ServeHTTP(w, r)
		})

		// Use a response recorder to capture errors
		rec := &responseRecorder{ResponseWriter: w, statusCode: 200}
		wrappedHandler.ServeHTTP(rec, r)

		if rec.statusCode != 200 {
			addEntry(validationEntry{
				Time:  time.Now(),
				Valid: false,
				Error: "Authentication failed",
			})
		}
	})

	// Simulated WebSocket validation (validates ?token= query param)
	mux.HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
		validateHandler.ServeHTTP(w, r)
	})

	addr := ":" + *port
	log.Printf("[%s] Resource server listening on %s", *name, addr)
	log.Fatal(http.ListenAndServe(addr, corsMiddleware(mux)))
}

// responseRecorder captures the status code for logging.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

// corsMiddleware allows cross-origin requests from demo apps.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func envOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
