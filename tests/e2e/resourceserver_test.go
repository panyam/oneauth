package e2e_test

// Resource server wiring for e2e tests. Mirrors cmd/demo-resource-server/main.go
// but uses JWKS from the in-process auth server.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
)

// buildResourceServers starts two resource servers that discover keys
// via JWKS from the auth server. Uses the auth server's httptest.Client
// so JWKS fetching works in-process (no real network).
func (e *TestEnv) buildResourceServers(t *testing.T) {
	t.Helper()
	e.ResourceServerA = buildOneResourceServer(t, "resource-a", e.AuthServer, e.KeyStore)
	e.ResourceServerB = buildOneResourceServer(t, "resource-b", e.AuthServer, e.KeyStore)
}

func buildOneResourceServer(t *testing.T, name string, authServer *httptest.Server, sharedKeyStore ...keys.KeyLookup) *httptest.Server {
	t.Helper()

	// Build key lookup: shared KeyStore (for HS256) + JWKS (for asymmetric)
	jwksURL := authServer.URL + "/.well-known/jwks.json"
	jwksKS := keys.NewJWKSKeyStore(jwksURL,
		keys.WithHTTPClient(authServer.Client()),
		keys.WithMinRefreshGap(0),
	)
	if err := jwksKS.Start(); err != nil {
		t.Fatalf("Failed to start JWKS KeyStore for %s: %v", name, err)
	}
	t.Cleanup(jwksKS.Stop)

	var keyLookup keys.KeyLookup = jwksKS
	if len(sharedKeyStore) > 0 && sharedKeyStore[0] != nil {
		// Composite: try shared KeyStore first (has HS256 secrets), then JWKS (has asymmetric)
		keyLookup = &keys.CompositeKeyLookup{Lookups: []keys.KeyLookup{sharedKeyStore[0], jwksKS}}
	}

	mw := &apiauth.APIMiddleware{
		KeyStore:        keyLookup,
		TokenQueryParam: "token",
	}

	var (
		logMu      sync.Mutex
		logEntries []map[string]any
	)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "resource_server": name})
	})

	mux.Handle("POST /validate", mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := apiauth.GetUserIDFromAPIContext(r.Context())
		customClaims := apiauth.GetCustomClaimsFromContext(r.Context())

		entry := map[string]any{
			"user_id":       userID,
			"valid":         true,
			"custom_claims": customClaims,
		}
		logMu.Lock()
		logEntries = append(logEntries, entry)
		logMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entry)
	})))

	mux.Handle("GET /resource", mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data":    "protected-resource",
			"user_id": apiauth.GetUserIDFromAPIContext(r.Context()),
		})
	})))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}
