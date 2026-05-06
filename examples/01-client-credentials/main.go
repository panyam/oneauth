// Example 01: OAuth 2.0 Client Credentials Flow.
//
// Two-process architecture:
//
//	Terminal 1:  make serve    # auth server :8081, resource server :8082
//	Terminal 2:  make demo     # demokit walkthrough (--tui for the TUI)
//
// The servers in --serve mode are real HTTP servers — any OAuth client
// (curl, your own app, MCP host, …) can hit them. The walkthrough is
// just one such client: it spins up the same servers in-process via
// httptest and drives them step-by-step. See walkthrough.go.
//
// Run:
//
//	make demo                     # interactive walkthrough (default)
//	make demo --tui               # styled TUI walkthrough
//	make serve                    # just run the servers, block
//	make walkthrough              # regenerate WALKTHROUGH.md
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
)

// jwtSecret is the HS256 secret shared by the AS that signs tokens and
// the RS that validates them. Real deployments rotate this and use
// per-client keys via KeyStore — see example 02.
const jwtSecret = "example-jwt-secret-at-least-32ch"

const jwtIssuer = "oneauth-example-01"

func main() {
	for _, arg := range os.Args[1:] {
		if strings.TrimSpace(arg) == "--serve" {
			serve()
			return
		}
	}
	runDemo()
}

// serve binds the auth server and resource server on real ports so an
// external client (curl, your app, an MCP host) can drive them.
func serve() {
	asAddr := flag.String("as-addr", ":8081", "auth server listen address")
	rsAddr := flag.String("rs-addr", ":8082", "resource server listen address")
	// Re-parse the flags after stripping --serve (which we already
	// consumed) so flag.Parse doesn't choke on it.
	args := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		if a != "--serve" {
			args = append(args, a)
		}
	}
	flag.CommandLine.Parse(args)

	ks := keys.NewInMemoryKeyStore()
	asMux := newAuthServer(ks)
	rsMux := newResourceServer()

	go func() {
		log.Printf("[example-01] resource server listening on %s", *rsAddr)
		if err := http.ListenAndServe(*rsAddr, rsMux); err != nil {
			log.Fatalf("resource server: %v", err)
		}
	}()
	log.Printf("[example-01] auth server listening on %s", *asAddr)
	log.Printf("[example-01] try: curl -X POST http://localhost%s/apps/register -d '{\"client_domain\":\"my.example.com\",\"signing_alg\":\"HS256\"}'", *asAddr)
	if err := http.ListenAndServe(*asAddr, asMux); err != nil {
		log.Fatalf("auth server: %v", err)
	}
}

// newAuthServer builds the auth-server HTTP handler. Used by both --serve
// (real listener) and the walkthrough (httptest.Server). The shared
// builder keeps the two modes byte-identical so a curl reproduction in
// the README always matches what the walkthrough exercises.
func newAuthServer(ks keys.KeyStorage) http.Handler {
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	apiAuth := &apiauth.APIAuth{
		JWTSecretKey:   jwtSecret,
		JWTIssuer:      jwtIssuer,
		ClientKeyStore: ks,
	}

	mux := http.NewServeMux()
	mux.Handle("/apps/", registrar.Handler())
	mux.HandleFunc("POST /api/token", apiAuth.ServeHTTP)
	return mux
}

// newResourceServer builds the resource-server HTTP handler. Validates
// JWTs with the same secret the AS signs with — for HS256, AS and RS
// must share the secret. RS256 (example 03) splits this via JWKS.
func newResourceServer() http.Handler {
	middleware := &apiauth.APIMiddleware{
		JWTSecretKey: jwtSecret,
		JWTIssuer:    jwtIssuer,
	}
	mux := http.NewServeMux()
	mux.Handle("GET /resource", middleware.ValidateToken(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"message": "hello from protected resource",
				"sub":     apiauth.GetUserIDFromAPIContext(r.Context()),
				"scopes":  apiauth.GetScopesFromAPIContext(r.Context()),
			})
		}),
	))
	return mux
}
