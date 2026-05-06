// Example 07: Client SDK — Production Patterns.
//
// Examples 01-06 made raw `http.Post` calls. This one shows how
// production client code uses OneAuth's SDK: discovery-driven
// configuration, automatic token caching, scope step-up, all behind
// the `TokenSource` interface.
//
// Two-process architecture:
//
//	make serve   # auth :8081 with token + discovery, resource :8082
//	make demo    # walkthrough that drives both
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
)

const jwtSecret = "sdk-example-secret-at-least-32ch!"

func main() {
	for _, arg := range os.Args[1:] {
		if strings.TrimSpace(arg) == "--serve" {
			serve()
			return
		}
	}
	runDemo()
}

func serve() {
	asAddr := flag.String("as-addr", ":8081", "auth server listen address")
	rsAddr := flag.String("rs-addr", ":8082", "resource server listen address")
	asPublicURL := flag.String("as-url", "", "external URL of the AS (issuer); default http://localhost<as-addr>")
	args := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		if a != "--serve" {
			args = append(args, a)
		}
	}
	flag.CommandLine.Parse(args)

	issuer := *asPublicURL
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost%s", *asAddr)
	}

	ks := keys.NewInMemoryKeyStore()
	go func() {
		log.Printf("[example-07] resource server listening on %s", *rsAddr)
		if err := http.ListenAndServe(*rsAddr, newResourceServer(issuer)); err != nil {
			log.Fatalf("resource server: %v", err)
		}
	}()
	log.Printf("[example-07] auth server listening on %s (issuer=%s)", *asAddr, issuer)
	if err := http.ListenAndServe(*asAddr, newAuthServer(ks, issuer)); err != nil {
		log.Fatalf("auth server: %v", err)
	}
}

func newAuthServer(ks keys.KeyStorage, issuer string) http.Handler {
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	apiAuth := &apiauth.APIAuth{
		JWTSecretKey:   jwtSecret,
		JWTIssuer:      issuer,
		ClientKeyStore: ks,
	}

	mux := http.NewServeMux()
	mux.Handle("/apps/", registrar.Handler())
	mux.HandleFunc("POST /api/token", apiAuth.ServeHTTP)
	mux.Handle("GET /.well-known/openid-configuration",
		apiauth.NewASMetadataHandler(&apiauth.ASServerMetadata{
			Issuer:                   issuer,
			TokenEndpoint:            issuer + "/api/token",
			GrantTypesSupported:      []string{"client_credentials"},
			TokenEndpointAuthMethods: []string{"client_secret_post", "client_secret_basic"},
		}))
	return mux
}

func newResourceServer(issuer string) http.Handler {
	middleware := &apiauth.APIMiddleware{
		JWTSecretKey: jwtSecret,
		JWTIssuer:    issuer,
	}
	mux := http.NewServeMux()
	mux.Handle("GET /resource", middleware.ValidateToken(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"user":   apiauth.GetUserIDFromAPIContext(r.Context()),
				"scopes": apiauth.GetScopesFromAPIContext(r.Context()),
			})
		}),
	))
	return mux
}
