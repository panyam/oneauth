// Example 06: Dynamic Client Registration (RFC 7591).
//
// Self-service client onboarding via the standard DCR endpoint
// (`/apps/dcr`) — same request shape works against OneAuth, Keycloak,
// Auth0, and any compliant AS. Supports both client_secret_post and
// private_key_jwt registrations.
//
// Two-process architecture:
//
//	make serve   # auth :8081 with /apps/dcr + token + JWKS + discovery
//	make demo    # walkthrough that drives both
//
// See: https://www.rfc-editor.org/rfc/rfc7591
package main

import (
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

const jwtSecret = "dcr-example-secret-at-least-32ch!"

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
	log.Printf("[example-06] auth server listening on %s (issuer=%s)", *asAddr, issuer)
	log.Printf("[example-06] DCR: POST %s/apps/dcr", issuer)
	if err := http.ListenAndServe(*asAddr, newAuthServer(ks, issuer)); err != nil {
		log.Fatalf("auth server: %v", err)
	}
}

// newAuthServer wires the DCR endpoint (under /apps/) plus token, JWKS,
// and discovery so a freshly-registered client can immediately fetch
// the AS metadata, mint a token, and verify signatures.
func newAuthServer(ks keys.KeyStorage, issuer string) http.Handler {
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	jwksHandler := &keys.JWKSHandler{KeyStore: ks}

	apiAuth := &apiauth.APIAuth{
		JWTSecretKey:   jwtSecret,
		JWTIssuer:      issuer,
		ClientKeyStore: ks,
	}

	mux := http.NewServeMux()
	mux.Handle("/apps/", registrar.Handler())
	mux.HandleFunc("POST /api/token", apiAuth.ServeHTTP)
	mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler.ServeHTTP)
	mux.Handle("GET /.well-known/openid-configuration",
		apiauth.NewASMetadataHandler(&apiauth.ASServerMetadata{
			Issuer:                   issuer,
			TokenEndpoint:            issuer + "/api/token",
			JWKSURI:                  issuer + "/.well-known/jwks.json",
			RegistrationEndpoint:     issuer + "/apps/dcr",
			GrantTypesSupported:      []string{"client_credentials"},
			TokenEndpointAuthMethods: []string{"client_secret_post", "client_secret_basic", "private_key_jwt"},
		}))
	return mux
}
