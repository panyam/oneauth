// Example 04: AS Metadata Discovery (RFC 8414).
//
// In Examples 01-03 we hardcoded URLs like authServer.URL+"/api/token".
// In production, clients discover endpoints automatically from a single
// well-known URL — same mechanism Keycloak / Auth0 / Authlete use.
//
// Two-process architecture:
//
//	make serve   # auth :8081 (full discovery surface), resource :8082
//	make demo    # walkthrough that drives both
//
// See: https://www.rfc-editor.org/rfc/rfc8414
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

const jwtSecret = "discovery-example-secret-32chars!"

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
	asPublicURL := flag.String("as-url", "", "external URL of the AS (used as issuer; default http://localhost<as-addr>)")
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
	asMux := newAuthServer(ks, issuer)
	rsMux := newResourceServer(issuer)

	go func() {
		log.Printf("[example-04] resource server listening on %s", *rsAddr)
		if err := http.ListenAndServe(*rsAddr, rsMux); err != nil {
			log.Fatalf("resource server: %v", err)
		}
	}()
	log.Printf("[example-04] auth server listening on %s (issuer=%s)", *asAddr, issuer)
	log.Printf("[example-04] discovery: curl %s/.well-known/openid-configuration", issuer)
	if err := http.ListenAndServe(*asAddr, asMux); err != nil {
		log.Fatalf("auth server: %v", err)
	}
}

// newAuthServer wires the full discovery surface: registration, token
// endpoint, JWKS, introspection, and the discovery document itself.
// `issuer` is the canonical public URL — token `iss` claims and the
// metadata `issuer` field both use it, and the RS's `JWTIssuer` must
// match.
func newAuthServer(ks keys.KeyStorage, issuer string) http.Handler {
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	jwksHandler := &keys.JWKSHandler{KeyStore: ks}

	apiAuth := &apiauth.APIAuth{
		JWTSecretKey:   jwtSecret,
		JWTIssuer:      issuer,
		ClientKeyStore: ks,
	}
	introspection := apiauth.NewIntrospectionHandler(apiAuth, ks)

	mux := http.NewServeMux()
	mux.Handle("/apps/", registrar.Handler())
	mux.HandleFunc("POST /api/token", apiAuth.ServeHTTP)
	mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler.ServeHTTP)
	mux.Handle("POST /oauth/introspect", introspection)
	mux.Handle("GET /.well-known/openid-configuration",
		apiauth.NewASMetadataHandler(&apiauth.ASServerMetadata{
			Issuer:                        issuer,
			TokenEndpoint:                 issuer + "/api/token",
			JWKSURI:                       issuer + "/.well-known/jwks.json",
			IntrospectionEndpoint:         issuer + "/oauth/introspect",
			RegistrationEndpoint:          issuer + "/apps/register",
			ScopesSupported:               []string{"read", "write", "admin"},
			GrantTypesSupported:           []string{"client_credentials"},
			ResponseTypesSupported:        []string{"token"},
			TokenEndpointAuthMethods:      []string{"client_secret_post", "client_secret_basic"},
			CodeChallengeMethodsSupported: []string{"S256"},
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
