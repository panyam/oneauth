// Example 03: Resource Token with RS256 + JWKS Discovery.
//
// Asymmetric variant of Example 02. The app generates an RSA key pair,
// registers only the public key, and the resource server discovers the
// public key via JWKS — the private key never leaves the app.
//
// Two-process architecture:
//
//	make serve   # auth :8081 (registration + JWKS), resource :8082 (JWKS-discovered RS)
//	make demo    # walkthrough that drives both
//
// See: https://www.rfc-editor.org/rfc/rfc7517 (JWK)
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
	asPublicURL := flag.String("as-url", "", "auth server URL the RS uses to fetch JWKS (default http://localhost<as-addr>)")
	args := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		if a != "--serve" {
			args = append(args, a)
		}
	}
	flag.CommandLine.Parse(args)

	ks := keys.NewInMemoryKeyStore()
	asMux := newAuthServer(ks)

	jwksURL := *asPublicURL
	if jwksURL == "" {
		jwksURL = fmt.Sprintf("http://localhost%s/.well-known/jwks.json", *asAddr)
	} else {
		jwksURL = strings.TrimRight(jwksURL, "/") + "/.well-known/jwks.json"
	}
	rsMux := newResourceServer(jwksURL)

	go func() {
		log.Printf("[example-03] resource server listening on %s (JWKS source: %s)", *rsAddr, jwksURL)
		if err := http.ListenAndServe(*rsAddr, rsMux); err != nil {
			log.Fatalf("resource server: %v", err)
		}
	}()
	log.Printf("[example-03] auth server listening on %s", *asAddr)
	log.Printf("[example-03] register an RS256 app with a PEM-encoded public_key field — see WALKTHROUGH.md")
	if err := http.ListenAndServe(*asAddr, asMux); err != nil {
		log.Fatalf("auth server: %v", err)
	}
}

// newAuthServer builds the auth server: AppRegistrar (open) and a JWKS
// endpoint that serves only public keys (HS256 secrets are excluded by
// JWKSHandler — see keys/jwks.go).
func newAuthServer(ks keys.KeyStorage) http.Handler {
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	jwksHandler := &keys.JWKSHandler{KeyStore: ks}

	mux := http.NewServeMux()
	mux.Handle("/apps/", registrar.Handler())
	mux.Handle("GET /.well-known/jwks.json", jwksHandler)
	return mux
}

// newResourceServer wires APIMiddleware to a JWKSKeyStore that fetches
// and caches the public keys from the AS's JWKS endpoint. The RS never
// shares storage with the AS — discovery is purely over HTTP.
func newResourceServer(jwksURL string) http.Handler {
	jwksKS := keys.NewJWKSKeyStore(jwksURL, keys.WithMinRefreshGap(0))
	jwksKS.Start()

	middleware := &apiauth.APIMiddleware{KeyStore: jwksKS}
	mux := http.NewServeMux()
	mux.Handle("GET /resource", middleware.ValidateToken(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"user":   apiauth.GetUserIDFromAPIContext(ctx),
				"scopes": apiauth.GetScopesFromAPIContext(ctx),
			})
		}),
	))
	return mux
}
