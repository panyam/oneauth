// Example 10: Security — Attack Prevention.
//
// Demonstrates real attacks against JWT-based auth and OneAuth's
// defenses: algorithm confusion (CVE-2015-9235), alg:none, cross-app
// forgery, and JWKS leak prevention.
//
// Two-process architecture:
//
//	make serve   # auth + JWKS :8081, protected resource :8082
//	make demo    # walkthrough that drives both
//
// In --serve mode you can fuzz the resource endpoint with crafted
// tokens to verify the middleware blocks them in your environment too:
//
//	curl http://localhost:8082/resource -H "Authorization: Bearer <crafted-token>"
//
// See: https://nvd.nist.gov/vuln/detail/CVE-2015-9235
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// servePreseededApps wires the two demo apps that the walkthrough
// references — `app-rsa` (RS256) and `app-hmac` (HS256). main and
// walkthrough both call this so the KeyStore is identical between
// modes.
func servePreseededApps(ks *keys.InMemoryKeyStore) (*rsa.PrivateKey, []byte) {
	rsaPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubPEM, _ := utils.EncodePublicKeyPEM(&rsaPrivKey.PublicKey)
	ks.RegisterKey("app-rsa", pubPEM, "RS256")
	ks.RegisterKey("app-hmac", []byte("shared-secret-for-hs256-app"), "HS256")
	return rsaPrivKey, pubPEM
}

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
	asAddr := flag.String("as-addr", ":8081", "auth/JWKS server listen address")
	rsAddr := flag.String("rs-addr", ":8082", "protected resource listen address")
	args := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		if a != "--serve" {
			args = append(args, a)
		}
	}
	flag.CommandLine.Parse(args)

	ks := keys.NewInMemoryKeyStore()
	servePreseededApps(ks)

	go func() {
		log.Printf("[example-10] resource server listening on %s", *rsAddr)
		if err := http.ListenAndServe(*rsAddr, newResourceServer(ks)); err != nil {
			log.Fatalf("resource server: %v", err)
		}
	}()
	log.Printf("[example-10] auth/JWKS server listening on %s", *asAddr)
	log.Printf("[example-10] try crafting tokens and POSTing them at %s/resource", *rsAddr)
	if err := http.ListenAndServe(*asAddr, newAuthServer(ks)); err != nil {
		log.Fatalf("auth server: %v", err)
	}
}

func newAuthServer(ks *keys.InMemoryKeyStore) http.Handler {
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	jwksHandler := &keys.JWKSHandler{KeyStore: ks}

	mux := http.NewServeMux()
	mux.Handle("/apps/", registrar.Handler())
	mux.Handle("GET /.well-known/jwks.json", jwksHandler)
	return mux
}

// newResourceServer is the strict-validation endpoint — middleware
// checks alg-vs-stored-key match, kid-owns-client_id, and rejects
// alg:none. This is what the walkthrough fires forged tokens against.
func newResourceServer(ks keys.KeyStorage) http.Handler {
	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	mux := http.NewServeMux()
	mux.Handle("GET /resource", middleware.ValidateToken(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			custom := apiauth.GetCustomClaimsFromContext(r.Context())
			fmt.Fprintf(w, `{"user":%q,"client_id":%q}`,
				apiauth.GetUserIDFromAPIContext(r.Context()),
				custom["client_id"])
		}),
	))
	return mux
}
