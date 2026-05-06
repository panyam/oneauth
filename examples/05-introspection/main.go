// Example 05: Token Introspection (RFC 7662).
//
// In examples 01-04 the resource server validated tokens locally by
// checking the JWT signature. That's fast, but if a token is revoked,
// the RS won't know until expiry. Introspection is the alternative: the
// RS asks the AS "is this token still valid?" — the AS checks its
// blacklist and returns the token's claims (or `{active: false}`).
//
// Two-process architecture:
//
//	make serve   # auth :8081 with token + introspection + blacklist
//	make demo    # walkthrough that drives it
//
// See: https://www.rfc-editor.org/rfc/rfc7662
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
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

const jwtSecret = "introspection-example-secret-32c!"

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
	blacklist := core.NewInMemoryBlacklist()

	log.Printf("[example-05] auth server listening on %s (issuer=%s)", *asAddr, issuer)
	log.Printf("[example-05] introspection: POST http://localhost%s/oauth/introspect", *asAddr)
	if err := http.ListenAndServe(*asAddr, newAuthServer(ks, blacklist, issuer)); err != nil {
		log.Fatalf("auth server: %v", err)
	}
}

// newAuthServer wires registration, token issuance, and introspection.
// The shared blacklist is what makes introspection-based revocation
// work — `RevocationHandler` (or any admin tool) can call
// `blacklist.Revoke(jti, exp)` to invalidate a token immediately.
func newAuthServer(ks keys.KeyStorage, blacklist core.TokenBlacklist, issuer string) http.Handler {
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	apiAuth := &apiauth.APIAuth{
		JWTSecretKey:   jwtSecret,
		JWTIssuer:      issuer,
		ClientKeyStore: ks,
		Blacklist:      blacklist,
	}
	introspectionHandler := apiauth.NewIntrospectionHandler(apiAuth, ks)

	mux := http.NewServeMux()
	mux.Handle("/apps/", registrar.Handler())
	mux.HandleFunc("POST /api/token", apiAuth.ServeHTTP)
	mux.Handle("POST /oauth/introspect", introspectionHandler)
	return mux
}
