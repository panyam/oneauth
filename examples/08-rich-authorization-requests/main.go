// Example 08: Rich Authorization Requests (RFC 9396).
//
// Flat scopes can't express "transfer 45 EUR to Merchant A". RAR adds
// structured `authorization_details` to the token endpoint, JWT claim,
// introspection response, and middleware enforcement.
//
// Three-server architecture:
//
//	make serve    # auth :8081, payments :8082, accounts :8083
//	make demo     # walkthrough that drives all three
//
// See: https://www.rfc-editor.org/rfc/rfc9396
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

const jwtSecret = "rar-example-secret-at-least-32ch!"

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
	payAddr := flag.String("payments-addr", ":8082", "payments RS listen address")
	acctAddr := flag.String("accounts-addr", ":8083", "accounts RS listen address")
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
		log.Printf("[example-08] payments RS listening on %s", *payAddr)
		if err := http.ListenAndServe(*payAddr, newPaymentsServer(issuer)); err != nil {
			log.Fatalf("payments server: %v", err)
		}
	}()
	go func() {
		log.Printf("[example-08] accounts RS listening on %s", *acctAddr)
		if err := http.ListenAndServe(*acctAddr, newAccountsServer(issuer)); err != nil {
			log.Fatalf("accounts server: %v", err)
		}
	}()
	log.Printf("[example-08] auth server listening on %s (issuer=%s)", *asAddr, issuer)
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
	introspection := apiauth.NewIntrospectionHandler(apiAuth, ks)

	mux := http.NewServeMux()
	mux.Handle("/apps/", registrar.Handler())
	mux.HandleFunc("POST /api/token", apiAuth.ServeHTTP)
	mux.Handle("POST /oauth/introspect", introspection)
	mux.Handle("GET /.well-known/openid-configuration",
		apiauth.NewASMetadataHandler(&apiauth.ASServerMetadata{
			Issuer:                             issuer,
			TokenEndpoint:                      issuer + "/api/token",
			IntrospectionEndpoint:              issuer + "/oauth/introspect",
			GrantTypesSupported:                []string{"client_credentials"},
			TokenEndpointAuthMethods:           []string{"client_secret_post", "client_secret_basic"},
			AuthorizationDetailsTypesSupported: []string{"payment_initiation", "account_information"},
		}))
	return mux
}

// newPaymentsServer enforces `payment_initiation` authorization_details.
// A token without that type — even with the right scopes — is rejected.
func newPaymentsServer(issuer string) http.Handler {
	mw := &apiauth.APIMiddleware{JWTSecretKey: jwtSecret, JWTIssuer: issuer}
	mux := http.NewServeMux()
	mux.Handle("POST /payments", mw.RequireAuthorizationDetails("payment_initiation")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			details := apiauth.GetAuthorizationDetailsFromContext(r.Context())
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"status":  "payment_accepted",
				"details": details,
			})
		}),
	))
	return mux
}

// newAccountsServer enforces `account_information` authorization_details.
func newAccountsServer(issuer string) http.Handler {
	mw := &apiauth.APIMiddleware{JWTSecretKey: jwtSecret, JWTIssuer: issuer}
	mux := http.NewServeMux()
	mux.Handle("GET /accounts", mw.RequireAuthorizationDetails("account_information")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			details := apiauth.GetAuthorizationDetailsFromContext(r.Context())
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"status":  "accounts_listed",
				"details": details,
			})
		}),
	))
	return mux
}
