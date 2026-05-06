// Example 02: Resource Token with HS256 (Federated Auth).
//
// Building on Example 01: a registered app mints resource-scoped tokens
// for individual users — not just for itself. The resource server
// validates with the same KeyStore the app's secret was registered into.
//
// Two-process architecture (mirrors Example 01):
//
//	make serve      # auth server :8081, resource server :8082
//	make demo       # demokit walkthrough (--tui for the styled TUI)
//
// In --serve mode the auth server and resource server share an
// in-process KeyStore (registration on the AS makes the secret visible
// to the RS for validation). A real deployment would back this with a
// persisted KeyStore (FS / GORM / GAE).
//
// See: https://www.rfc-editor.org/rfc/rfc7519 (JWT)
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
	args := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		if a != "--serve" {
			args = append(args, a)
		}
	}
	flag.CommandLine.Parse(args)

	ks := keys.NewInMemoryKeyStore()
	asMux := newAuthServer(ks)
	rsMux := newResourceServer(ks)

	go func() {
		log.Printf("[example-02] resource server listening on %s", *rsAddr)
		if err := http.ListenAndServe(*rsAddr, rsMux); err != nil {
			log.Fatalf("resource server: %v", err)
		}
	}()
	log.Printf("[example-02] auth server listening on %s", *asAddr)
	log.Printf("[example-02] register: curl -X POST http://localhost%s/apps/register -d '{\"client_domain\":\"my.example.com\",\"signing_alg\":\"HS256\"}'", *asAddr)
	if err := http.ListenAndServe(*asAddr, asMux); err != nil {
		log.Fatalf("auth server: %v", err)
	}
}

// newAuthServer exposes the AppRegistrar — open registration so the
// walkthrough (and any external client) can register fresh apps and
// pull a fresh secret. Real deployments gate this with AdminAuth.
func newAuthServer(ks keys.KeyStorage) http.Handler {
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	mux := http.NewServeMux()
	mux.Handle("/apps/", registrar.Handler())
	return mux
}

// newResourceServer validates JWTs using the same KeyStore the AS
// registered each app's secret into. The RS extracts the user, scopes,
// and the quota claims (max_rooms, max_msg_rate) without ever calling
// back to the auth server.
func newResourceServer(ks keys.KeyStorage) http.Handler {
	middleware := &apiauth.APIMiddleware{KeyStore: ks}
	mux := http.NewServeMux()
	mux.Handle("GET /resource", middleware.ValidateToken(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			custom := apiauth.GetCustomClaimsFromContext(ctx)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"user":      apiauth.GetUserIDFromAPIContext(ctx),
				"scopes":    apiauth.GetScopesFromAPIContext(ctx),
				"client_id": custom["client_id"],
				"max_rooms": custom["max_rooms"],
			})
		}),
	))
	return mux
}
