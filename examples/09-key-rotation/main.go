// Example 09: Key Rotation with Grace Periods.
//
// In production, signing keys must be rotated periodically without
// breaking tokens that were issued with the old key. OneAuth uses
// `KidStore` + `CompositeKeyLookup` to keep the old key valid for a
// grace window after rotation.
//
// Two-process architecture:
//
//	make serve   # auth :8081 (registration + rotation), resource :8082
//	make demo    # walkthrough that drives rotation in-process
//
// In --serve mode an admin can drive rotation by hand:
//
//	POST /apps/register            → returns client_id + client_secret (kv1)
//	POST /apps/{id}/rotate         → returns new client_secret (kv2),
//	                                 old key sticks in KidStore for grace period
//	GET  /resource (Bearer token)  → validates against KeyStore + KidStore
//
// See: https://www.rfc-editor.org/rfc/rfc7517 (JWK)
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
)

// gracePeriod is short for demo purposes — production would be hours
// or days, long enough that any in-flight tokens roll over to the new
// key before old ones are invalidated.
const gracePeriod = 100 * time.Millisecond

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
	kidStore := keys.NewKidStore()
	asMux := newAuthServer(ks, kidStore)
	rsMux := newResourceServer(ks, kidStore)

	go func() {
		log.Printf("[example-09] resource server listening on %s", *rsAddr)
		if err := http.ListenAndServe(*rsAddr, rsMux); err != nil {
			log.Fatalf("resource server: %v", err)
		}
	}()
	log.Printf("[example-09] auth server listening on %s", *asAddr)
	log.Printf("[example-09] rotate: curl -X POST http://localhost%s/apps/<client_id>/rotate", *asAddr)
	if err := http.ListenAndServe(*asAddr, asMux); err != nil {
		log.Fatalf("auth server: %v", err)
	}
}

// newAuthServer wires AppRegistrar with a configured KidStore and grace
// period. Rotation moves the old key into KidStore with the grace TTL.
func newAuthServer(ks keys.KeyStorage, kidStore *keys.KidStore) http.Handler {
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
	registrar.KidStore = kidStore
	registrar.DefaultGracePeriod = gracePeriod

	mux := http.NewServeMux()
	mux.Handle("/apps/", registrar.Handler())
	return mux
}

// newResourceServer uses CompositeKeyLookup so the middleware checks the
// current KeyStore first, then falls back to KidStore for grace-period
// keys.
func newResourceServer(ks keys.KeyStorage, kidStore *keys.KidStore) http.Handler {
	composite := &keys.CompositeKeyLookup{
		Lookups: []keys.KeyLookup{ks, kidStore},
	}
	middleware := &apiauth.APIMiddleware{KeyStore: composite}

	mux := http.NewServeMux()
	mux.Handle("GET /resource", middleware.ValidateToken(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"user":%q,"scopes":%q}`,
				apiauth.GetUserIDFromAPIContext(r.Context()),
				apiauth.GetScopesFromAPIContext(r.Context()))
		}),
	))
	return mux
}
