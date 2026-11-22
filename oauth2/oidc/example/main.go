// Command example signs a person in through any OpenID Connect provider
// with oauth2/oidc. By default it points at the Keycloak realm in the
// repo's docker-compose.yml:
//
//	docker compose up -d keycloak
//	go run ./oauth2/oidc/example
//	open http://127.0.0.1:8080/        (log in as testuser / testpassword)
//
//	go run ./oauth2/oidc/example -device   (sign in from the terminal)
//
// Point it at your own provider with -issuer, -client and -secret, and
// register http://127.0.0.1:8080/auth/oidc/callback/ as a redirect URI.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"golang.org/x/oauth2"

	"github.com/panyam/oneauth/oauth2/oidc"
)

func main() {
	issuer := flag.String("issuer", "http://localhost:8180/realms/oneauth-test", "OpenID Connect issuer URL")
	clientID := flag.String("client", "test-confidential", "client id")
	secret := flag.String("secret", "test-secret-for-confidential-client", "client secret")
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	domains := flag.String("allow-domains", "example.com", "comma-separated email domains allowed to sign in")
	device := flag.Bool("device", false, "sign in with the device flow instead of serving")
	flag.Parse()

	allow := oidc.AllowList{EmailDomains: strings.Split(*domains, ",")}
	p, err := oidc.New(context.Background(), oidc.Config{
		Issuer:       *issuer,
		ClientID:     *clientID,
		ClientSecret: *secret,
		CallbackURL:  "http://" + *addr + "/auth/oidc/callback/",
		HandleUser: func(_, _ string, _ *oauth2.Token, claims map[string]any, w http.ResponseWriter, r *http.Request) {
			if !allow.Allows(claims) {
				http.Error(w, fmt.Sprintf("%v may not sign in here", claims["email"]), http.StatusForbidden)
				return
			}
			// A real app starts its session here.
			w.Header().Set("Content-Type", "application/json")
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			_ = enc.Encode(claims)
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	if *device {
		signInFromTerminal(p, allow)
		return
	}
	mux := http.NewServeMux()
	mux.Handle("/auth/oidc/", http.StripPrefix("/auth/oidc", p.Handler()))
	mux.HandleFunc("/auth/failed", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "sign-in failed", http.StatusUnauthorized)
	})
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `<a href="/auth/oidc/">Sign in</a>`)
	})
	log.Printf("open http://%s/", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func signInFromTerminal(p *oidc.Provider, allow oidc.AllowList) {
	ctx := context.Background()
	da, err := p.DeviceAuth(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Open %s and enter %s\n", da.VerificationURI, da.UserCode)
	if da.VerificationURIComplete != "" {
		fmt.Printf("or open %s\n", da.VerificationURIComplete)
	}
	_, claims, err := p.DeviceAccessToken(ctx, da)
	if err != nil {
		log.Fatal(err)
	}
	if !allow.Allows(claims.Claims) {
		log.Fatalf("%v may not sign in here", claims.Claims["email"])
	}
	fmt.Printf("signed in as %s (%v)\n", claims.Subject, claims.Claims["email"])
}
