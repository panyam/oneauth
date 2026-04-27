// cmd/rar-test-issuer is a minimal OAuth 2.0 Authorization Server that supports
// RFC 9396 Rich Authorization Requests. It is designed as a test fixture for
// interop testing — proving that OneAuth resource servers can validate RAR tokens
// issued by an external AS over real HTTP.
//
// This server fills a gap: no open-source IdP (Keycloak, Curity, etc.) currently
// supports RFC 9396 on standard OAuth flows (client_credentials, authorization_code).
// When Keycloak adds RAR support (tracked: keycloak/keycloak#29340), the interop
// tests should be migrated to use Keycloak and this binary can be retired.
//
// Endpoints:
//
//	POST /api/token                          — token endpoint (client_credentials + RAR)
//	POST /oauth/introspect                   — token introspection (RFC 7662)
//	GET  /.well-known/openid-configuration   — AS metadata (RFC 8414 + RFC 9396 §10)
//	GET  /.well-known/jwks.json              — JWKS (RFC 7517)
//	GET  /_ah/health                         — health check
//
// Pre-registered clients:
//
//	client_id: rar-test-client       secret: rar-test-secret
//	client_id: rar-introspect-client secret: rar-introspect-secret
//
// Usage:
//
//	go run ./cmd/rar-test-issuer                    # default :8181
//	RAR_ISSUER_PORT=9090 go run ./cmd/rar-test-issuer
//
// See: https://www.rfc-editor.org/rfc/rfc9396
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

const (
	defaultPort = "8181"

	// Pre-registered test clients
	testClientID     = "rar-test-client"
	testClientSecret = "rar-test-secret"

	introClientID     = "rar-introspect-client"
	introClientSecret = "rar-introspect-secret"
)

// Supported authorization_details types — advertised in AS metadata.
// Tests request these types to verify the full RAR flow.
var supportedRARTypes = []string{
	"payment_initiation",
	"account_information",
	"signing_service",
}

func main() {
	port := os.Getenv("RAR_ISSUER_PORT")
	if port == "" {
		port = defaultPort
	}
	baseURL := fmt.Sprintf("http://localhost:%s", port)

	// Generate RS256 key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Key store with the server's public key + pre-registered clients
	ks := keys.NewInMemoryKeyStore()

	pubPEM, err := utils.EncodePublicKeyPEM(&privKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to encode public key: %v", err)
	}
	kid, err := utils.ComputeKid(&privKey.PublicKey, "RS256")
	if err != nil {
		log.Fatalf("Failed to compute kid: %v", err)
	}
	ks.PutKey(&keys.KeyRecord{ClientID: "rar-test-issuer", Key: pubPEM, Algorithm: "RS256", Kid: kid})

	// Register test clients
	ks.PutKey(&keys.KeyRecord{ClientID: testClientID, Key: []byte(testClientSecret), Algorithm: "HS256"})
	ks.PutKey(&keys.KeyRecord{ClientID: introClientID, Key: []byte(introClientSecret), Algorithm: "HS256"})

	// API Auth (token endpoint)
	apiAuth := &apiauth.APIAuth{
		JWTSigningAlg:  "RS256",
		JWTSigningKey:  privKey,
		JWTVerifyKey:   &privKey.PublicKey,
		JWTIssuer:      baseURL,
		ClientKeyStore: ks,
	}

	// Introspection
	introspection := apiauth.NewIntrospectionHandler(apiAuth, ks)

	// JWKS
	jwksHandler := &keys.JWKSHandler{KeyStore: ks}

	// AS Metadata with authorization_details_types_supported (RFC 9396 §10)
	asMeta := apiauth.NewASMetadataHandler(&apiauth.ASServerMetadata{
		Issuer:                             baseURL,
		TokenEndpoint:                      baseURL + "/api/token",
		JWKSURI:                            baseURL + "/.well-known/jwks.json",
		IntrospectionEndpoint:              baseURL + "/oauth/introspect",
		ScopesSupported:                    []string{"read", "write", "payments", "accounts"},
		GrantTypesSupported:                []string{"client_credentials"},
		ResponseTypesSupported:             []string{"token"},
		TokenEndpointAuthMethods:           []string{"client_secret_post", "client_secret_basic"},
		AuthorizationDetailsTypesSupported: supportedRARTypes,
	})

	// App registration (for DCR tests)
	registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())

	// Routes
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_ah/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /api/token", apiAuth.ServeHTTP)
	mux.Handle("POST /oauth/introspect", introspection)
	mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler.ServeHTTP)
	mux.Handle("GET /.well-known/openid-configuration", asMeta)
	mux.Handle("/apps/", registrar.Handler())

	log.Printf("rar-test-issuer listening on :%s", port)
	log.Printf("  Clients: %s, %s", testClientID, introClientID)
	log.Printf("  RAR types: %v", supportedRARTypes)
	log.Printf("  JWKS: %s/.well-known/jwks.json", baseURL)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
