// Example 06: Dynamic Client Registration (RFC 7591)
//
// In Examples 01-05, we registered apps via OneAuth's proprietary /apps/register
// endpoint. That works but is OneAuth-specific. RFC 7591 defines a standard way
// for clients to register themselves — the same API works across OneAuth,
// Keycloak, Auth0, and any compliant provider.
//
// Run:   go run ./examples/06-dynamic-client-registration/
// Docs:  Run with --readme to regenerate README.md
//
// See: https://www.rfc-editor.org/rfc/rfc7591
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/demokit"
	"github.com/panyam/oneauth/examples/refs"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

const kcExamplesURL = "http://localhost:8280"
const kcExamplesRealm = "oneauth-examples"

func main() {
	var authServer *httptest.Server
	var ks keys.KeyStorage
	var symClientID, symClientSecret string
	var asymClientID string

	demo := demokit.New("06: Dynamic Client Registration").
		Dir("06-dynamic-client-registration").
		Description("Non-UI | No infrastructure needed | Builds on Example 04").
		Actors(
			demokit.Actor("App", "New App"),
			demokit.Actor("AS", "Auth Server"),
		)

	demo.Section("About this example",
		"**Actors:** App (a new third-party integration), Auth Server (AS).",
		"Think: a developer builds a new Slack bot and registers it via API — no admin dashboard needed.",
		"[What are these?](../README.md#cast-of-characters)",
		"",
		"In Examples 01-05, we registered via `/apps/register` — OneAuth's proprietary",
		"endpoint. RFC 7591 defines a standard registration API that works across providers:",
		"",
		"| Endpoint | Standard | Works with |",
		"|----------|----------|-----------|",
		"| `/apps/register` | OneAuth proprietary | OneAuth only |",
		"| `/apps/dcr` | RFC 7591 | OneAuth, Keycloak, Auth0, any compliant AS |",
		"",
		"DCR lets apps self-register by posting their metadata (name, redirect URIs,",
		"grant types, auth method). The AS creates the client and returns credentials.",
	)

	// --- Setup ---
	demo.Step("Start auth server with DCR endpoint").
		Ref(refs.RFC7591).
		Ref(refs.RFC8414).
		Note("The auth server serves /apps/dcr (RFC 7591) alongside the proprietary /apps/register. Both create clients in the same KeyStore.").
		Run(func() {
			ks = keys.NewInMemoryKeyStore()
			registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
			jwksHandler := &keys.JWKSHandler{KeyStore: ks}

			apiAuth := &apiauth.APIAuth{
				JWTSecretKey:   "dcr-example-secret-at-least-32ch!",
				ClientKeyStore: ks,
			}

			mux := http.NewServeMux()
			mux.Handle("/apps/", registrar.Handler()) // includes /apps/dcr
			mux.HandleFunc("POST /api/token", apiAuth.ServeHTTP)
			mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler.ServeHTTP)
			authServer = httptest.NewServer(mux)
			apiAuth.JWTIssuer = authServer.URL

			mux.Handle("GET /.well-known/openid-configuration",
				apiauth.NewASMetadataHandler(&apiauth.ASServerMetadata{
					Issuer:                   authServer.URL,
					TokenEndpoint:            authServer.URL + "/api/token",
					JWKSURI:                  authServer.URL + "/.well-known/jwks.json",
					RegistrationEndpoint:     authServer.URL + "/apps/dcr",
					GrantTypesSupported:      []string{"client_credentials"},
					TokenEndpointAuthMethods: []string{"client_secret_post", "client_secret_basic", "private_key_jwt"},
				}))

			fmt.Printf("    Auth server:    %s\n", authServer.URL)
			fmt.Printf("    DCR endpoint:   %s/apps/dcr\n", authServer.URL)
		})

	demo.Section("DCR request format (RFC 7591 §2)",
		"A DCR request is a JSON object with client metadata:",
		"```json",
		"{",
		"  \"client_name\": \"My Bot\",",
		"  \"client_uri\": \"https://mybot.example.com\",",
		"  \"grant_types\": [\"client_credentials\"],",
		"  \"token_endpoint_auth_method\": \"client_secret_post\",",
		"  \"scope\": \"read write\"",
		"}",
		"```",
		"",
		"The AS responds with the registered client metadata plus generated credentials:",
		"```json",
		"{",
		"  \"client_id\": \"app_abc123...\",",
		"  \"client_secret\": \"7f3e8a...\",",
		"  \"client_id_issued_at\": 1700000000,",
		"  \"client_name\": \"My Bot\",",
		"  \"token_endpoint_auth_method\": \"client_secret_post\"",
		"}",
		"```",
	)

	// --- Symmetric registration ---
	demo.Step("Register a symmetric client (client_secret_post)").
		Ref(refs.RFC7591).
		Arrow("App", "AS", "POST /apps/dcr {client_name, grant_types, auth_method}").
		DashedArrow("AS", "App", "{client_id, client_secret, client_id_issued_at}").
		Note("The simplest DCR: the AS generates both a client_id and client_secret. The client uses client_secret_post to authenticate at the token endpoint.").
		Run(func() {
			dcrReq := map[string]any{
				"client_name":                "My Example Bot",
				"client_uri":                 "https://bot.example.com",
				"grant_types":                []string{"client_credentials"},
				"token_endpoint_auth_method": "client_secret_post",
				"scope":                      "read write",
			}
			body, _ := json.Marshal(dcrReq)

			resp, _ := http.Post(authServer.URL+"/apps/dcr", "application/json",
				bytes.NewReader(body))
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			fmt.Printf("    HTTP status: %d\n\n", resp.StatusCode)

			var dcrResp map[string]any
			json.Unmarshal(respBody, &dcrResp)
			pretty, _ := json.MarshalIndent(dcrResp, "    ", "  ")
			fmt.Printf("    %s\n", string(pretty))

			symClientID = dcrResp["client_id"].(string)
			symClientSecret = dcrResp["client_secret"].(string)
		})

	// --- Use the registered client ---
	demo.Step("Get a token with the DCR-registered client").
		Ref(refs.RFC6749_ClientCredentials).
		Arrow("App", "AS", "POST /api/token {client_id, client_secret from DCR}").
		DashedArrow("AS", "App", "{access_token}").
		Note("The dynamically registered client works exactly like a manually registered one — the AS doesn't distinguish between registration methods.").
		Run(func() {
			tokenResp, _ := http.PostForm(authServer.URL+"/api/token", url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {symClientID},
				"client_secret": {symClientSecret},
				"scope":         {"read"},
			})
			var tokenData map[string]any
			json.NewDecoder(tokenResp.Body).Decode(&tokenData)
			tokenResp.Body.Close()

			fmt.Printf("    token_type:    %s\n", tokenData["token_type"])
			fmt.Printf("    scope:         %s\n", tokenData["scope"])
			fmt.Printf("    access_token:  %s...\n", tokenData["access_token"].(string)[:40])
		})

	// --- Asymmetric registration ---
	demo.Step("Register an asymmetric client (private_key_jwt with JWKS)").
		Ref(refs.RFC7591).
		Ref(refs.RFC7517).
		Arrow("App", "AS", "POST /apps/dcr {auth_method: private_key_jwt, jwks: {keys: [...]}}").
		DashedArrow("AS", "App", "{client_id} (no client_secret — asymmetric!)").
		Note("For asymmetric auth, the client sends its public key as a JWK set. No secret is returned — the client authenticates with signed JWTs using its private key.").
		Run(func() {
			_, pubPEM, _ := utils.GenerateRSAKeyPair(2048)
			pubKey, _ := utils.ParsePublicKeyPEM(pubPEM)
			kid, _ := utils.ComputeKid(pubKey, "RS256")
			jwk, _ := utils.PublicKeyToJWK(kid, "RS256", pubKey)

			dcrReq := map[string]any{
				"client_name":                "My Secure Service",
				"grant_types":                []string{"client_credentials"},
				"token_endpoint_auth_method": "private_key_jwt",
				"jwks":                       map[string]any{"keys": []any{jwk}},
			}
			body, _ := json.Marshal(dcrReq)

			resp, _ := http.Post(authServer.URL+"/apps/dcr", "application/json",
				bytes.NewReader(body))
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			fmt.Printf("    HTTP status: %d\n\n", resp.StatusCode)

			var dcrResp map[string]any
			json.Unmarshal(respBody, &dcrResp)
			pretty, _ := json.MarshalIndent(dcrResp, "    ", "  ")
			fmt.Printf("    %s\n", string(pretty))

			asymClientID = dcrResp["client_id"].(string)
			hasSecret := dcrResp["client_secret"] != nil && dcrResp["client_secret"] != ""
			fmt.Printf("\n    client_id:     %s\n", asymClientID)
			fmt.Printf("    client_secret: %v (asymmetric — no secret needed)\n", hasSecret)
		})

	demo.Section("Symmetric vs asymmetric DCR",
		"| | client_secret_post / basic | private_key_jwt |",
		"|---|---|---|",
		"| **DCR sends** | Just metadata | Metadata + JWKS (public key) |",
		"| **AS returns** | client_id + client_secret | client_id only (no secret) |",
		"| **Token auth** | Send secret in request | Sign a JWT with private key |",
		"| **Key in JWKS** | Not in JWKS (secret) | Public key served in JWKS |",
		"| **Best for** | Simple integrations | High-security, multi-service |",
	)

	// --- Optional: Keycloak DCR ---
	demo.Step("Register via Keycloak DCR (optional)").
		Ref(refs.RFC7591).
		Arrow("App", "AS", "POST {KC registration_endpoint} {client_name, grant_types}").
		DashedArrow("AS", "App", "{client_id, client_secret, registration_access_token}").
		Note("Same DCR request format against Keycloak. KC returns additional fields like registration_access_token for client management. If KC isn't running, this step is skipped.").
		Run(func() {
			kcRealmURL := kcExamplesURL + "/realms/" + kcExamplesRealm
			httpClient := &http.Client{Timeout: 2 * time.Second}
			resp, err := httpClient.Get(kcRealmURL)
			if err != nil {
				fmt.Printf("    SKIPPED: Keycloak not running at %s\n", kcExamplesURL)
				fmt.Printf("    To enable: cd examples && make upkcl\n")
				return
			}
			resp.Body.Close()

			// Discover KC registration endpoint
			kcMeta, err := client.DiscoverAS(kcRealmURL)
			if err != nil {
				fmt.Printf("    ERROR discovering Keycloak: %v\n", err)
				return
			}

			if kcMeta.RegistrationEndpoint == "" {
				fmt.Printf("    SKIPPED: Keycloak does not advertise a registration_endpoint\n")
				fmt.Printf("    (KC may need 'registrationAllowed' enabled on the realm)\n")
				return
			}

			fmt.Printf("    KC registration endpoint: %s\n\n", kcMeta.RegistrationEndpoint)

			dcrReq := map[string]any{
				"client_name": "Example Bot (from OneAuth demo)",
				"grant_types": []string{"client_credentials"},
			}
			body, _ := json.Marshal(dcrReq)

			dcrResp, _ := http.Post(kcMeta.RegistrationEndpoint, "application/json",
				bytes.NewReader(body))
			dcrBody, _ := io.ReadAll(dcrResp.Body)
			dcrResp.Body.Close()

			fmt.Printf("    HTTP status: %d\n", dcrResp.StatusCode)
			var kcDCR map[string]any
			json.Unmarshal(dcrBody, &kcDCR)
			pretty, _ := json.MarshalIndent(kcDCR, "    ", "  ")
			fmt.Printf("    %s\n", string(pretty))
		})

	demo.Section("What's next?",
		"In [07 — Client SDK](../07-client-sdk/), you'll see production patterns:",
		"automatic token caching, background refresh, scope step-up, and discovery-driven",
		"configuration — all wrapped in a simple `TokenSource` interface.",
	)

	demo.Execute()

	if authServer != nil {
		authServer.Close()
	}
}
