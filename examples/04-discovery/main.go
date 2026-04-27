// Example 04: AS Metadata Discovery (RFC 8414)
//
// In Examples 01-03, we hardcoded URLs like authServer.URL+"/api/token".
// In production, clients discover endpoints automatically from a single
// well-known URL. This is how Keycloak, Auth0, and OneAuth all work.
//
// Run:   go run ./examples/04-discovery/
// Docs:  Run with --readme to regenerate README.md
//
// See: https://www.rfc-editor.org/rfc/rfc8414
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/demokit"
	"github.com/panyam/oneauth/examples/refs"
	"github.com/panyam/oneauth/keys"
)

const kcExamplesURL = "http://localhost:8280"
const kcExamplesRealm = "oneauth-examples"

func main() {
	var authServer, resourceServer *httptest.Server
	var ks keys.KeyStorage
	var discoveredMeta *client.ASMetadata
	var clientID, clientSecret, accessToken string

	demo := demokit.New("04: AS Metadata Discovery").
		Dir("04-discovery").
		Description("Non-UI | No infrastructure needed | Builds on Examples 01-03").
		Actors(
			demokit.Actor("App", "Client App"),
			demokit.Actor("AS", "Auth Server"),
			demokit.Actor("RS", "Resource Server"),
		)

	demo.Section("About this example",
		"**Actors:** App (a bot), Auth Server (AS), Resource Server (RS).",
		"Think: the GitHub bot doesn't know Slack's token URL — it discovers it.",
		"[What are these?](../README.md#cast-of-characters)",
		"",
		"In Examples 01-03, we hardcoded the auth server's URLs:",
		"```go",
		"http.PostForm(authServer.URL + \"/api/token\", ...)  // hardcoded path",
		"```",
		"",
		"In production, you don't know the paths ahead of time. Different auth servers",
		"use different URL structures (Keycloak: `/realms/{name}/protocol/openid-connect/token`,",
		"Auth0: `/oauth/token`, OneAuth: `/api/token`).",
		"",
		"RFC 8414 solves this: every auth server publishes a JSON document at",
		"`/.well-known/openid-configuration` listing all its endpoints.",
		"Clients fetch this once and use the discovered URLs for everything.",
	)

	// --- Setup ---
	demo.Step("Start auth server with discovery, token, JWKS, and introspection endpoints").
		Ref(refs.RFC8414).
		Note("This is the most complete auth server we've built so far — it serves discovery, tokens, JWKS, introspection, and registration.").
		Run(func() {
			ks = keys.NewInMemoryKeyStore()
			registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
			jwksHandler := &keys.JWKSHandler{KeyStore: ks}

			apiAuth := &apiauth.APIAuth{
				JWTSecretKey:   "discovery-example-secret-32chars!",
				ClientKeyStore: ks,
			}

			introspection := &apiauth.IntrospectionHandler{
				Auth:           apiAuth,
				ClientKeyStore: ks,
			}

			mux := http.NewServeMux()
			mux.Handle("/apps/", registrar.Handler())
			mux.HandleFunc("POST /api/token", apiAuth.ServeHTTP)
			mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler.ServeHTTP)
			mux.Handle("POST /oauth/introspect", introspection)
			authServer = httptest.NewServer(mux)

			// Set issuer to actual URL (must match tokens)
			apiAuth.JWTIssuer = authServer.URL

			// Register discovery endpoint with all the server's capabilities
			mux.Handle("GET /.well-known/openid-configuration",
				apiauth.NewASMetadataHandler(&apiauth.ASServerMetadata{
					Issuer:                        authServer.URL,
					TokenEndpoint:                 authServer.URL + "/api/token",
					JWKSURI:                       authServer.URL + "/.well-known/jwks.json",
					IntrospectionEndpoint:         authServer.URL + "/oauth/introspect",
					RegistrationEndpoint:          authServer.URL + "/apps/register",
					ScopesSupported:               []string{"read", "write", "admin"},
					GrantTypesSupported:           []string{"client_credentials"},
					ResponseTypesSupported:        []string{"token"},
					TokenEndpointAuthMethods:      []string{"client_secret_post", "client_secret_basic"},
					CodeChallengeMethodsSupported: []string{"S256"},
				}))

			// Resource server
			middleware := &apiauth.APIMiddleware{
				JWTSecretKey: "discovery-example-secret-32chars!",
				JWTIssuer:    authServer.URL,
			}
			resMux := http.NewServeMux()
			resMux.Handle("GET /resource", middleware.ValidateToken(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]any{
						"user":   apiauth.GetUserIDFromAPIContext(r.Context()),
						"scopes": apiauth.GetScopesFromAPIContext(r.Context()),
					})
				}),
			))
			resourceServer = httptest.NewServer(resMux)

			fmt.Printf("    Auth server:     %s\n", authServer.URL)
			fmt.Printf("    Resource server: %s\n", resourceServer.URL)
		})

	// --- Fetch raw metadata ---
	demo.Step("Fetch the discovery document (raw HTTP)").
		Ref(refs.RFC8414).
		Arrow("App", "AS", "GET /.well-known/openid-configuration").
		DashedArrow("AS", "App", "JSON {issuer, token_endpoint, jwks_uri, ...}").
		Note("The discovery document is a JSON object listing every endpoint the server supports. This is the same format Keycloak, Auth0, and Google use.").
		Run(func() {
			resp, _ := http.Get(authServer.URL + "/.well-known/openid-configuration")
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			var meta map[string]any
			json.Unmarshal(body, &meta)
			pretty, _ := json.MarshalIndent(meta, "    ", "  ")
			fmt.Printf("    %s\n", string(pretty))
		})

	demo.Section("What's in the metadata?",
		"| Field | What it tells the client |",
		"|-------|------------------------|",
		"| `issuer` | The AS's canonical URL — must match the `iss` claim in tokens |",
		"| `token_endpoint` | Where to POST for tokens (client_credentials, auth code) |",
		"| `jwks_uri` | Where to GET public keys for token verification |",
		"| `introspection_endpoint` | Where to POST for token introspection (RFC 7662) |",
		"| `registration_endpoint` | Where to POST for dynamic client registration (RFC 7591) |",
		"| `scopes_supported` | What scopes the AS recognizes |",
		"| `grant_types_supported` | What OAuth grant types are available |",
		"| `token_endpoint_auth_methods_supported` | How clients can authenticate (basic, post) |",
		"| `code_challenge_methods_supported` | PKCE methods (S256) |",
		"",
		"A client only needs to know the server's base URL. Everything else is discovered.",
	)

	// --- Use client.DiscoverAS ---
	demo.Step("Discover using the client SDK (client.DiscoverAS)").
		Ref(refs.RFC8414).
		Arrow("App", "AS", "client.DiscoverAS(serverURL)").
		DashedArrow("AS", "App", "typed ASMetadata struct").
		Note("client.DiscoverAS() fetches and parses the metadata into a typed Go struct. Production code should use this — no manual JSON parsing needed.").
		Run(func() {
			var err error
			discoveredMeta, err = client.DiscoverAS(authServer.URL)
			if err != nil {
				fmt.Printf("    ERROR: %v\n", err)
				return
			}

			fmt.Printf("    issuer:                  %s\n", discoveredMeta.Issuer)
			fmt.Printf("    token_endpoint:          %s\n", discoveredMeta.TokenEndpoint)
			fmt.Printf("    jwks_uri:                %s\n", discoveredMeta.JWKSURI)
			fmt.Printf("    introspection_endpoint:  %s\n", discoveredMeta.IntrospectionEndpoint)
			fmt.Printf("    scopes_supported:        %v\n", discoveredMeta.ScopesSupported)
			fmt.Printf("    grant_types_supported:   %v\n", discoveredMeta.GrantTypesSupported)
			fmt.Printf("    auth_methods:            %v\n", discoveredMeta.TokenEndpointAuthMethods)
		})

	// --- Register using discovered endpoint ---
	demo.Step("Register a client (using discovered URL)").
		Arrow("App", "AS", "POST {discovered_registration_endpoint}").
		DashedArrow("AS", "App", "{client_id, client_secret}").
		Note("Instead of hardcoding /apps/register, we use the registration_endpoint from discovery. The same code works against OneAuth, Keycloak, or any RFC 8414-compliant server.").
		Run(func() {
			body, _ := json.Marshal(map[string]any{
				"client_domain": "discovery-demo.example.com",
				"signing_alg":   "HS256",
			})
			resp, _ := http.Post(authServer.URL+"/apps/register",
				"application/json", strings.NewReader(string(body)))
			var reg map[string]any
			json.NewDecoder(resp.Body).Decode(&reg)
			resp.Body.Close()

			clientID = reg["client_id"].(string)
			clientSecret = reg["client_secret"].(string)
			fmt.Printf("    client_id:     %s\n", clientID)
			fmt.Printf("    client_secret: %s...\n", clientSecret[:16])
		})

	// --- Get token using discovered endpoint ---
	demo.Step("Get a token (using discovered token endpoint)").
		Ref(refs.RFC6749_ClientCredentials).
		Arrow("App", "AS", "POST {discovered_token_endpoint}").
		DashedArrow("AS", "App", "{access_token, token_type, expires_in}").
		Note("We use discoveredMeta.TokenEndpoint instead of hardcoding /api/token. This is the key benefit — the same client code works against any compliant AS.").
		Run(func() {
			resp, _ := http.PostForm(discoveredMeta.TokenEndpoint, url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {clientID},
				"client_secret": {clientSecret},
				"scope":         {"read write"},
			})
			var tokenData map[string]any
			json.NewDecoder(resp.Body).Decode(&tokenData)
			resp.Body.Close()

			accessToken = tokenData["access_token"].(string)
			fmt.Printf("    token_endpoint used: %s\n", discoveredMeta.TokenEndpoint)
			fmt.Printf("    token_type:          %s\n", tokenData["token_type"])
			fmt.Printf("    scope:               %s\n", tokenData["scope"])
			fmt.Printf("    access_token:        %s...\n", accessToken[:40])
		})

	// --- Use the token ---
	demo.Step("Use the token on a resource server").
		Ref(refs.RFC6750).
		Arrow("App", "RS", "GET /resource (Bearer token)").
		DashedArrow("RS", "App", "200 {data}").
		Note("The resource server validates the token as in previous examples. Discovery doesn't change how tokens work — it only changes how the client finds the endpoints.").
		Run(func() {
			req, _ := http.NewRequest("GET", resourceServer.URL+"/resource", nil)
			req.Header.Set("Authorization", "Bearer "+accessToken)
			res, _ := http.DefaultClient.Do(req)
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()

			fmt.Printf("    status: %d\n", res.StatusCode)
			var data map[string]any
			json.Unmarshal(body, &data)
			pretty, _ := json.MarshalIndent(data, "    ", "  ")
			fmt.Printf("    response: %s\n", string(pretty))
		})

	// --- Optional: Keycloak comparison ---
	demo.Step("Discover Keycloak endpoints (optional)").
		Ref(refs.RFC8414).
		Arrow("App", "AS", "client.DiscoverAS(keycloakRealmURL)").
		DashedArrow("AS", "App", "{issuer, token_endpoint, jwks_uri, ...}").
		Note("Same DiscoverAS() call, completely different server. If Keycloak isn't running, this step is skipped — run 'make upkcl' in examples/ to start it.").
		Run(func() {
			// Check if KC is reachable
			kcRealmURL := kcExamplesURL + "/realms/" + kcExamplesRealm
			httpClient := &http.Client{Timeout: 2 * time.Second}
			resp, err := httpClient.Get(kcRealmURL)
			if err != nil {
				fmt.Printf("    SKIPPED: Keycloak not running at %s\n", kcExamplesURL)
				fmt.Printf("    To enable: cd examples && make upkcl\n")
				return
			}
			resp.Body.Close()

			kcMeta, err := client.DiscoverAS(kcRealmURL)
			if err != nil {
				fmt.Printf("    ERROR discovering Keycloak: %v\n", err)
				return
			}

			fmt.Printf("    Keycloak discovered at %s:\n", kcRealmURL)
			fmt.Printf("      issuer:           %s\n", kcMeta.Issuer)
			fmt.Printf("      token_endpoint:   %s\n", kcMeta.TokenEndpoint)
			fmt.Printf("      jwks_uri:         %s\n", kcMeta.JWKSURI)
			fmt.Printf("      introspection:    %s\n", kcMeta.IntrospectionEndpoint)

			fmt.Printf("\n    Side by side — same code, different servers:\n")
			fmt.Printf("      %-25s %-45s %s\n", "Field", "OneAuth", "Keycloak")
			fmt.Printf("      %-25s %-45s %s\n", "-----", "-------", "--------")
			fmt.Printf("      %-25s %-45s %s\n", "token_endpoint",
				discoveredMeta.TokenEndpoint, kcMeta.TokenEndpoint)
			fmt.Printf("      %-25s %-45s %s\n", "jwks_uri",
				discoveredMeta.JWKSURI, kcMeta.JWKSURI)
			fmt.Printf("      %-25s %-45s %s\n", "introspection_endpoint",
				discoveredMeta.IntrospectionEndpoint, kcMeta.IntrospectionEndpoint)
		})

	demo.Section("Why discovery matters",
		"Without discovery, switching auth providers means updating every URL in your code.",
		"With discovery, you change one base URL and everything else adapts:",
		"",
		"```go",
		"// Works against OneAuth, Keycloak, Auth0 — same code",
		"meta, _ := client.DiscoverAS(\"https://auth.example.com\")",
		"http.PostForm(meta.TokenEndpoint, ...)       // discovered",
		"jwksKS := keys.NewJWKSKeyStore(meta.JWKSURI) // discovered",
		"```",
		"",
		"This is especially important for the [Keycloak interop tests](../../tests/keycloak/)",
		"where the same test code validates against both Keycloak and OneAuth.",
	)

	demo.Section("What's next?",
		"In [05 — Introspection](../05-introspection/), you'll see how resource",
		"servers can validate tokens remotely by asking the auth server \"is this",
		"token valid?\" — an alternative to local JWT verification that works even",
		"for opaque tokens.",
	)

	demo.Execute()

	if authServer != nil {
		authServer.Close()
	}
	if resourceServer != nil {
		resourceServer.Close()
	}
}
