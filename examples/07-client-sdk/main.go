// Example 07: Client SDK — Production Patterns
//
// Examples 01-06 showed the server side and raw HTTP calls. This example shows
// how production client code works: discovery-driven configuration, automatic
// token caching/refresh, and scope step-up — all via OneAuth's client SDK.
//
// Run:   go run ./examples/07-client-sdk/
// Docs:  Run with --readme to regenerate README.md
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
const kcExampleClientID = "example-app"
const kcExampleClientSecret = "example-app-secret"

func main() {
	var authServer, resourceServer *httptest.Server
	var registeredClientID, registeredSecret string
	var tokenSource *client.ClientCredentialsSource

	demo := demokit.New("07: Client SDK — Production Patterns").
		Dir("07-client-sdk").
		Description("Non-UI | No infrastructure needed | Builds on Examples 01-06").
		Actors(
			demokit.Actor("App", "Client App (SDK)"),
			demokit.Actor("AS", "Auth Server"),
			demokit.Actor("RS", "Resource Server"),
		)

	demo.Section("About this example",
		"**Actors:** App (using the client SDK), Auth Server (AS), Resource Server (RS).",
		"Think: the GitHub bot in production — not making raw HTTP calls, but using a library.",
		"[What are these?](../README.md#cast-of-characters)",
		"",
		"In Examples 01-06, we made raw `http.Post` calls to the token endpoint.",
		"That works for learning, but production code needs:",
		"- **Discovery** — don't hardcode URLs (Example 04)",
		"- **Token caching** — don't fetch a new token on every request",
		"- **Auto-refresh** — renew tokens before they expire",
		"- **Scope step-up** — request additional scopes when needed",
		"",
		"OneAuth's client SDK wraps all of this in a `TokenSource` interface:",
		"```go",
		"token, err := tokenSource.Token()  // cached, auto-refreshed",
		"```",
	)

	// --- Setup ---
	demo.Step("Start auth server and resource server").
		Note("Same auth server as previous examples. We also pre-register a client since the SDK focuses on token acquisition, not registration.").
		Run(func() {
			ks := keys.NewInMemoryKeyStore()
			registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())

			apiAuth := &apiauth.APIAuth{
				JWTSecretKey:   "sdk-example-secret-at-least-32ch!",
				ClientKeyStore: ks,
			}

			mux := http.NewServeMux()
			mux.Handle("/apps/", registrar.Handler())
			mux.HandleFunc("POST /api/token", apiAuth.ServeHTTP)
			authServer = httptest.NewServer(mux)
			apiAuth.JWTIssuer = authServer.URL

			mux.Handle("GET /.well-known/openid-configuration",
				apiauth.NewASMetadataHandler(&apiauth.ASServerMetadata{
					Issuer:                   authServer.URL,
					TokenEndpoint:            authServer.URL + "/api/token",
					GrantTypesSupported:      []string{"client_credentials"},
					TokenEndpointAuthMethods: []string{"client_secret_post", "client_secret_basic"},
				}))

			// Resource server
			middleware := &apiauth.APIMiddleware{
				JWTSecretKey: "sdk-example-secret-at-least-32ch!",
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

			// Pre-register a client
			resp := postJSON(authServer.URL+"/apps/register", map[string]any{
				"client_domain": "sdk-demo.example.com",
				"signing_alg":   "HS256",
			})
			registeredClientID = resp["client_id"].(string)
			registeredSecret = resp["client_secret"].(string)

			fmt.Printf("    Auth server:     %s\n", authServer.URL)
			fmt.Printf("    Resource server: %s\n", resourceServer.URL)
			fmt.Printf("    Client ID:       %s\n", registeredClientID)
		})

	// --- One-shot token ---
	demo.Step("One-shot token with AuthClient").
		Ref(refs.RFC6749_ClientCredentials).
		Ref(refs.RFC8414).
		Arrow("App", "AS", "client.DiscoverAS(serverURL)").
		Arrow("App", "AS", "authClient.ClientCredentialsToken(id, secret, scopes)").
		DashedArrow("AS", "App", "ServerCredential{AccessToken, ExpiresAt, Scope}").
		Note("AuthClient is the low-level SDK: discover endpoints, then make a single token request. Good for one-off calls. Uses discovery to find the token endpoint automatically.").
		Run(func() {
			// Discover + create client
			meta, _ := client.DiscoverAS(authServer.URL)
			authClient := client.NewAuthClient(authServer.URL, nil,
				client.WithASMetadata(meta))

			cred, err := authClient.ClientCredentialsToken(
				registeredClientID, registeredSecret, []string{"read"})
			if err != nil {
				fmt.Printf("    ERROR: %v\n", err)
				return
			}

			fmt.Printf("    access_token: %s...\n", cred.AccessToken[:40])
			fmt.Printf("    scope:        %s\n", cred.Scope)
			fmt.Printf("    expires_at:   %s\n", cred.ExpiresAt.Format(time.RFC3339))
		})

	demo.Section("AuthClient vs ClientCredentialsSource",
		"| | AuthClient | ClientCredentialsSource |",
		"|---|---|---|",
		"| **Use case** | One-shot token requests | Long-running services |",
		"| **Caching** | None — new request every time | Automatic — reuses valid tokens |",
		"| **Refresh** | Manual | Automatic (on next Token() call) |",
		"| **Interface** | `ClientCredentialsToken()` | `Token() string` (TokenSource) |",
		"| **Scope step-up** | Manual | `TokenForScopes()` |",
	)

	// --- TokenSource with caching ---
	demo.Step("Cached token with ClientCredentialsSource").
		Ref(refs.RFC6749_ClientCredentials).
		Arrow("App", "App", "tokenSource.Token() → cached or fetched").
		Arrow("App", "RS", "GET /resource (Bearer: cached token)").
		DashedArrow("RS", "App", "200 {data}").
		Note("ClientCredentialsSource implements TokenSource: Token() returns a cached token if still valid, or fetches a new one. Multiple goroutines can safely call Token() concurrently.").
		Run(func() {
			tokenSource = &client.ClientCredentialsSource{
				TokenEndpoint: authServer.URL + "/api/token",
				ClientID:      registeredClientID,
				ClientSecret:  registeredSecret,
				Scopes:        []string{"read"},
			}

			// First call: fetches a new token
			token1, err := tokenSource.Token()
			if err != nil {
				fmt.Printf("    ERROR: %v\n", err)
				return
			}
			fmt.Printf("    First call:  %s... (fetched)\n", token1[:40])

			// Second call: returns cached token (no HTTP call)
			token2, _ := tokenSource.Token()
			fmt.Printf("    Second call: %s... (cached)\n", token2[:40])
			fmt.Printf("    Same token:  %v\n", token1 == token2)

			// Use the token on a resource server
			req, _ := http.NewRequest("GET", resourceServer.URL+"/resource", nil)
			req.Header.Set("Authorization", "Bearer "+token1)
			res, _ := http.DefaultClient.Do(req)
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()

			fmt.Printf("    Resource:    %d %s\n", res.StatusCode, string(body))
		})

	// --- Scope step-up ---
	demo.Step("Scope step-up with TokenForScopes").
		Arrow("App", "App", "tokenSource.TokenForScopes([\"write\"])").
		Arrow("App", "AS", "POST /api/token {scope: read write} (merged)").
		DashedArrow("AS", "App", "new token with expanded scopes").
		Note("When your app needs additional permissions, TokenForScopes merges the new scopes with existing ones, invalidates the cache, and fetches a fresh token.").
		Run(func() {
			// Original token has "read" only
			oldToken, _ := tokenSource.Token()
			fmt.Printf("    Before step-up: %s...\n", oldToken[:40])

			// Step up to include "write"
			newToken, err := tokenSource.TokenForScopes([]string{"write"})
			if err != nil {
				fmt.Printf("    ERROR: %v\n", err)
				return
			}
			fmt.Printf("    After step-up:  %s...\n", newToken[:40])
			fmt.Printf("    Different token: %v (cache was invalidated)\n", oldToken != newToken)
		})

	demo.Section("TokenSource in practice",
		"The `TokenSource` interface (`Token() (string, error)`) is designed to",
		"plug into HTTP clients, gRPC interceptors, or any code that needs a token:",
		"",
		"```go",
		"// Create once, reuse everywhere",
		"ts := &client.ClientCredentialsSource{",
		"    TokenEndpoint: meta.TokenEndpoint,",
		"    ClientID:      \"my-app\",",
		"    ClientSecret:  \"my-secret\",",
		"    Scopes:        []string{\"read\"},",
		"}",
		"",
		"// In your HTTP client middleware",
		"token, _ := ts.Token()  // fast: returns cached token",
		"req.Header.Set(\"Authorization\", \"Bearer \" + token)",
		"```",
		"",
		"The interface matches `mcpkit/core.TokenSource` by structural typing —",
		"no cross-module import needed.",
	)

	// --- Optional: Keycloak ---
	demo.Step("Use the SDK against Keycloak (optional)").
		Ref(refs.RFC8414).
		Ref(refs.RFC6749_ClientCredentials).
		Arrow("App", "AS", "client.DiscoverAS(keycloakRealmURL)").
		Arrow("App", "AS", "authClient.ClientCredentialsToken(...)").
		DashedArrow("AS", "App", "ServerCredential from Keycloak").
		Note("Same SDK code, pointed at Keycloak. DiscoverAS finds the KC token endpoint automatically. If KC isn't running, this step is skipped.").
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

			// Discover KC
			kcMeta, err := client.DiscoverAS(kcRealmURL)
			if err != nil {
				fmt.Printf("    ERROR discovering KC: %v\n", err)
				return
			}

			// Use AuthClient against KC
			kcClient := client.NewAuthClient(kcRealmURL, nil,
				client.WithASMetadata(kcMeta))
			cred, err := kcClient.ClientCredentialsToken(
				kcExampleClientID, kcExampleClientSecret, []string{"openid"})
			if err != nil {
				fmt.Printf("    ERROR getting KC token: %v\n", err)
				return
			}

			fmt.Printf("    KC access_token: %s...\n", cred.AccessToken[:40])
			fmt.Printf("    KC scope:        %s\n", cred.Scope)
			fmt.Printf("    KC expires_at:   %s\n", cred.ExpiresAt.Format(time.RFC3339))
			fmt.Printf("\n    Same SDK code — different server. That's the point.\n")
		})

	demo.Section("What's next?",
		"In [08 — Rich Authorization Requests](../08-rich-authorization-requests/),",
		"you'll see how to go beyond flat scopes: request fine-grained permissions",
		"like \"transfer 45 EUR to Merchant A\" using RFC 9396.",
	)

	demo.Execute()

	if tokenSource != nil {
		tokenSource.Close()
	}
	if authServer != nil {
		authServer.Close()
	}
	if resourceServer != nil {
		resourceServer.Close()
	}
}

// postJSON is a helper that POSTs JSON and returns the decoded response.
func postJSON(url string, body any) map[string]any {
	data, _ := json.Marshal(body)
	resp, _ := http.Post(url, "application/json", bytes.NewReader(data))
	defer resp.Body.Close()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}
