// Example 01: OAuth 2.0 Client Credentials Flow
//
// The simplest way to get a token from OneAuth. A client authenticates with
// its client_id and client_secret, and receives a JWT access token.
//
// Run:   go run ./examples/01-client-credentials/
// Docs:  Run with --readme to regenerate README.md
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/examples/demokit"
	"github.com/panyam/oneauth/keys"
)

func main() {
	// Shared state across steps
	var authServer, resourceServer *httptest.Server
	var ks keys.KeyStorage
	var clientID, clientSecret, accessToken string

	demo := demokit.New("01: Client Credentials Flow").
		Dir("01-client-credentials").
		Description("Non-UI | No infrastructure needed | RFC 6749 §4.4").
		Actors(
			demokit.Actor("App", "Client App"),
			demokit.Actor("AS", "Auth Server"),
			demokit.Actor("RS", "Resource Server"),
		)

	demo.Section("About this example",
		"**Actors:** App (a bot), Auth Server (AS), Resource Server (RS).",
		"Think: a GitHub bot posting to Slack's API. [What are these?](../README.md#cast-of-characters)",
		"",
		"The `client_credentials` grant is the standard OAuth 2.0 machine-to-machine",
		"flow. No user is involved — the bot authenticates directly with its own",
		"credentials and receives an access token.",
		"",
		"Common use cases: service-to-service calls, background jobs, CLI tools.",
	)

	// --- Setup ---
	demo.Step("Start auth server and resource server").
		Note("We spin up two in-process HTTP servers: one for the AS (issues tokens) and one for the RS (validates them). Both share the same KeyStore.").
		Run(func() {
			ks = keys.NewInMemoryKeyStore()
			registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())

			apiAuth := &apiauth.APIAuth{
				JWTSecretKey:   "example-jwt-secret-at-least-32ch",
				JWTIssuer:      "example-issuer",
				ClientKeyStore: ks,
			}

			authMux := http.NewServeMux()
			authMux.Handle("/apps/", registrar.Handler())
			authMux.HandleFunc("POST /api/token", apiAuth.ServeHTTP)
			authServer = httptest.NewServer(authMux)

			middleware := &apiauth.APIMiddleware{
				JWTSecretKey: "example-jwt-secret-at-least-32ch",
				JWTIssuer:    "example-issuer",
			}
			resMux := http.NewServeMux()
			resMux.Handle("GET /resource", middleware.ValidateToken(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]any{
						"message": "hello from protected resource",
						"sub":     apiauth.GetUserIDFromAPIContext(r.Context()),
						"scopes":  apiauth.GetScopesFromAPIContext(r.Context()),
					})
				}),
			))
			resourceServer = httptest.NewServer(resMux)

			fmt.Printf("    Auth server:     %s\n", authServer.URL)
			fmt.Printf("    Resource server: %s\n", resourceServer.URL)
		})

	demo.Section("How client registration works",
		"Before a client can get tokens, it needs to register with the auth server",
		"and receive a `client_id` + `client_secret` pair. This is the equivalent",
		"of going to GitHub Developer Settings → OAuth Apps → \"New OAuth App\".",
		"",
		"In this example, registration is **open** (`NewNoAuth()`) for simplicity.",
		"In production, gate registration with authentication — see",
		"[How does an App get registered?](../README.md#how-does-an-app-get-registered)",
		"for the full spectrum from web dashboards to automated DCR.",
		"",
		"**The `client_secret` is a backend credential.** It lives in your server,",
		"not in a browser or mobile app. Never expose it in frontend code.",
	)

	// --- Step 1: Register ---
	demo.Step("Register a client").
		Ref(demokit.RFC7591).
		Arrow("App", "AS", "POST /apps/register {domain, signing_alg}").
		DashedArrow("AS", "App", "{client_id, client_secret}").
		Note("The client receives credentials it will use to authenticate in the next step.").
		Run(func() {
			body, _ := json.Marshal(map[string]any{
				"client_domain": "my-service.example.com",
				"signing_alg":   "HS256",
			})
			resp, _ := http.Post(authServer.URL+"/apps/register", "application/json",
				strings.NewReader(string(body)))
			var reg map[string]any
			json.NewDecoder(resp.Body).Decode(&reg)
			resp.Body.Close()

			clientID = reg["client_id"].(string)
			clientSecret = reg["client_secret"].(string)
			fmt.Printf("    client_id:     %s\n", clientID)
			fmt.Printf("    client_secret: %s...\n", clientSecret[:16])
		})

	// --- Step 2: Token ---
	demo.Step("Request an access token").
		Ref(demokit.RFC6749_ClientCredentials).
		Ref(demokit.RFC7519).
		Arrow("App", "AS", "POST /api/token {grant_type: client_credentials}").
		DashedArrow("AS", "App", "{access_token, token_type, expires_in}").
		Note("The AS verifies the client credentials and returns a signed JWT. The token carries sub=client_id (no user context in this flow).").
		Run(func() {
			resp, _ := http.PostForm(authServer.URL+"/api/token", url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {clientID},
				"client_secret": {clientSecret},
				"scope":         {"read write"},
			})
			var tokenData map[string]any
			json.NewDecoder(resp.Body).Decode(&tokenData)
			resp.Body.Close()

			accessToken = tokenData["access_token"].(string)
			fmt.Printf("    token_type:   %s\n", tokenData["token_type"])
			fmt.Printf("    scope:        %s\n", tokenData["scope"])
			fmt.Printf("    expires_in:   %.0fs\n", tokenData["expires_in"])
			fmt.Printf("    access_token: %s...\n", accessToken[:40])
		})

	demo.Section("What's in the JWT?",
		"The access token is a signed JWT containing:",
		"- `sub`: the client_id (who this token represents)",
		"- `scopes`: the granted scopes",
		"- `iss`: the issuer URL",
		"- `exp`/`iat`: expiry and issued-at timestamps",
		"- `jti`: unique token ID (for revocation)",
		"",
		"The resource server can validate this token locally by checking the",
		"signature — no callback to the auth server needed.",
	)

	// --- Step 3: Use token ---
	demo.Step("Access a protected resource").
		Ref(demokit.RFC6750).
		Ref(demokit.RFC7515).
		Arrow("App", "RS", "GET /resource (Authorization: Bearer token)").
		Arrow("RS", "RS", "Validate JWT signature + claims").
		DashedArrow("RS", "App", "200 {data}").
		Note("The resource server validates the JWT signature and extracts claims from it. No network call to the auth server.").
		Run(func() {
			req, _ := http.NewRequest("GET", resourceServer.URL+"/resource", nil)
			req.Header.Set("Authorization", "Bearer "+accessToken)
			res, _ := http.DefaultClient.Do(req)
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()

			fmt.Printf("    status: %d\n", res.StatusCode)
			var resource map[string]any
			json.Unmarshal(body, &resource)
			pretty, _ := json.MarshalIndent(resource, "    ", "  ")
			fmt.Printf("    response: %s\n", string(pretty))
		})

	// --- Step 4: No token ---
	demo.Step("Access without a token (expect rejection)").
		Ref(demokit.RFC6750).
		Arrow("App", "RS", "GET /resource (no Authorization header)").
		DashedArrow("RS", "App", "401 Unauthorized").
		Note("Without a valid Bearer token, the resource server rejects the request.").
		Run(func() {
			req, _ := http.NewRequest("GET", resourceServer.URL+"/resource", nil)
			res, _ := http.DefaultClient.Do(req)
			res.Body.Close()
			fmt.Printf("    status: %d (correctly rejected)\n", res.StatusCode)
		})

	demo.Section("What's next?",
		"In [02 — Resource Token (HS256)](../02-resource-token-hs256/), you'll see",
		"how a registered app can mint tokens *for individual users*, not just for",
		"itself. This is the federated authentication pattern used by OneAuth's",
		"multi-app architecture.",
	)

	demo.Execute()

	// Cleanup
	if authServer != nil {
		authServer.Close()
	}
	if resourceServer != nil {
		resourceServer.Close()
	}
}
