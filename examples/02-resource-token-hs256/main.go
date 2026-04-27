// Example 02: Resource Token with HS256 (Federated Auth)
//
// Building on Example 01, this shows how a registered app can mint
// resource-scoped tokens for individual users — not just for itself.
// This is OneAuth's federated authentication pattern.
//
// In Example 01: client_credentials → token with sub=client_id (machine identity)
// In this example: app registers → mints per-user tokens → resource server validates
//
// Run:   go run ./examples/02-resource-token-hs256/
// Docs:  Run with --readme to regenerate README.md
//
// See: https://www.rfc-editor.org/rfc/rfc7519 (JWT)
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/demokit"
	"github.com/panyam/oneauth/examples/refs"
	"github.com/panyam/oneauth/keys"
)

func main() {
	var authServer, resourceServer *httptest.Server
	var ks keys.KeyStorage
	var clientID, clientSecret string
	var aliceToken, bobToken string

	demo := demokit.New("02: Resource Token with HS256 (Federated Auth)").
		Dir("02-resource-token-hs256").
		Description("Non-UI | No infrastructure needed | Builds on Example 01").
		Actors(
			demokit.Actor("App", "Your App"),
			demokit.Actor("AS", "Auth Server"),
			demokit.Actor("RS", "Resource Server"),
		)

	demo.Section("How this differs from Example 01",
		"**Actors:** App, Auth Server (AS), Resource Server (RS).",
		"Think: the GitHub bot now posts to Slack *as Alice*, not as itself.",
		"[What are these?](../README.md#cast-of-characters)",
		"",
		"In [01 — Client Credentials](../01-client-credentials/), the bot got a token",
		"representing *itself* (sub=client_id). That's machine-to-machine auth.",
		"",
		"Here, the app registers with the auth server and gets a shared secret (HS256).",
		"Then it uses `admin.MintResourceToken()` to create JWTs *for individual users*.",
		"Each token carries:",
		"- `sub` = the user's ID (not the app's)",
		"- `client_id` = the app that minted it",
		"- `scopes` = what this user can do",
		"- Quota claims (max_rooms, max_msg_rate) for resource-level limits",
		"",
		"The resource server validates these tokens using the same KeyStore — it trusts",
		"the app's signing key without calling back to the auth server.",
	)

	// --- Setup ---
	demo.Step("Start auth server and resource server").
		Note("Same as Example 01, but now the resource server also extracts the `client_id` claim to know which app minted the token.").
		Run(func() {
			ks = keys.NewInMemoryKeyStore()
			registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())

			authMux := http.NewServeMux()
			authMux.Handle("/apps/", registrar.Handler())
			authServer = httptest.NewServer(authMux)

			middleware := &apiauth.APIMiddleware{KeyStore: ks}
			resMux := http.NewServeMux()
			resMux.Handle("GET /resource", middleware.ValidateToken(
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
			resourceServer = httptest.NewServer(resMux)

			fmt.Printf("    Auth server:     %s\n", authServer.URL)
			fmt.Printf("    Resource server: %s\n", resourceServer.URL)
		})

	// --- Register ---
	demo.Step("Register an app with HS256 signing").
		Ref(refs.RFC7515).
		Arrow("App", "AS", "POST /apps/register {domain: myapp.example.com, signing_alg: HS256}").
		DashedArrow("AS", "App", "{client_id, client_secret}").
		Note("The app gets a client_id and a shared secret. The secret is stored in the KeyStore — both the app and resource server can use it for signing/verification.").
		Run(func() {
			body, _ := json.Marshal(map[string]any{
				"client_domain": "myapp.example.com",
				"signing_alg":   "HS256",
			})
			resp, _ := http.Post(authServer.URL+"/apps/register", "application/json",
				bytes.NewReader(body))
			var reg map[string]any
			json.NewDecoder(resp.Body).Decode(&reg)
			resp.Body.Close()

			clientID = reg["client_id"].(string)
			clientSecret = reg["client_secret"].(string)
			fmt.Printf("    client_id:     %s\n", clientID)
			fmt.Printf("    client_secret: %s...\n", clientSecret[:16])
		})

	demo.Section("MintResourceToken vs client_credentials",
		"`MintResourceToken` is a library call, not an HTTP endpoint. The app calls it",
		"directly in its own process to create a JWT signed with the shared secret.",
		"",
		"This is different from the `client_credentials` grant in Example 01, where the",
		"app POSTs to the auth server's token endpoint. Here the app is trusted to mint",
		"tokens itself — the auth server just manages key registration.",
		"",
		"Think of it like this:",
		"- **client_credentials**: \"Auth server, give ME a token\"",
		"- **MintResourceToken**: \"I'll make a token FOR this user, signed with my key\"",
	)

	// --- Mint for Alice ---
	demo.Step("Mint a resource token for user Alice").
		Ref(refs.RFC7519).
		Ref(refs.RFC7515).
		Ref(refs.RFC7638).
		Arrow("App", "App", "MintResourceToken(alice, scopes=[read,write], max_rooms=10)").
		Note("The app creates a JWT with sub=alice, signed with its HS256 secret. The token includes quota claims (max_rooms) for resource-level enforcement.").
		Run(func() {
			var err error
			aliceToken, err = admin.MintResourceToken(
				"alice", clientID, clientSecret,
				admin.AppQuota{MaxRooms: 10, MaxMsgRate: 30.0},
				[]string{"read", "write"}, nil,
			)
			if err != nil {
				fmt.Printf("    ERROR: %v\n", err)
				return
			}
			fmt.Printf("    token for alice: %s...\n", aliceToken[:40])
		})

	// --- Mint for Bob ---
	demo.Step("Mint a resource token for user Bob (different scopes)").
		Ref(refs.RFC7519).
		Arrow("App", "App", "MintResourceToken(bob, scopes=[read], max_rooms=3)").
		Note("Same app, different user, different permissions. Bob gets read-only access with a lower room quota.").
		Run(func() {
			var err error
			bobToken, err = admin.MintResourceToken(
				"bob", clientID, clientSecret,
				admin.AppQuota{MaxRooms: 3},
				[]string{"read"}, nil,
			)
			if err != nil {
				fmt.Printf("    ERROR: %v\n", err)
				return
			}
			fmt.Printf("    token for bob: %s...\n", bobToken[:40])
		})

	// --- Validate Alice ---
	demo.Step("Resource server validates Alice's token").
		Ref(refs.RFC6750).
		Ref(refs.RFC7515).
		Arrow("App", "RS", "GET /resource (Bearer: alice's token)").
		Arrow("RS", "RS", "Validate HS256 signature via KeyStore").
		DashedArrow("RS", "App", "200 {user: alice, scopes: [read,write], max_rooms: 10}").
		Note("The resource server validates the JWT using the app's key from the shared KeyStore. It extracts the user ID, scopes, and quota claims.").
		Run(func() {
			req, _ := http.NewRequest("GET", resourceServer.URL+"/resource", nil)
			req.Header.Set("Authorization", "Bearer "+aliceToken)
			res, _ := http.DefaultClient.Do(req)
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()

			fmt.Printf("    status: %d\n", res.StatusCode)
			var data map[string]any
			json.Unmarshal(body, &data)
			pretty, _ := json.MarshalIndent(data, "    ", "  ")
			fmt.Printf("    response: %s\n", string(pretty))
		})

	// --- Validate Bob ---
	demo.Step("Resource server validates Bob's token").
		Arrow("App", "RS", "GET /resource (Bearer: bob's token)").
		DashedArrow("RS", "App", "200 {user: bob, scopes: [read], max_rooms: 3}").
		Note("Same resource server, different user — Bob's token has fewer scopes and a lower quota.").
		Run(func() {
			req, _ := http.NewRequest("GET", resourceServer.URL+"/resource", nil)
			req.Header.Set("Authorization", "Bearer "+bobToken)
			res, _ := http.DefaultClient.Do(req)
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()

			fmt.Printf("    status: %d\n", res.StatusCode)
			var data map[string]any
			json.Unmarshal(body, &data)
			pretty, _ := json.MarshalIndent(data, "    ", "  ")
			fmt.Printf("    response: %s\n", string(pretty))
		})

	// --- Wrong secret ---
	demo.Step("Token signed with wrong secret is rejected").
		Ref(refs.RFC7515).
		Arrow("App", "App", "MintResourceToken(eve, secret=wrong-secret)").
		Arrow("App", "RS", "GET /resource (Bearer: bad token)").
		DashedArrow("RS", "App", "401 Unauthorized").
		Note("A token signed with the wrong secret fails signature verification — the resource server rejects it immediately.").
		Run(func() {
			badToken, _ := admin.MintResourceToken(
				"eve", clientID, "wrong-secret",
				admin.AppQuota{}, []string{"admin"}, nil,
			)
			req, _ := http.NewRequest("GET", resourceServer.URL+"/resource", nil)
			req.Header.Set("Authorization", "Bearer "+badToken)
			res, _ := http.DefaultClient.Do(req)
			res.Body.Close()
			fmt.Printf("    status: %d (correctly rejected — wrong signing key)\n", res.StatusCode)
		})

	demo.Section("What's next?",
		"In [03 — Resource Token (RS256 + JWKS)](../03-resource-token-rs256-jwks/),",
		"you'll see the asymmetric version: the app registers a public key, serves it",
		"via JWKS, and the resource server discovers it automatically. No shared",
		"secrets — the resource server never sees the private key.",
	)

	demo.Execute()

	if authServer != nil {
		authServer.Close()
	}
	if resourceServer != nil {
		resourceServer.Close()
	}
}
