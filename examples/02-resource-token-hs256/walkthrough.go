package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/panyam/demokit"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/examples/common"
	"github.com/panyam/oneauth/examples/refs"
	"github.com/panyam/oneauth/keys"
)

func runDemo() {
	ks := keys.NewInMemoryKeyStore()
	authServer := httptest.NewServer(newAuthServer(ks))
	defer authServer.Close()
	resourceServer := httptest.NewServer(newResourceServer(ks))
	defer resourceServer.Close()

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

	demo.Step("Register an app with HS256 signing").
		Ref(refs.RFC7515).
		Arrow("App", "AS", "POST /apps/register {domain: myapp.example.com, signing_alg: HS256}").
		DashedArrow("AS", "App", "{client_id, client_secret}").
		Note("The app gets a client_id and a shared secret. The secret is stored in the KeyStore — both the app (for minting) and the resource server (for validation) read from there.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -X POST http://localhost:8081/apps/register \
  -H 'Content-Type: application/json' \
  -d '{"client_domain":"myapp.example.com","signing_alg":"HS256"}'`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			body, _ := json.Marshal(map[string]any{
				"client_domain": "myapp.example.com",
				"signing_alg":   "HS256",
			})
			resp, err := http.Post(authServer.URL+"/apps/register", "application/json",
				bytes.NewReader(body))
			if err != nil {
				return demokit.Errf("register: %v", err)
			}
			var reg map[string]any
			json.NewDecoder(resp.Body).Decode(&reg)
			resp.Body.Close()

			clientID = reg["client_id"].(string)
			clientSecret = reg["client_secret"].(string)
			fmt.Printf("    client_id:     %s\n", clientID)
			fmt.Printf("    client_secret: %s...\n", clientSecret[:16])
			return nil
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

	demo.Step("Mint a resource token for user Alice").
		Ref(refs.RFC7519).
		Ref(refs.RFC7515).
		Ref(refs.RFC7638).
		Arrow("App", "App", "MintResourceToken(alice, scopes=[read,write], max_rooms=10)").
		Note("The app creates a JWT with sub=alice, signed with its HS256 secret. The token includes quota claims (max_rooms) for resource-level enforcement.").
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			tok, err := admin.MintResourceToken(
				"alice", clientID, clientSecret,
				admin.AppQuota{MaxRooms: 10, MaxMsgRate: 30.0},
				[]string{"read", "write"}, nil,
			)
			if err != nil {
				return demokit.Errf("mint alice: %v", err)
			}
			aliceToken = tok
			fmt.Printf("    token for alice: %s...\n", aliceToken[:40])
			return nil
		})

	demo.Step("Mint a resource token for user Bob (different scopes)").
		Ref(refs.RFC7519).
		Arrow("App", "App", "MintResourceToken(bob, scopes=[read], max_rooms=3)").
		Note("Same app, different user, different permissions. Bob gets read-only access with a lower room quota.").
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			tok, err := admin.MintResourceToken(
				"bob", clientID, clientSecret,
				admin.AppQuota{MaxRooms: 3},
				[]string{"read"}, nil,
			)
			if err != nil {
				return demokit.Errf("mint bob: %v", err)
			}
			bobToken = tok
			fmt.Printf("    token for bob: %s...\n", bobToken[:40])
			return nil
		})

	demo.Step("Resource server validates Alice's token").
		Ref(refs.RFC6750).
		Ref(refs.RFC7515).
		Arrow("App", "RS", "GET /resource (Bearer: alice's token)").
		Arrow("RS", "RS", "Validate HS256 signature via KeyStore").
		DashedArrow("RS", "App", "200 {user: alice, scopes: [read,write], max_rooms: 10}").
		Note("The resource server validates the JWT using the app's key from the shared KeyStore. It extracts the user ID, scopes, and quota claims.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s http://localhost:8082/resource \
  -H "Authorization: Bearer <alice's token>"`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			req, _ := http.NewRequest("GET", resourceServer.URL+"/resource", nil)
			req.Header.Set("Authorization", "Bearer "+aliceToken)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return demokit.Errf("get: %v", err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()

			fmt.Printf("    status: %d\n", res.StatusCode)
			var data map[string]any
			json.Unmarshal(body, &data)
			pretty, _ := json.MarshalIndent(data, "    ", "  ")
			fmt.Printf("    response: %s\n", string(pretty))
			return nil
		})

	demo.Step("Resource server validates Bob's token").
		Arrow("App", "RS", "GET /resource (Bearer: bob's token)").
		DashedArrow("RS", "App", "200 {user: bob, scopes: [read], max_rooms: 3}").
		Note("Same resource server, different user — Bob's token has fewer scopes and a lower quota.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s http://localhost:8082/resource \
  -H "Authorization: Bearer <bob's token>"`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			req, _ := http.NewRequest("GET", resourceServer.URL+"/resource", nil)
			req.Header.Set("Authorization", "Bearer "+bobToken)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return demokit.Errf("get: %v", err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()

			fmt.Printf("    status: %d\n", res.StatusCode)
			var data map[string]any
			json.Unmarshal(body, &data)
			pretty, _ := json.MarshalIndent(data, "    ", "  ")
			fmt.Printf("    response: %s\n", string(pretty))
			return nil
		})

	demo.Step("Token signed with wrong secret is rejected").
		Ref(refs.RFC7515).
		Arrow("App", "App", "MintResourceToken(eve, secret=wrong-secret)").
		Arrow("App", "RS", "GET /resource (Bearer: bad token)").
		DashedArrow("RS", "App", "401 Unauthorized").
		Note("A token signed with the wrong secret fails signature verification — the resource server rejects it immediately.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -o /dev/null -w '%{http_code}\n' \
  http://localhost:8082/resource \
  -H "Authorization: Bearer <token signed with a different secret>"`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			badToken, _ := admin.MintResourceToken(
				"eve", clientID, "wrong-secret",
				admin.AppQuota{}, []string{"admin"}, nil,
			)
			req, _ := http.NewRequest("GET", resourceServer.URL+"/resource", nil)
			req.Header.Set("Authorization", "Bearer "+badToken)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return demokit.Errf("get: %v", err)
			}
			res.Body.Close()
			fmt.Printf("    status: %d (correctly rejected — wrong signing key)\n", res.StatusCode)
			return nil
		})

	demo.Section("What's next?",
		"In [03 — Resource Token (RS256 + JWKS)](../03-resource-token-rs256-jwks/),",
		"you'll see the asymmetric version: the app registers a public key, serves it",
		"via JWKS, and the resource server discovers it automatically. No shared",
		"secrets — the resource server never sees the private key.",
	)

	common.SetupRenderer(demo)
	demo.Execute()
}
