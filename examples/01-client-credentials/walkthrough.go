package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/panyam/demokit"
	"github.com/panyam/oneauth/examples/common"
	"github.com/panyam/oneauth/examples/refs"
	"github.com/panyam/oneauth/keys"
)

// runDemo is the walkthrough — a demokit demo that acts as an OAuth
// client driving the auth server and resource server step by step.
//
// The demo is structurally identical to a real OAuth client. The only
// difference is that the AS+RS run inside this process via httptest
// instead of being separate processes. With `make serve` running, you
// can replicate every step of this walkthrough with curl — the demo
// renders a copy-paste curl command beside each step that hits the wire.
func runDemo() {
	// Servers are spun up in-process from the same builders main.go
	// uses for --serve, so the walkthrough stays byte-identical to the
	// real-server case.
	ks := keys.NewInMemoryKeyStore()
	authServer := httptest.NewServer(newAuthServer(ks))
	defer authServer.Close()
	resourceServer := httptest.NewServer(newResourceServer())
	defer resourceServer.Close()

	// State threaded across steps via closure capture.
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
		"",
		"This walkthrough acts as a scripted OAuth client. The auth server and",
		"resource server it talks to are the same code `make serve` boots — see",
		"`main.go`. Run `make serve` in another terminal and you can replay every",
		"step on the wire with the `curl` blocks shown below.",
	)

	demo.Step("Register a client").
		Ref(refs.RFC7591).
		Arrow("App", "AS", "POST /apps/register {domain, signing_alg}").
		DashedArrow("AS", "App", "{client_id, client_secret}").
		Note("The client receives credentials it will use to authenticate in the next step. Open registration (`NewNoAuth`) is for the demo only — gate this in production.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -X POST http://localhost:8081/apps/register \
  -H 'Content-Type: application/json' \
  -d '{"client_domain":"my-service.example.com","signing_alg":"HS256"}'`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			body, _ := json.Marshal(map[string]any{
				"client_domain": "my-service.example.com",
				"signing_alg":   "HS256",
			})
			resp, err := http.Post(authServer.URL+"/apps/register", "application/json",
				strings.NewReader(string(body)))
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

	demo.Step("Request an access token").
		Ref(refs.RFC6749_ClientCredentials).
		Ref(refs.RFC7519).
		Arrow("App", "AS", "POST /api/token {grant_type: client_credentials}").
		DashedArrow("AS", "App", "{access_token, token_type, expires_in}").
		Note("The AS verifies the client credentials and returns a signed JWT. The token carries sub=client_id (no user context in this flow).").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -X POST http://localhost:8081/api/token \
  -d 'grant_type=client_credentials' \
  -d 'client_id=<from previous step>' \
  -d 'client_secret=<from previous step>' \
  -d 'scope=read write'`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			resp, err := http.PostForm(authServer.URL+"/api/token", url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {clientID},
				"client_secret": {clientSecret},
				"scope":         {"read write"},
			})
			if err != nil {
				return demokit.Errf("token: %v", err)
			}
			var tokenData map[string]any
			json.NewDecoder(resp.Body).Decode(&tokenData)
			resp.Body.Close()

			accessToken = tokenData["access_token"].(string)
			fmt.Printf("    token_type:   %s\n", tokenData["token_type"])
			fmt.Printf("    scope:        %s\n", tokenData["scope"])
			fmt.Printf("    expires_in:   %.0fs\n", tokenData["expires_in"])
			fmt.Printf("    access_token: %s...\n", accessToken[:40])
			return nil
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

	demo.Step("Access a protected resource").
		Ref(refs.RFC6750).
		Ref(refs.RFC7515).
		Arrow("App", "RS", "GET /resource (Authorization: Bearer token)").
		Arrow("RS", "RS", "Validate JWT signature + claims").
		DashedArrow("RS", "App", "200 {data}").
		Note("The resource server validates the JWT signature and extracts claims from it. No network call to the auth server.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s http://localhost:8082/resource \
  -H "Authorization: Bearer <access_token from previous step>"`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			req, _ := http.NewRequest("GET", resourceServer.URL+"/resource", nil)
			req.Header.Set("Authorization", "Bearer "+accessToken)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return demokit.Errf("resource: %v", err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()

			fmt.Printf("    status: %d\n", res.StatusCode)
			var resource map[string]any
			json.Unmarshal(body, &resource)
			pretty, _ := json.MarshalIndent(resource, "    ", "  ")
			fmt.Printf("    response: %s\n", string(pretty))
			return nil
		})

	demo.Step("Access without a token (expect rejection)").
		Ref(refs.RFC6750).
		Arrow("App", "RS", "GET /resource (no Authorization header)").
		DashedArrow("RS", "App", "401 Unauthorized").
		Note("Without a valid Bearer token, the resource server rejects the request.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8082/resource`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			req, _ := http.NewRequest("GET", resourceServer.URL+"/resource", nil)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return demokit.Errf("resource: %v", err)
			}
			res.Body.Close()
			fmt.Printf("    status: %d (correctly rejected)\n", res.StatusCode)
			return nil
		})

	demo.Section("What's next?",
		"In [02 — Resource Token (HS256)](../02-resource-token-hs256/), you'll see",
		"how a registered app can mint tokens *for individual users*, not just for",
		"itself. This is the federated authentication pattern used by OneAuth's",
		"multi-app architecture.",
	)

	common.SetupRenderer(demo)
	demo.Execute()
}
