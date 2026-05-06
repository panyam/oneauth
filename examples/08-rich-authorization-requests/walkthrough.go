package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/panyam/demokit"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/examples/common"
	"github.com/panyam/oneauth/examples/refs"
	"github.com/panyam/oneauth/keys"
)

const rarIssuerURL = "http://localhost:8181"

func runDemo() {
	ks := keys.NewInMemoryKeyStore()

	authServer := httptest.NewUnstartedServer(http.NewServeMux())
	authServer.Config.Handler = newAuthServer(ks, "")
	authServer.Start()
	defer authServer.Close()
	authServer.Config.Handler = newAuthServer(ks, authServer.URL)

	paymentsRS := httptest.NewServer(newPaymentsServer(authServer.URL))
	defer paymentsRS.Close()
	accountsRS := httptest.NewServer(newAccountsServer(authServer.URL))
	defer accountsRS.Close()

	var clientID, clientSecret string
	var paymentToken string

	demo := demokit.New("08: Rich Authorization Requests (RFC 9396)").
		Dir("08-rich-authorization-requests").
		Description("Non-UI | No infrastructure needed | Builds on all previous examples").
		Actors(
			demokit.Actor("App", "Banking App"),
			demokit.Actor("AS", "Auth Server"),
			demokit.Actor("Pay", "Payments API"),
			demokit.Actor("Acct", "Accounts API"),
		)

	demo.Section("About this example",
		"**Actors:** Banking App, Auth Server (AS), Payments API (RS), Accounts API (RS).",
		"Think: a fintech app that needs to initiate a specific payment — not just \"access payments\".",
		"[What are these?](../README.md#cast-of-characters)",
		"",
		"**The problem with scopes:**",
		"```",
		"scope=payments              ← \"can do anything with payments\" (too broad)",
		"scope=payments:initiate     ← better, but can't express amount/recipient",
		"scope=payments:initiate:45EUR:merchant-a  ← this is getting silly",
		"```",
		"",
		"**RFC 9396 solution — authorization_details:**",
		"```json",
		"{",
		"  \"type\": \"payment_initiation\",",
		"  \"actions\": [\"initiate\"],",
		"  \"instructedAmount\": {\"currency\": \"EUR\", \"amount\": \"45.00\"},",
		"  \"creditorName\": \"Merchant A\"",
		"}",
		"```",
		"",
		"Structured, typed, with API-specific extension fields. This is what banks,",
		"fintechs, and any regulated industry needs.",
	)

	fmt.Printf("    Auth server:   %s\n", authServer.URL)
	fmt.Printf("    Payments API:  %s\n", paymentsRS.URL)
	fmt.Printf("    Accounts API:  %s\n\n", accountsRS.URL)

	demo.Step("Discover supported authorization_details types").
		Ref(refs.RFC9396).
		Ref(refs.RFC8414).
		Arrow("App", "AS", "GET /.well-known/openid-configuration").
		DashedArrow("AS", "App", "{..., authorization_details_types_supported: [...]}").
		Note("RFC 9396 §10: the AS advertises which authorization_details types it supports. Clients check this before requesting.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s http://localhost:8081/.well-known/openid-configuration \
  | jq '.authorization_details_types_supported'`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			meta, err := client.DiscoverAS(authServer.URL)
			if err != nil {
				return demokit.Errf("discover: %v", err)
			}
			resp, err := http.Get(authServer.URL + "/.well-known/openid-configuration")
			if err != nil {
				return demokit.Errf("metadata: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var raw map[string]any
			json.Unmarshal(body, &raw)

			types := raw["authorization_details_types_supported"]
			fmt.Printf("    authorization_details_types_supported: %v\n", types)
			fmt.Printf("    token_endpoint: %s\n", meta.TokenEndpoint)
			return nil
		})

	demo.Step("Register a banking app via DCR (RFC 7591)").
		Ref(refs.RFC7591).
		Arrow("App", "AS", "POST /apps/dcr {client_name, grant_types, scope}").
		DashedArrow("AS", "App", "{client_id, client_secret}").
		Note("Using standards-compliant DCR (Example 06) instead of the proprietary endpoint. A banking app should be fully standards-based.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -X POST http://localhost:8081/apps/dcr \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name":"Fintech Payment App",
    "grant_types":["client_credentials"],
    "token_endpoint_auth_method":"client_secret_post",
    "scope":"payments accounts"
  }' | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			body, _ := json.Marshal(map[string]any{
				"client_name":                "Fintech Payment App",
				"grant_types":                []string{"client_credentials"},
				"token_endpoint_auth_method": "client_secret_post",
				"scope":                      "payments accounts",
			})
			resp, err := http.Post(authServer.URL+"/apps/dcr", "application/json",
				bytes.NewReader(body))
			if err != nil {
				return demokit.Errf("dcr: %v", err)
			}
			var reg map[string]any
			json.NewDecoder(resp.Body).Decode(&reg)
			resp.Body.Close()
			clientID = reg["client_id"].(string)
			clientSecret = reg["client_secret"].(string)
			fmt.Printf("    client_id:   %s\n", clientID)
			fmt.Printf("    client_name: %s\n", reg["client_name"])
			return nil
		})

	demo.Step("Request a token with payment authorization_details").
		Ref(refs.RFC9396).
		Ref(refs.RFC6749_ClientCredentials).
		Arrow("App", "AS", "POST /api/token {authorization_details: [{type: payment_initiation, ...}]}").
		DashedArrow("AS", "App", "{access_token, authorization_details: [{type: payment_initiation, ...}]}").
		Note("The token request includes structured authorization_details — not just 'scope=payments' but the exact payment to initiate. The AS validates, embeds in the JWT, and echoes in the response.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -X POST http://localhost:8081/api/token \
  -H 'Content-Type: application/json' \
  -d '{
    "grant_type":"client_credentials",
    "client_id":"<from previous step>",
    "client_secret":"<from previous step>",
    "authorization_details":[{
      "type":"payment_initiation",
      "actions":["initiate"],
      "locations":["http://localhost:8082/payments"],
      "instructedAmount":{"currency":"EUR","amount":"45.00"},
      "creditorName":"Merchant A"
    }]
  }' | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			reqBody := map[string]any{
				"grant_type":    "client_credentials",
				"client_id":     clientID,
				"client_secret": clientSecret,
				"authorization_details": []map[string]any{
					{
						"type":      "payment_initiation",
						"actions":   []string{"initiate"},
						"locations": []string{paymentsRS.URL + "/payments"},
						"instructedAmount": map[string]any{
							"currency": "EUR",
							"amount":   "45.00",
						},
						"creditorName": "Merchant A",
					},
				},
			}
			body, _ := json.Marshal(reqBody)

			resp, err := http.Post(authServer.URL+"/api/token", "application/json",
				bytes.NewReader(body))
			if err != nil {
				return demokit.Errf("token: %v", err)
			}
			var tokenData map[string]any
			json.NewDecoder(resp.Body).Decode(&tokenData)
			resp.Body.Close()

			paymentToken = tokenData["access_token"].(string)

			ad := tokenData["authorization_details"].([]any)
			adPretty, _ := json.MarshalIndent(ad, "    ", "  ")
			fmt.Printf("    authorization_details in response:\n    %s\n\n", string(adPretty))
			fmt.Printf("    access_token: %s...\n", paymentToken[:40])
			return nil
		})

	demo.Section("What's in the JWT?",
		"The access token now carries `authorization_details` as a JWT claim:",
		"```json",
		"{",
		"  \"sub\": \"app_abc123\",",
		"  \"scopes\": [...],",
		"  \"authorization_details\": [",
		"    {",
		"      \"type\": \"payment_initiation\",",
		"      \"actions\": [\"initiate\"],",
		"      \"instructedAmount\": {\"currency\": \"EUR\", \"amount\": \"45.00\"},",
		"      \"creditorName\": \"Merchant A\"",
		"    }",
		"  ]",
		"}",
		"```",
		"The resource server reads this claim to enforce fine-grained access.",
	)

	demo.Step("Access the Payments API (authorized)").
		Ref(refs.RFC9396).
		Arrow("App", "Pay", "POST /payments (Bearer: payment token)").
		Arrow("Pay", "Pay", "RequireAuthorizationDetails(\"payment_initiation\") ✓").
		DashedArrow("Pay", "App", "200 {status: payment_accepted, details: [...]}").
		Note("The Payments API uses RequireAuthorizationDetails middleware — it checks that the token has a payment_initiation authorization_details entry. The details are available in the request context.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -X POST http://localhost:8082/payments \
  -H "Authorization: Bearer <payment token>" | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			req, _ := http.NewRequest("POST", paymentsRS.URL+"/payments", nil)
			req.Header.Set("Authorization", "Bearer "+paymentToken)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return demokit.Errf("payments: %v", err)
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

	demo.Step("Access the Accounts API with a payment token (rejected)").
		Ref(refs.RFC9396).
		Arrow("App", "Acct", "GET /accounts (Bearer: payment token)").
		Arrow("Acct", "Acct", "RequireAuthorizationDetails(\"account_information\") ✗").
		DashedArrow("Acct", "App", "401 Unauthorized").
		Note("The payment token has type=payment_initiation but the Accounts API requires type=account_information. Fine-grained enforcement: a payment token can't read account data.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8083/accounts \
  -H "Authorization: Bearer <payment token>"`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			req, _ := http.NewRequest("GET", accountsRS.URL+"/accounts", nil)
			req.Header.Set("Authorization", "Bearer "+paymentToken)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return demokit.Errf("accounts: %v", err)
			}
			res.Body.Close()
			fmt.Printf("    status: %d (correctly rejected — wrong authorization type)\n", res.StatusCode)
			return nil
		})

	demo.Step("Introspect the payment token").
		Ref(refs.RFC9396).
		Ref(refs.RFC7662).
		Arrow("RS", "AS", "POST /oauth/introspect {token}").
		DashedArrow("AS", "RS", "{active: true, authorization_details: [...]}").
		Note("Introspection returns the authorization_details alongside the standard claims. Resource servers that use introspection (instead of local JWT validation) get the same fine-grained information.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -u "<client_id>:<client_secret>" \
  -d "token=<payment token>" \
  http://localhost:8081/oauth/introspect | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			form := url.Values{"token": {paymentToken}}
			req, _ := http.NewRequest("POST", authServer.URL+"/oauth/introspect",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(clientID, clientSecret)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return demokit.Errf("introspect: %v", err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()

			var result map[string]any
			json.Unmarshal(body, &result)
			pretty, _ := json.MarshalIndent(result, "    ", "  ")
			fmt.Printf("    %s\n", string(pretty))
			return nil
		})

	demo.Step("RAR coexists with scopes").
		Ref(refs.RFC9396).
		Arrow("App", "AS", "POST /api/token {scope: read, authorization_details: [...]}").
		DashedArrow("AS", "App", "{scope: read, authorization_details: [...]}").
		Note("Scopes and authorization_details are independent — you can use both in the same request. Scopes for coarse-grained access, RAR for fine-grained.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -X POST http://localhost:8081/api/token \
  -H 'Content-Type: application/json' \
  -d '{
    "grant_type":"client_credentials",
    "client_id":"<id>","client_secret":"<secret>",
    "scope":"read write",
    "authorization_details":[{"type":"account_information","actions":["list_accounts"]}]
  }' | jq '{scope, authorization_details}'`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			reqBody := map[string]any{
				"grant_type":    "client_credentials",
				"client_id":     clientID,
				"client_secret": clientSecret,
				"scope":         "read write",
				"authorization_details": []map[string]any{
					{"type": "account_information", "actions": []string{"list_accounts"}},
				},
			}
			body, _ := json.Marshal(reqBody)
			resp, err := http.Post(authServer.URL+"/api/token", "application/json",
				bytes.NewReader(body))
			if err != nil {
				return demokit.Errf("token: %v", err)
			}
			var tokenData map[string]any
			json.NewDecoder(resp.Body).Decode(&tokenData)
			resp.Body.Close()

			fmt.Printf("    scope: %s\n", tokenData["scope"])
			ad := tokenData["authorization_details"].([]any)
			fmt.Printf("    authorization_details: %d entries\n", len(ad))
			fmt.Printf("    Both present — independent, composable.\n")
			return nil
		})

	demo.Step("Cross-server RAR validation (optional — RAR test issuer)").
		Ref(refs.RFC9396).
		Arrow("App", "AS", "POST {RAR issuer}/api/token {authorization_details}").
		Arrow("App", "RS", "Bearer token → validate via JWKS from RAR issuer").
		Note("No open-source IdP supports RFC 9396 on standard OAuth flows yet. We built a RAR test issuer (cmd/rar-test-issuer) for interop testing. Run 'make uprar' to start it. When Keycloak adds RAR support, this step will migrate to KC.").
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			httpClient := &http.Client{Timeout: 2 * time.Second}
			resp, err := httpClient.Get(rarIssuerURL + "/_ah/health")
			if err != nil {
				fmt.Printf("    SKIPPED: RAR test issuer not running at %s\n", rarIssuerURL)
				fmt.Printf("    To enable: make uprar (from repo root)\n")
				return nil
			}
			resp.Body.Close()

			reqBody := map[string]any{
				"grant_type":    "client_credentials",
				"client_id":     "rar-test-client",
				"client_secret": "rar-test-secret",
				"authorization_details": []map[string]any{
					{"type": "payment_initiation", "actions": []string{"initiate"}},
				},
			}
			body, _ := json.Marshal(reqBody)
			tokenResp, err := http.Post(rarIssuerURL+"/api/token", "application/json",
				bytes.NewReader(body))
			if err != nil {
				fmt.Printf("    ERROR: %v\n", err)
				return nil
			}
			var tokenData map[string]any
			json.NewDecoder(tokenResp.Body).Decode(&tokenData)
			tokenResp.Body.Close()

			fmt.Printf("    Token from RAR test issuer: %s...\n", tokenData["access_token"].(string)[:40])
			ad := tokenData["authorization_details"].([]any)
			fmt.Printf("    authorization_details: %v\n", ad[0].(map[string]any)["type"])
			fmt.Printf("\n    Same RFC 9396 format — issued by a different server.\n")
			return nil
		})

	demo.Section("RFC 9396 in OneAuth — what we built",
		"| Layer | What | RFC section |",
		"|-------|------|------------|",
		"| Data model | `core.AuthorizationDetail` with JSON flattening | §2 |",
		"| Token endpoint | Parse, validate, embed in JWT, return in response | §5 |",
		"| Form-encoded | `authorization_details` as JSON string in form params | §6.1 |",
		"| Introspection | Include in introspection response | §9.1 |",
		"| AS metadata | `authorization_details_types_supported` | §10 |",
		"| DCR | `authorization_details_types` on client registration | §10 |",
		"| Middleware | `RequireAuthorizationDetails()` enforcement | §2 |",
		"| Client SDK | `AuthorizationDetails` on token requests/responses | §5 |",
		"| Error handling | `invalid_authorization_details` error code | §5.2 |",
	)

	demo.Section("What's next?",
		"In [09 — Key Rotation](../09-key-rotation/), you'll see how to rotate",
		"signing keys with a grace period — old tokens keep working during the",
		"transition, then fail after the grace window closes.",
	)

	common.SetupRenderer(demo)
	demo.Execute()
}
