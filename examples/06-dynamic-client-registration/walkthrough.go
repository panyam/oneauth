package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/panyam/demokit"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/examples/common"
	"github.com/panyam/oneauth/examples/refs"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

const kcExamplesURL = "http://localhost:8280"
const kcExamplesRealm = "oneauth-examples"

func runDemo() {
	ks := keys.NewInMemoryKeyStore()

	authServer := httptest.NewUnstartedServer(http.NewServeMux())
	authServer.Config.Handler = newAuthServer(ks, "")
	authServer.Start()
	defer authServer.Close()
	authServer.Config.Handler = newAuthServer(ks, authServer.URL)

	var symClientID, symClientSecret string
	var symRegToken, symRegURI string
	var symRegTokenPrevious string // captured before PUT rotation so the next step can demo rejection
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

	demo.Step("Register a symmetric client (client_secret_post)").
		Ref(refs.RFC7591).
		Arrow("App", "AS", "POST /apps/dcr {client_name, grant_types, auth_method}").
		DashedArrow("AS", "App", "{client_id, client_secret, client_id_issued_at}").
		Note("The simplest DCR: the AS generates both a client_id and client_secret. The client uses client_secret_post to authenticate at the token endpoint.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -X POST http://localhost:8081/apps/dcr \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name":"My Example Bot",
    "client_uri":"https://bot.example.com",
    "grant_types":["client_credentials"],
    "token_endpoint_auth_method":"client_secret_post",
    "scope":"read write"
  }' | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			dcrReq := map[string]any{
				"client_name":                "My Example Bot",
				"client_uri":                 "https://bot.example.com",
				"grant_types":                []string{"client_credentials"},
				"token_endpoint_auth_method": "client_secret_post",
				"scope":                      "read write",
			}
			body, _ := json.Marshal(dcrReq)

			resp, err := http.Post(authServer.URL+"/apps/dcr", "application/json",
				bytes.NewReader(body))
			if err != nil {
				return demokit.Errf("dcr: %v", err)
			}
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			fmt.Printf("    HTTP status: %d\n\n", resp.StatusCode)

			var dcrResp map[string]any
			json.Unmarshal(respBody, &dcrResp)
			pretty, _ := json.MarshalIndent(dcrResp, "    ", "  ")
			fmt.Printf("    %s\n", string(pretty))

			symClientID = dcrResp["client_id"].(string)
			symClientSecret = dcrResp["client_secret"].(string)
			symRegToken, _ = dcrResp["registration_access_token"].(string)
			symRegURI, _ = dcrResp["registration_client_uri"].(string)
			return nil
		})

	demo.Section("RFC 7592: managing your own registration",
		"Notice the response above includes two extra fields:",
		"",
		"- `registration_access_token` — a Bearer token tied to **this specific client_id**",
		"- `registration_client_uri` — the management endpoint for this registration",
		"",
		"These come from RFC 7592 (Dynamic Client Registration *Management*). Once a client",
		"is registered, holding the access token lets the client read, update, or delete",
		"its own registration without going through an admin — a self-service lifecycle.",
		"",
		"OneAuth issue 168 ships GET (read); 169 / 170 will add PUT (update) and DELETE.",
	)

	demo.Step("Fetch your own registration (RFC 7592 §2.1)").
		Ref(refs.RFC7592).
		Arrow("App", "AS", "GET {registration_client_uri}  Authorization: Bearer {registration_access_token}").
		DashedArrow("AS", "App", "{registration metadata — without client_secret}").
		Note("client.GetRegistration is a thin SDK wrapper. Note the response intentionally omits client_secret on read — re-emitting symmetric credentials on every fetch enlarges disclosure if the access token leaks. Clients that lose the secret will rotate via PUT (#169).").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -X GET '<registration_client_uri>' \
  -H 'Authorization: Bearer <registration_access_token>' | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			if symRegToken == "" || symRegURI == "" {
				return demokit.Errf("symmetric registration didn't issue management credentials")
			}
			resp, err := client.GetRegistration(context.Background(), &client.GetRegistrationRequest{
				RegistrationClientURI:   symRegURI,
				RegistrationAccessToken: symRegToken,
			})
			if err != nil {
				return demokit.Errf("GetRegistration: %v", err)
			}
			got := resp.Registration
			fmt.Printf("    client_id:                 %s\n", got.ClientID)
			fmt.Printf("    client_name:               %s\n", got.ClientName)
			fmt.Printf("    scope:                     %s\n", got.Scope)
			fmt.Printf("    grant_types:               %v\n", got.GrantTypes)
			fmt.Printf("    registration_client_uri:   %s\n", got.RegistrationClientURI)
			fmt.Printf("    client_secret in response: %v (intentionally omitted)\n", got.ClientSecret != "")
			return nil
		})

	demo.Step("Update your scope (RFC 7592 §2.2)").
		Ref(refs.RFC7592).
		Arrow("App", "AS", "PUT {registration_client_uri}  Authorization: Bearer {registration_access_token}").
		DashedArrow("AS", "App", "{registration metadata + NEW registration_access_token}").
		Note("PUT is a full replacement (not PATCH-style merge): any field omitted from the body is cleared. The AS rotates the registration_access_token on success — the response includes a NEW token that supersedes the one passed in. The OneAuth server also rejects token_endpoint_auth_method changes (those require re-keying; clients DELETE + re-register instead).").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -X PUT '<registration_client_uri>' \
  -H 'Authorization: Bearer <registration_access_token>' \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id":"<from registration>",
    "client_name":"My Example Bot",
    "client_uri":"https://bot.example.com",
    "grant_types":["client_credentials"],
    "token_endpoint_auth_method":"client_secret_post",
    "scope":"read write admin"
  }' | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			if symRegToken == "" || symRegURI == "" {
				return demokit.Errf("symmetric registration didn't issue management credentials")
			}
			resp, err := client.UpdateRegistration(context.Background(), &client.UpdateRegistrationRequest{
				RegistrationClientURI:   symRegURI,
				RegistrationAccessToken: symRegToken,
				ClientID:                symClientID,
				Metadata: client.ClientRegistrationRequest{
					ClientName:              "My Example Bot",
					ClientURI:               "https://bot.example.com",
					GrantTypes:              []string{"client_credentials"},
					TokenEndpointAuthMethod: "client_secret_post",
					Scope:                   "read write admin",
				},
			})
			if err != nil {
				return demokit.Errf("UpdateRegistration: %v", err)
			}
			updated := resp.Registration
			fmt.Printf("    client_id:        %s\n", updated.ClientID)
			fmt.Printf("    new scope:        %s\n", updated.Scope)
			fmt.Printf("    token rotated:    %v (old != new)\n", updated.RegistrationAccessToken != symRegToken)
			fmt.Printf("    new token (4):    %s...\n", updated.RegistrationAccessToken[:4])

			// Persist the rotated token; remember the old one so the next step
			// can demonstrate that it is now rejected.
			symRegTokenPrevious = symRegToken
			symRegToken = updated.RegistrationAccessToken
			return nil
		})

	demo.Step("Old token is rejected after rotation").
		Ref(refs.RFC7592).
		Arrow("App", "AS", "GET {registration_client_uri}  Authorization: Bearer {OLD token}").
		DashedArrow("AS", "App", "401 Unauthorized").
		Note("After PUT rotates the token, attempting to reuse the *previous* registration_access_token must fail with 401 — even though the client_id is still valid. This is the security guarantee of rotation: a leaked-then-rotated token cannot be replayed.").
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			if symRegTokenPrevious == "" {
				return demokit.Errf("previous step didn't capture the old token")
			}
			_, err := client.GetRegistration(context.Background(), &client.GetRegistrationRequest{
				RegistrationClientURI:   symRegURI,
				RegistrationAccessToken: symRegTokenPrevious,
			})
			if err == nil {
				return demokit.Errf("expected old token to be rejected; it succeeded instead")
			}
			fmt.Printf("    old token (4): %s...\n", symRegTokenPrevious[:4])
			fmt.Printf("    new token (4): %s...\n", symRegToken[:4])
			fmt.Printf("    error from AS: %v\n", err)
			fmt.Printf("    is ErrRegistrationUnauthorized: %v\n",
				errors.Is(err, client.ErrRegistrationUnauthorized))
			return nil
		})

	demo.Step("Get a token with the DCR-registered client").
		Ref(refs.RFC6749_ClientCredentials).
		Arrow("App", "AS", "POST /api/token {client_id, client_secret from DCR}").
		DashedArrow("AS", "App", "{access_token}").
		Note("The dynamically registered client works exactly like a manually registered one — the AS doesn't distinguish between registration methods.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -X POST http://localhost:8081/api/token \
  -d 'grant_type=client_credentials' \
  -d 'client_id=<from DCR>' \
  -d 'client_secret=<from DCR>' \
  -d 'scope=read' | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			tokenResp, err := http.PostForm(authServer.URL+"/api/token", url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {symClientID},
				"client_secret": {symClientSecret},
				"scope":         {"read"},
			})
			if err != nil {
				return demokit.Errf("token: %v", err)
			}
			var tokenData map[string]any
			json.NewDecoder(tokenResp.Body).Decode(&tokenData)
			tokenResp.Body.Close()

			fmt.Printf("    token_type:    %s\n", tokenData["token_type"])
			fmt.Printf("    scope:         %s\n", tokenData["scope"])
			fmt.Printf("    access_token:  %s...\n", tokenData["access_token"].(string)[:40])
			return nil
		})

	demo.Step("Delete the registration (RFC 7592 §2.3)").
		Ref(refs.RFC7592).
		Arrow("App", "AS", "DELETE {registration_client_uri}  Authorization: Bearer {registration_access_token}").
		DashedArrow("AS", "App", "204 No Content").
		Note("DELETE removes the registration AND invalidates the signing credentials. After this, the client_secret captured at registration can no longer mint access tokens — the AS has dropped the signing key. RFC 7592 §2.3 requires the AS to MUST invalidate already-issued tokens; OneAuth does this by deleting the KeyStore entry so the JWT signature check fails.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -X DELETE '<registration_client_uri>' \
  -H 'Authorization: Bearer <registration_access_token>' -i`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			if symRegToken == "" || symRegURI == "" {
				return demokit.Errf("symmetric registration didn't issue management credentials")
			}
			_, err := client.DeleteRegistration(context.Background(), &client.DeleteRegistrationRequest{
				RegistrationClientURI:   symRegURI,
				RegistrationAccessToken: symRegToken,
			})
			if err != nil {
				return demokit.Errf("DeleteRegistration: %v", err)
			}
			fmt.Printf("    DELETE: 204 No Content (registration removed)\n\n")

			// Demonstrate that the credentials are dead — client_credentials
			// with the now-invalidated secret fails.
			tokenResp, err := http.PostForm(authServer.URL+"/api/token", url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {symClientID},
				"client_secret": {symClientSecret},
				"scope":         {"read"},
			})
			if err != nil {
				return demokit.Errf("token check: %v", err)
			}
			tokenResp.Body.Close()
			fmt.Printf("    POST /api/token with old secret → HTTP %d (deleted client cannot mint tokens)\n", tokenResp.StatusCode)
			return nil
		})

	demo.Step("Register an asymmetric client (private_key_jwt with JWKS)").
		Ref(refs.RFC7591).
		Ref(refs.RFC7517).
		Arrow("App", "AS", "POST /apps/dcr {auth_method: private_key_jwt, jwks: {keys: [...]}}").
		DashedArrow("AS", "App", "{client_id} (no client_secret — asymmetric!)").
		Note("For asymmetric auth, the client sends its public key as a JWK set. No secret is returned — the client authenticates with signed JWTs using its private key.").
		VerbatimLang("Reproduce on the wire", "bash", `# Replace JWK_JSON with a single JWK for your public key (kty/n/e for RSA, kty/x/y for EC)
JWK_JSON='{"kty":"RSA","alg":"RS256","kid":"...","n":"...","e":"AQAB"}'
curl -s -X POST http://localhost:8081/apps/dcr \
  -H 'Content-Type: application/json' \
  -d "{
    \"client_name\":\"My Secure Service\",
    \"grant_types\":[\"client_credentials\"],
    \"token_endpoint_auth_method\":\"private_key_jwt\",
    \"jwks\":{\"keys\":[$JWK_JSON]}
  }" | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
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

			resp, err := http.Post(authServer.URL+"/apps/dcr", "application/json",
				bytes.NewReader(body))
			if err != nil {
				return demokit.Errf("dcr: %v", err)
			}
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
			return nil
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

	demo.Step("Register via Keycloak DCR (optional)").
		Ref(refs.RFC7591).
		Arrow("App", "AS", "POST {KC registration_endpoint} {client_name, grant_types}").
		DashedArrow("AS", "App", "{client_id, client_secret, registration_access_token}").
		Note("Same DCR request format against Keycloak. KC returns additional fields like registration_access_token for client management. If KC isn't running, this step is skipped.").
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			kcRealmURL := kcExamplesURL + "/realms/" + kcExamplesRealm
			httpClient := &http.Client{Timeout: 2 * time.Second}
			resp, err := httpClient.Get(kcRealmURL)
			if err != nil {
				fmt.Printf("    SKIPPED: Keycloak not running at %s\n", kcExamplesURL)
				fmt.Printf("    To enable: cd examples && make upkcl\n")
				return nil
			}
			resp.Body.Close()

			kcMeta, err := client.DiscoverAS(kcRealmURL)
			if err != nil {
				fmt.Printf("    ERROR discovering Keycloak: %v\n", err)
				return nil
			}

			if kcMeta.RegistrationEndpoint == "" {
				fmt.Printf("    SKIPPED: Keycloak does not advertise a registration_endpoint\n")
				fmt.Printf("    (KC may need 'registrationAllowed' enabled on the realm)\n")
				return nil
			}

			fmt.Printf("    KC registration endpoint: %s\n\n", kcMeta.RegistrationEndpoint)

			dcrReq := map[string]any{
				"client_name": "Example Bot (from OneAuth demo)",
				"grant_types": []string{"client_credentials"},
			}
			body, _ := json.Marshal(dcrReq)

			dcrResp, err := http.Post(kcMeta.RegistrationEndpoint, "application/json",
				bytes.NewReader(body))
			if err != nil {
				fmt.Printf("    ERROR: %v\n", err)
				return nil
			}
			dcrBody, _ := io.ReadAll(dcrResp.Body)
			dcrResp.Body.Close()

			fmt.Printf("    HTTP status: %d\n", dcrResp.StatusCode)
			var kcDCR map[string]any
			json.Unmarshal(dcrBody, &kcDCR)
			pretty, _ := json.MarshalIndent(kcDCR, "    ", "  ")
			fmt.Printf("    %s\n", string(pretty))
			return nil
		})

	demo.Section("What's next?",
		"In [07 — Client SDK](../07-client-sdk/), you'll see production patterns:",
		"automatic token caching, background refresh, scope step-up, and discovery-driven",
		"configuration — all wrapped in a simple `TokenSource` interface.",
	)

	common.SetupRenderer(demo)
	demo.Execute()
}
