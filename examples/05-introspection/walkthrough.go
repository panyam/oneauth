package main

import (
	"encoding/base64"
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
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/examples/common"
	"github.com/panyam/oneauth/examples/refs"
	"github.com/panyam/oneauth/keys"
)

const kcExamplesURL = "http://localhost:8280"
const kcExamplesRealm = "oneauth-examples"
const kcExampleClientID = "example-app"
const kcExampleClientSecret = "example-app-secret"

func runDemo() {
	ks := keys.NewInMemoryKeyStore()
	blacklist := core.NewInMemoryBlacklist()

	// Two-pass start: get the test server's URL, rebuild handler with
	// it as the issuer (the issuer claim has to match the discovery /
	// metadata identity for tokens to validate).
	authServer := httptest.NewUnstartedServer(http.NewServeMux())
	authServer.Config.Handler = newAuthServer(ks, blacklist, "")
	authServer.Start()
	defer authServer.Close()
	authServer.Config.Handler = newAuthServer(ks, blacklist, authServer.URL)

	var clientID, clientSecret, accessToken string
	var tokenJTI string

	demo := demokit.New("05: Token Introspection").
		Dir("05-introspection").
		Description("Non-UI | No infrastructure needed | Builds on Example 04").
		Actors(
			demokit.Actor("App", "Client App"),
			demokit.Actor("AS", "Auth Server"),
			demokit.Actor("RS", "Resource Server"),
		)

	demo.Section("About this example",
		"**Actors:** App, Auth Server (AS), Resource Server (RS).",
		"Think: Slack's API asks Slack's identity service \"is this bot's token still valid?\"",
		"[What are these?](../README.md#cast-of-characters)",
		"",
		"In Examples 01-04, the resource server validated JWTs locally — fast, but",
		"it can't detect revoked tokens until they expire.",
		"",
		"Token introspection (RFC 7662) is the alternative: the RS sends the token",
		"to the AS's introspection endpoint and gets back `{active: true/false}` plus",
		"the token's claims. The AS checks its blacklist before responding.",
		"",
		"**When to use which:**",
		"| Method | Speed | Revocation | Use when |",
		"|--------|-------|-----------|----------|",
		"| Local JWT validation | Fast (no network) | Not immediate | Most requests, short-lived tokens |",
		"| Introspection | Slower (HTTP call) | Immediate | Sensitive ops, long-lived tokens, revocation needed |",
		"| Both (hybrid) | Best of both | Immediate | Validate locally, introspect on failure or for critical ops |",
	)

	demo.Step("Register a client and get an access token").
		Ref(refs.RFC6749_ClientCredentials).
		Ref(refs.RFC7519).
		Arrow("App", "AS", "POST /apps/register → POST /api/token").
		DashedArrow("AS", "App", "{client_id, client_secret, access_token}").
		Note("Same as Example 01 — register, then client_credentials grant. The token includes a jti (JWT ID) claim used for revocation.").
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			body, _ := json.Marshal(map[string]any{
				"client_domain": "introspect-demo.example.com",
				"signing_alg":   "HS256",
			})
			regResp, err := http.Post(authServer.URL+"/apps/register",
				"application/json", strings.NewReader(string(body)))
			if err != nil {
				return demokit.Errf("register: %v", err)
			}
			var reg map[string]any
			json.NewDecoder(regResp.Body).Decode(&reg)
			regResp.Body.Close()
			clientID = reg["client_id"].(string)
			clientSecret = reg["client_secret"].(string)

			tokenResp, err := http.PostForm(authServer.URL+"/api/token", url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {clientID},
				"client_secret": {clientSecret},
				"scope":         {"read write"},
			})
			if err != nil {
				return demokit.Errf("token: %v", err)
			}
			var tokenData map[string]any
			json.NewDecoder(tokenResp.Body).Decode(&tokenData)
			tokenResp.Body.Close()
			accessToken = tokenData["access_token"].(string)

			claims := parseJWTClaims(accessToken)
			tokenJTI = claims["jti"].(string)

			fmt.Printf("    client_id:    %s\n", clientID)
			fmt.Printf("    access_token: %s...\n", accessToken[:40])
			fmt.Printf("    jti:          %s...\n", tokenJTI[:16])
			return nil
		})

	demo.Section("How introspection works",
		"The resource server POSTs the token to `/oauth/introspect` and authenticates",
		"itself with HTTP Basic auth (its own client_id + secret). The AS:",
		"",
		"1. Authenticates the caller (is this a registered resource server?)",
		"2. Validates the token (signature, expiry)",
		"3. Checks the blacklist (has this token been revoked?)",
		"4. Returns `{active: true, sub, scope, exp, ...}` or `{active: false}`",
		"",
		"**Security:** The introspection endpoint never reveals *why* a token is invalid.",
		"Expired, revoked, malformed — all return `{active: false}`. This prevents",
		"information leakage to potentially malicious callers.",
	)

	demo.Step("Introspect a valid token").
		Ref(refs.RFC7662).
		Arrow("RS", "AS", "POST /oauth/introspect {token} (Basic auth)").
		DashedArrow("AS", "RS", "{active: true, sub, scope, exp, iss, jti}").
		Note("The RS authenticates with its own credentials (same client in this example). The response includes the token's claims — the RS doesn't need to decode the JWT itself.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -u "<client_id>:<client_secret>" \
  -d "token=<access_token>" \
  http://localhost:8081/oauth/introspect | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			result := introspect(authServer.URL+"/oauth/introspect", accessToken, clientID, clientSecret)
			pretty, _ := json.MarshalIndent(result, "    ", "  ")
			fmt.Printf("    %s\n", string(pretty))
			return nil
		})

	demo.Step("Introspect a garbage token").
		Ref(refs.RFC7662).
		Arrow("RS", "AS", "POST /oauth/introspect {token: not-a-real-token}").
		DashedArrow("AS", "RS", "{active: false}").
		Note("Invalid tokens always return {active: false} — the AS never reveals why. This is a security requirement of RFC 7662.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -u "<client_id>:<client_secret>" \
  -d "token=not-a-real-token" \
  http://localhost:8081/oauth/introspect | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			result := introspect(authServer.URL+"/oauth/introspect", "not-a-real-token", clientID, clientSecret)
			pretty, _ := json.MarshalIndent(result, "    ", "  ")
			fmt.Printf("    %s\n", string(pretty))
			return nil
		})

	demo.Step("Revoke the token, then introspect again").
		Ref(refs.RFC7662).
		Arrow("Admin", "AS", "blacklist.Revoke(jti)").
		Arrow("RS", "AS", "POST /oauth/introspect {same token as step 3}").
		DashedArrow("AS", "RS", "{active: false}").
		Note("After revocation, the same token that was valid in step 3 now returns active=false. This is the key advantage over local JWT validation — revocation takes effect immediately.").
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			claims := parseJWTClaims(accessToken)
			expFloat := claims["exp"].(float64)
			blacklist.Revoke(tokenJTI, time.Unix(int64(expFloat), 0))
			fmt.Printf("    Revoked jti=%s...\n\n", tokenJTI[:16])

			result := introspect(authServer.URL+"/oauth/introspect", accessToken, clientID, clientSecret)
			pretty, _ := json.MarshalIndent(result, "    ", "  ")
			fmt.Printf("    %s\n", string(pretty))
			return nil
		})

	demo.Step("Introspect without authentication (rejected)").
		Ref(refs.RFC7662).
		Arrow("Attacker", "AS", "POST /oauth/introspect {token} (no Basic auth)").
		DashedArrow("AS", "Attacker", "401 Unauthorized").
		Note("The introspection endpoint requires the caller to authenticate. An unauthenticated request is rejected — you can't fish for valid tokens.").
		VerbatimLang("Reproduce on the wire", "bash", `# No -u — caller is unauthenticated
curl -s -o /dev/null -w '%{http_code}\n' \
  -d "token=<access_token>" \
  http://localhost:8081/oauth/introspect`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			form := url.Values{"token": {accessToken}}
			req, _ := http.NewRequest("POST", authServer.URL+"/oauth/introspect",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return demokit.Errf("post: %v", err)
			}
			resp.Body.Close()
			fmt.Printf("    status: %d (correctly rejected — no authentication)\n", resp.StatusCode)
			return nil
		})

	demo.Step("Introspect via Keycloak (optional)").
		Ref(refs.RFC7662).
		Arrow("App", "AS", "POST {KC token_endpoint} → get KC token").
		Arrow("RS", "AS", "POST {KC introspection_endpoint} {token}").
		DashedArrow("AS", "RS", "{active: true, sub, scope, ...}").
		Note("Same introspection flow against Keycloak. If KC isn't running, this step is skipped — run 'make upkcl' in examples/ to start it.").
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
			fmt.Printf("    Keycloak introspection endpoint: %s\n\n", kcMeta.IntrospectionEndpoint)

			kcTokenResp, err := http.PostForm(kcMeta.TokenEndpoint, url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {kcExampleClientID},
				"client_secret": {kcExampleClientSecret},
				"scope":         {"openid"},
			})
			if err != nil {
				fmt.Printf("    ERROR getting KC token: %v\n", err)
				return nil
			}
			var kcToken map[string]any
			json.NewDecoder(kcTokenResp.Body).Decode(&kcToken)
			kcTokenResp.Body.Close()

			if kcToken["error"] != nil {
				fmt.Printf("    ERROR getting KC token: %v\n", kcToken["error_description"])
				return nil
			}

			kcAccessToken := kcToken["access_token"].(string)
			fmt.Printf("    KC access_token: %s...\n\n", kcAccessToken[:40])

			kcResult := introspect(kcMeta.IntrospectionEndpoint,
				kcAccessToken, kcExampleClientID, kcExampleClientSecret)
			pretty, _ := json.MarshalIndent(kcResult, "    ", "  ")
			fmt.Printf("    KC introspection response:\n    %s\n", string(pretty))
			return nil
		})

	demo.Section("Introspection vs local validation — the tradeoff",
		"```",
		"Local JWT validation:     RS checks signature locally",
		"  + No network call        ← fast",
		"  + Works offline          ← resilient",
		"  - Can't detect revocation until token expires",
		"",
		"Introspection:            RS asks AS on every request",
		"  + Revocation is immediate",
		"  + Works with opaque (non-JWT) tokens",
		"  - Adds latency (HTTP round-trip)",
		"  - AS becomes a dependency",
		"",
		"Hybrid (production pattern):",
		"  1. Validate JWT locally first (fast path)",
		"  2. If local validation fails, fall back to introspection",
		"  3. For critical operations, always introspect",
		"```",
		"",
		"OneAuth's `APIMiddleware` supports the hybrid model via the `Introspection`",
		"field — set it to enable automatic fallback to introspection.",
	)

	demo.Section("What's next?",
		"In [06 — Dynamic Client Registration](../06-dynamic-client-registration/),",
		"you'll see how apps can register themselves programmatically via RFC 7591 —",
		"no admin dashboard needed. This is how third-party integrations onboard.",
	)

	common.SetupRenderer(demo)
	demo.Execute()
}

// introspect calls an introspection endpoint and returns the parsed
// response. endpointURL is the full introspection URL.
func introspect(endpointURL, token, callerID, callerSecret string) map[string]any {
	form := url.Values{"token": {token}}
	req, _ := http.NewRequest("POST", endpointURL,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(callerID, callerSecret)

	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result map[string]any
	json.Unmarshal(body, &result)
	return result
}

// parseJWTClaims decodes a JWT payload without verification (display only).
func parseJWTClaims(tokenStr string) map[string]any {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	json.Unmarshal(payload, &claims)
	return claims
}
