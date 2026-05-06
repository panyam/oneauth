package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/panyam/demokit"
	"github.com/panyam/oneauth/client"
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

	authServer := httptest.NewUnstartedServer(http.NewServeMux())
	authServer.Config.Handler = newAuthServer(ks, "")
	authServer.Start()
	defer authServer.Close()
	authServer.Config.Handler = newAuthServer(ks, authServer.URL)

	resourceServer := httptest.NewServer(newResourceServer(authServer.URL))
	defer resourceServer.Close()

	// Pre-register a client — the SDK is about token acquisition, not
	// registration (covered in Example 06).
	regResp := postJSON(authServer.URL+"/apps/register", map[string]any{
		"client_domain": "sdk-demo.example.com",
		"signing_alg":   "HS256",
	})
	registeredClientID := regResp["client_id"].(string)
	registeredSecret := regResp["client_secret"].(string)

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

	fmt.Printf("    Pre-registered client: %s\n\n", registeredClientID)

	demo.Step("One-shot token with AuthClient").
		Ref(refs.RFC6749_ClientCredentials).
		Ref(refs.RFC8414).
		Arrow("App", "AS", "client.DiscoverAS(serverURL)").
		Arrow("App", "AS", "authClient.ClientCredentialsToken(id, secret, scopes)").
		DashedArrow("AS", "App", "ServerCredential{AccessToken, ExpiresAt, Scope}").
		Note("AuthClient is the low-level SDK: discover endpoints, then make a single token request. Good for one-off calls. Uses discovery to find the token endpoint automatically.").
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			meta, err := client.DiscoverAS(authServer.URL)
			if err != nil {
				return demokit.Errf("discover: %v", err)
			}
			authClient := client.NewAuthClient(authServer.URL, nil,
				client.WithASMetadata(meta))

			cred, err := authClient.ClientCredentialsToken(
				registeredClientID, registeredSecret, []string{"read"})
			if err != nil {
				return demokit.Errf("token: %v", err)
			}

			fmt.Printf("    access_token: %s...\n", cred.AccessToken[:40])
			fmt.Printf("    scope:        %s\n", cred.Scope)
			fmt.Printf("    expires_at:   %s\n", cred.ExpiresAt.Format(time.RFC3339))
			return nil
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

	demo.Step("Cached token with ClientCredentialsSource").
		Ref(refs.RFC6749_ClientCredentials).
		Arrow("App", "App", "tokenSource.Token() → cached or fetched").
		Arrow("App", "RS", "GET /resource (Bearer: cached token)").
		DashedArrow("RS", "App", "200 {data}").
		Note("ClientCredentialsSource implements TokenSource: Token() returns a cached token if still valid, or fetches a new one. Multiple goroutines can safely call Token() concurrently.").
		VerbatimLang("Equivalent on the wire", "bash", `# What the SDK does under the hood (first call only — subsequent calls reuse the cached token):
TOKEN=$(curl -s -X POST http://localhost:8081/api/token \
  -d 'grant_type=client_credentials' \
  -d 'client_id=<id>' -d 'client_secret=<secret>' -d 'scope=read' | jq -r .access_token)
curl -s http://localhost:8082/resource -H "Authorization: Bearer $TOKEN" | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			tokenSource = &client.ClientCredentialsSource{
				TokenEndpoint: authServer.URL + "/api/token",
				ClientID:      registeredClientID,
				ClientSecret:  registeredSecret,
				Scopes:        []string{"read"},
			}

			token1, err := tokenSource.Token()
			if err != nil {
				return demokit.Errf("token: %v", err)
			}
			fmt.Printf("    First call:  %s... (fetched)\n", token1[:40])

			token2, _ := tokenSource.Token()
			fmt.Printf("    Second call: %s... (cached)\n", token2[:40])
			fmt.Printf("    Same token:  %v\n", token1 == token2)

			req, _ := http.NewRequest("GET", resourceServer.URL+"/resource", nil)
			req.Header.Set("Authorization", "Bearer "+token1)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return demokit.Errf("resource: %v", err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			fmt.Printf("    Resource:    %d %s\n", res.StatusCode, string(body))
			return nil
		})

	demo.Step("Scope step-up with TokenForScopes").
		Arrow("App", "App", "tokenSource.TokenForScopes([\"write\"])").
		Arrow("App", "AS", "POST /api/token {scope: read write} (merged)").
		DashedArrow("AS", "App", "new token with expanded scopes").
		Note("When your app needs additional permissions, TokenForScopes merges the new scopes with existing ones, invalidates the cache, and fetches a fresh token.").
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			oldToken, _ := tokenSource.Token()
			fmt.Printf("    Before step-up: %s...\n", oldToken[:40])

			newToken, err := tokenSource.TokenForScopes([]string{"write"})
			if err != nil {
				return demokit.Errf("step-up: %v", err)
			}
			fmt.Printf("    After step-up:  %s...\n", newToken[:40])
			fmt.Printf("    Different token: %v (cache was invalidated)\n", oldToken != newToken)
			return nil
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

	demo.Step("Use the SDK against Keycloak (optional)").
		Ref(refs.RFC8414).
		Ref(refs.RFC6749_ClientCredentials).
		Arrow("App", "AS", "client.DiscoverAS(keycloakRealmURL)").
		Arrow("App", "AS", "authClient.ClientCredentialsToken(...)").
		DashedArrow("AS", "App", "ServerCredential from Keycloak").
		Note("Same SDK code, pointed at Keycloak. DiscoverAS finds the KC token endpoint automatically. If KC isn't running, this step is skipped.").
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
				fmt.Printf("    ERROR discovering KC: %v\n", err)
				return nil
			}

			kcClient := client.NewAuthClient(kcRealmURL, nil,
				client.WithASMetadata(kcMeta))
			cred, err := kcClient.ClientCredentialsToken(
				kcExampleClientID, kcExampleClientSecret, []string{"openid"})
			if err != nil {
				fmt.Printf("    ERROR getting KC token: %v\n", err)
				return nil
			}

			fmt.Printf("    KC access_token: %s...\n", cred.AccessToken[:40])
			fmt.Printf("    KC scope:        %s\n", cred.Scope)
			fmt.Printf("    KC expires_at:   %s\n", cred.ExpiresAt.Format(time.RFC3339))
			fmt.Printf("\n    Same SDK code — different server. That's the point.\n")
			return nil
		})

	demo.Section("What's next?",
		"In [08 — Rich Authorization Requests](../08-rich-authorization-requests/),",
		"you'll see how to go beyond flat scopes: request fine-grained permissions",
		"like \"transfer 45 EUR to Merchant A\" using RFC 9396.",
	)

	common.SetupRenderer(demo)
	demo.Execute()

	if tokenSource != nil {
		tokenSource.Close()
	}
}

// postJSON POSTs JSON and returns the decoded response.
func postJSON(url string, body any) map[string]any {
	data, _ := json.Marshal(body)
	resp, _ := http.Post(url, "application/json", bytes.NewReader(data))
	defer resp.Body.Close()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}
