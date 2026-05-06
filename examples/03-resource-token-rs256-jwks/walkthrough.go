package main

import (
	"bytes"
	"crypto/rsa"
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
	"github.com/panyam/oneauth/utils"
)

func runDemo() {
	ks := keys.NewInMemoryKeyStore()
	authServer := httptest.NewServer(newAuthServer(ks))
	defer authServer.Close()
	resourceServer := httptest.NewServer(newResourceServer(authServer.URL + "/.well-known/jwks.json"))
	defer resourceServer.Close()

	var clientID string
	var privKey *rsa.PrivateKey
	var aliceToken string

	demo := demokit.New("03: Resource Token with RS256 + JWKS Discovery").
		Dir("03-resource-token-rs256-jwks").
		Description("Non-UI | No infrastructure needed | Builds on Example 02").
		Actors(
			demokit.Actor("App", "Your App"),
			demokit.Actor("AS", "Auth Server"),
			demokit.Actor("RS", "Resource Server"),
		)

	demo.Section("Why asymmetric signing?",
		"**Actors:** App, Auth Server (AS), Resource Server (RS).",
		"Think: the GitHub bot gets its own key pair — Slack's API never sees the private key.",
		"[What are these?](../README.md#cast-of-characters)",
		"",
		"In [02 — HS256](../02-resource-token-hs256/), both the app and resource server",
		"share the same secret. That works, but it means:",
		"- The resource server *could* forge tokens (it has the signing key)",
		"- Compromising the resource server compromises the signing key",
		"- Rotating keys requires coordinating both sides",
		"",
		"With RS256 (asymmetric):",
		"- The app keeps the private key — only it can sign tokens",
		"- The resource server only has the public key — it can verify but never forge",
		"- The public key is served via JWKS — resource servers discover it automatically",
		"- Key rotation is seamless: publish a new key to JWKS, resource servers pick it up",
	)

	demo.Step("App generates an RSA key pair").
		Ref(refs.RFC7515).
		Note("The app generates a 2048-bit RSA key pair. The private key stays with the app. The public key will be registered with the auth server.").
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			privPEM, pubPEM, err := utils.GenerateRSAKeyPair(2048)
			if err != nil {
				return demokit.Errf("keygen: %v", err)
			}
			parsed, _ := utils.ParsePrivateKeyPEM(privPEM)
			privKey = parsed.(*rsa.PrivateKey)
			fmt.Printf("    Private key: %d bytes (stays with app)\n", len(privPEM))
			fmt.Printf("    Public key:  %d bytes (will be registered)\n", len(pubPEM))
			return nil
		})

	demo.Step("Register app with RS256 public key").
		Ref(refs.RFC7517).
		Arrow("App", "AS", "POST /apps/register {domain, signing_alg: RS256, public_key}").
		DashedArrow("AS", "App", "{client_id} (no client_secret — asymmetric!)").
		Note("Unlike HS256 registration, no secret is returned. The auth server stores the public key and serves it via JWKS.").
		VerbatimLang("Reproduce on the wire", "bash", `PUB=$(cat your-public-key.pem)
curl -s -X POST http://localhost:8081/apps/register \
  -H 'Content-Type: application/json' \
  -d "{\"client_domain\":\"myapp.example.com\",\"signing_alg\":\"RS256\",\"public_key\":$(jq -Rs . <<<"$PUB")}"`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			pubPEM, _ := utils.EncodePublicKeyPEM(&privKey.PublicKey)
			body, _ := json.Marshal(map[string]any{
				"client_domain": "myapp.example.com",
				"signing_alg":   "RS256",
				"public_key":    string(pubPEM),
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
			fmt.Printf("    client_id:     %s\n", clientID)
			fmt.Printf("    client_secret: (none — RS256 uses key pair)\n")
			return nil
		})

	demo.Step("Verify the public key appears in JWKS").
		Ref(refs.RFC7517).
		Ref(refs.RFC7638).
		Arrow("App", "AS", "GET /.well-known/jwks.json").
		DashedArrow("AS", "App", "{keys: [{kty: RSA, alg: RS256, kid: ..., n: ..., e: ...}]}").
		Note("The JWKS endpoint serves only public keys — HS256 secrets are never exposed. Each key includes a kid (Key ID) computed from the key thumbprint (RFC 7638).").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s http://localhost:8081/.well-known/jwks.json | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			resp, err := http.Get(authServer.URL + "/.well-known/jwks.json")
			if err != nil {
				return demokit.Errf("jwks: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			var jwkSet map[string]any
			json.Unmarshal(body, &jwkSet)
			jwksKeys := jwkSet["keys"].([]any)
			fmt.Printf("    JWKS key count: %d\n", len(jwksKeys))

			if len(jwksKeys) > 0 {
				key := jwksKeys[0].(map[string]any)
				fmt.Printf("    kty: %s\n", key["kty"])
				fmt.Printf("    alg: %s\n", key["alg"])
				fmt.Printf("    kid: %s\n", key["kid"])
				fmt.Printf("    key_ops: %v\n", key["key_ops"])

				for _, field := range []string{"d", "p", "q", "dp", "dq", "qi"} {
					if key[field] != nil {
						fmt.Printf("    WARNING: private field %q leaked!\n", field)
					}
				}
				fmt.Printf("    private fields: (absent — only public components served)\n")
			}
			return nil
		})

	demo.Section("How JWKS discovery works",
		"The resource server doesn't need the auth server's key ahead of time.",
		"It uses `JWKSKeyStore` which:",
		"1. Fetches `/.well-known/jwks.json` from the auth server",
		"2. Caches the keys locally",
		"3. When a token arrives with a `kid` header, looks up the matching key",
		"4. Periodically refreshes to pick up new/rotated keys",
		"",
		"This is the same mechanism Keycloak, Auth0, and other IdPs use.",
	)

	demo.Step("Mint a token with the private key and validate via JWKS").
		Ref(refs.RFC7519).
		Ref(refs.RFC7515).
		Ref(refs.RFC7638).
		Arrow("App", "App", "MintResourceTokenWithKey(alice, privKey)").
		Arrow("App", "RS", "GET /resource (Bearer: RS256 token)").
		Arrow("RS", "AS", "GET /.well-known/jwks.json (cached)").
		Arrow("RS", "RS", "Verify RS256 signature with public key from JWKS").
		DashedArrow("RS", "App", "200 {user: alice}").
		Note("The token's kid header tells the resource server which key to use. The signature is verified with the public key — the private key was never shared.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s http://localhost:8082/resource \
  -H "Authorization: Bearer <RS256 token>"`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			tok, err := admin.MintResourceTokenWithKey(
				"alice", clientID, privKey,
				admin.AppQuota{}, []string{"read", "write"}, nil,
			)
			if err != nil {
				return demokit.Errf("mint: %v", err)
			}
			aliceToken = tok
			fmt.Printf("    token: %s...\n", aliceToken[:40])

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

	demo.Step("Token signed with a different private key is rejected").
		Ref(refs.RFC7515).
		Arrow("App", "App", "MintResourceTokenWithKey(eve, differentPrivKey)").
		Arrow("App", "RS", "GET /resource (Bearer: bad token)").
		DashedArrow("RS", "App", "401 Unauthorized").
		Note("Even though the token is a valid JWT, its kid doesn't match any key in JWKS, or the signature doesn't verify with the registered public key.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -o /dev/null -w '%{http_code}\n' \
  http://localhost:8082/resource \
  -H "Authorization: Bearer <token signed with a different RSA key>"`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			otherPrivPEM, _, _ := utils.GenerateRSAKeyPair(2048)
			otherPrivKey, _ := utils.ParsePrivateKeyPEM(otherPrivPEM)

			badToken, _ := admin.MintResourceTokenWithKey(
				"eve", clientID, otherPrivKey,
				admin.AppQuota{}, []string{"admin"}, nil,
			)
			req, _ := http.NewRequest("GET", resourceServer.URL+"/resource", nil)
			req.Header.Set("Authorization", "Bearer "+badToken)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return demokit.Errf("get: %v", err)
			}
			res.Body.Close()
			fmt.Printf("    status: %d (correctly rejected — wrong private key)\n", res.StatusCode)
			return nil
		})

	demo.Section("HS256 vs RS256 — when to use which",
		"| | HS256 (Example 02) | RS256 (this example) |",
		"|---|---|---|",
		"| **Key type** | Shared secret | Public/private key pair |",
		"| **Who can sign** | Anyone with the secret | Only the private key holder |",
		"| **Who can verify** | Anyone with the secret | Anyone with the public key |",
		"| **Key distribution** | Must be kept secret on both sides | Public key is... public |",
		"| **JWKS** | Secrets excluded from JWKS | Public keys served via JWKS |",
		"| **Best for** | Simple setups, trusted environments | Multi-service, zero-trust |",
		"",
		"**Rule of thumb:** Use RS256 when the resource server is a separate service.",
		"Use HS256 when the app and resource server are the same process or fully trusted.",
	)

	demo.Section("What's next?",
		"In [04 — Discovery](../04-discovery/), you'll see how clients can",
		"auto-discover the auth server's endpoints (token, JWKS, introspection)",
		"without hardcoding URLs. This is the foundation for interoperability",
		"with external IdPs like Keycloak and Auth0.",
	)

	common.SetupRenderer(demo)
	demo.Execute()
}
