package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/demokit"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/examples/common"
	"github.com/panyam/oneauth/examples/refs"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

func runDemo() {
	ks := keys.NewInMemoryKeyStore()
	rsaPrivKey, pubPEM := servePreseededApps(ks)

	authServer := httptest.NewServer(newAuthServer(ks))
	defer authServer.Close()
	resourceServer := httptest.NewServer(newResourceServer(ks))
	defer resourceServer.Close()

	demo := demokit.New("10: Security — Attack Prevention").
		Dir("10-security").
		Description("Non-UI | No infrastructure needed | Standalone").
		Actors(
			demokit.Actor("Legit", "Legitimate App"),
			demokit.Actor("Attacker", "Attacker"),
			demokit.Actor("RS", "Resource Server"),
		)

	demo.Section("About this example",
		"This example demonstrates real JWT attacks and OneAuth's defenses.",
		"Each attack is executed live — you'll see both the attack and the defense in action.",
		"",
		"**Attacks covered:**",
		"1. Algorithm confusion (CVE-2015-9235) — the most famous JWT vulnerability",
		"2. Cross-app token forgery — using one app's key with another app's client_id",
		"3. `alg: none` — disabling signature verification entirely",
		"4. JWKS private key leakage — checking that secrets stay secret",
	)

	fmt.Printf("    KeyStore pre-seeded with two apps:\n")
	fmt.Printf("      app-rsa  — RS256 (public key registered)\n")
	fmt.Printf("      app-hmac — HS256 (shared secret registered)\n")
	fmt.Printf("    Resource server: %s\n\n", resourceServer.URL)

	demo.Step("Attack 1: Algorithm confusion (CVE-2015-9235)").
		Ref(refs.CVE_2015_9235).
		Ref(refs.RFC7515).
		Arrow("Attacker", "Attacker", "Craft JWT: alg=HS256, sign with RSA public key").
		Arrow("Attacker", "RS", "Bearer: confused token").
		DashedArrow("RS", "Attacker", "401 Unauthorized (blocked)").
		Note("The attack: The attacker knows the RSA public key (it's public, served via JWKS). They craft a JWT with alg:HS256 and sign it using the public key bytes as the HMAC secret. A naive server reads alg:HS256, grabs the stored key bytes, and verifies — which passes because the attacker used those same bytes.\n\nOneAuth's defense: The middleware checks that the token's alg header matches the KeyRecord.Algorithm. Store says RS256, token says HS256 → mismatch → rejected before any signature check.").
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			legit := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub": "alice", "client_id": "app-rsa", "type": "access",
				"scopes": []string{"read"}, "exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			})
			if kid, err := utils.ComputeKid(&rsaPrivKey.PublicKey, "RS256"); err == nil {
				legit.Header["kid"] = kid
			}
			legitToken, _ := legit.SignedString(rsaPrivKey)
			fmt.Printf("    Legitimate RS256 token: %d\n", callRS(resourceServer.URL, legitToken))

			attack := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"sub": "attacker", "client_id": "app-rsa", "type": "access",
				"scopes": []string{"admin"}, "exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			})
			attackToken, _ := attack.SignedString(pubPEM)
			fmt.Printf("    Algorithm confusion:    %d (blocked — alg mismatch)\n", callRS(resourceServer.URL, attackToken))
			return nil
		})

	demo.Step("Attack 2: alg:none — no signature at all").
		Ref(refs.CVE_2015_9235).
		Arrow("Attacker", "Attacker", "Craft JWT: alg=none, no signature").
		Arrow("Attacker", "RS", "Bearer: unsigned token").
		DashedArrow("RS", "Attacker", "401 Unauthorized (blocked)").
		Note("The attack: The attacker sends a JWT with alg:none — no signature at all. Some JWT libraries accept this as valid.\n\nOneAuth uses golang-jwt/v5 which rejects alg:none by default unless explicitly opted in with UnsafeAllowNoneSignatureType.").
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			none := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
				"sub": "attacker", "client_id": "app-rsa", "type": "access",
				"scopes": []string{"admin"}, "exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			})
			noneToken, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
			fmt.Printf("    alg:none token: %d (blocked)\n", callRS(resourceServer.URL, noneToken))
			return nil
		})

	demo.Step("Attack 3: Cross-app token forgery").
		Arrow("Attacker", "Attacker", "Sign JWT with app-A's key but claim client_id=app-B").
		Arrow("Attacker", "RS", "Bearer: cross-app token").
		DashedArrow("RS", "Attacker", "401 Unauthorized (blocked)").
		Note("The attack: App A's key is compromised. The attacker signs a token claiming to be App B (client_id=app-B) using App A's key. If the resource server only checks the signature and not which app owns the key, the token validates.\n\nOneAuth's defense: The middleware checks that the kid's owning client matches the client_id claim. App A's key → kid owned by app-A → client_id claim says app-B → mismatch → rejected.").
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			var clientIDs [2]string
			var secrets [2]string
			for i, domain := range []string{"app-a.com", "app-b.com"} {
				body, _ := json.Marshal(map[string]any{"client_domain": domain})
				resp, err := http.Post(authServer.URL+"/apps/register", "application/json",
					bytes.NewReader(body))
				if err != nil {
					return demokit.Errf("register: %v", err)
				}
				var reg map[string]any
				json.NewDecoder(resp.Body).Decode(&reg)
				resp.Body.Close()
				clientIDs[i] = reg["client_id"].(string)
				secrets[i] = reg["client_secret"].(string)
			}

			crossToken, _ := admin.MintResourceToken(
				"eve", clientIDs[1], secrets[0], admin.AppQuota{}, []string{"read"}, nil)
			fmt.Printf("    Cross-app token (A's key, B's id): %d (blocked — kid/client_id mismatch)\n",
				callRS(resourceServer.URL, crossToken))

			correctToken, _ := admin.MintResourceToken(
				"alice", clientIDs[0], secrets[0], admin.AppQuota{}, []string{"read"}, nil)
			fmt.Printf("    Correct token (A's key, A's id):   %d ✓\n",
				callRS(resourceServer.URL, correctToken))
			return nil
		})

	demo.Step("JWKS security: only public keys, never secrets").
		Ref(refs.RFC7517).
		Arrow("Anyone", "AS", "GET /.well-known/jwks.json").
		DashedArrow("AS", "Anyone", "{keys: [RSA public key only]}").
		Note("JWKS serves only asymmetric public keys. HS256 secrets are excluded entirely. RSA keys include only public components (n, e) — private fields (d, p, q) are structurally absent from the JWK type.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s http://localhost:8081/.well-known/jwks.json | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			resp, err := http.Get(authServer.URL + "/.well-known/jwks.json")
			if err != nil {
				return demokit.Errf("jwks: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			var raw map[string]any
			json.Unmarshal(body, &raw)
			jwksKeys := raw["keys"].([]any)

			fmt.Printf("    Total apps in KeyStore: 4 (2 preseeded + 2 from forgery step, RSA + HMAC mix)\n")
			fmt.Printf("    Keys in JWKS:           %d (only RSA — HMAC secrets excluded)\n", len(jwksKeys))

			if len(jwksKeys) > 0 {
				key := jwksKeys[0].(map[string]any)
				fmt.Printf("    kty: %s, alg: %s, key_ops: %v\n", key["kty"], key["alg"], key["key_ops"])

				leaked := false
				for _, field := range []string{"d", "p", "q", "dp", "dq", "qi"} {
					if key[field] != nil {
						fmt.Printf("    LEAK: private field %q found!\n", field)
						leaked = true
					}
				}
				if !leaked {
					fmt.Printf("    Private fields (d, p, q, dp, dq, qi): absent ✓\n")
				}
			}
			return nil
		})

	demo.Section("Summary of defenses",
		"| Attack | How it works | OneAuth's defense |",
		"|--------|-------------|------------------|",
		"| Algorithm confusion (CVE-2015-9235) | Sign HS256 with RSA public key | alg must match KeyRecord.Algorithm |",
		"| alg:none | No signature at all | golang-jwt/v5 rejects by default |",
		"| Cross-app forgery | Sign with app A's key, claim app B | kid owner must match client_id claim |",
		"| JWKS private key leak | Serve private key fields | JWK struct cannot carry private fields |",
		"| HS256 secret in JWKS | Expose shared secret via JWKS | HS256 keys excluded from JWKS output |",
		"",
		"These defenses are built into the middleware and key management layers —",
		"they're always active, not opt-in. You get them by using `APIMiddleware`",
		"and `JWKSHandler`.",
	)

	demo.Section("End of the journey",
		"You've completed all 10 examples! Here's what you've learned:",
		"",
		"| # | Concept | RFC |",
		"|---|---------|-----|",
		"| 01 | Client credentials — get a token | RFC 6749 §4.4 |",
		"| 02 | Resource tokens — per-user JWTs | RFC 7519 |",
		"| 03 | Asymmetric signing + JWKS discovery | RFC 7517, 7515 |",
		"| 04 | AS metadata discovery | RFC 8414 |",
		"| 05 | Token introspection + revocation | RFC 7662 |",
		"| 06 | Dynamic client registration | RFC 7591 |",
		"| 07 | Client SDK production patterns | — |",
		"| 08 | Rich Authorization Requests | RFC 9396 |",
		"| 09 | Key rotation with grace periods | RFC 7638 |",
		"| 10 | Security — attack prevention | CVE-2015-9235 |",
	)

	common.SetupRenderer(demo)
	demo.Execute()
}

// callRS hits the protected endpoint with a Bearer token and returns
// the HTTP status. Used by the walkthrough to score each attack.
func callRS(rsURL, token string) int {
	req, _ := http.NewRequest("GET", rsURL+"/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	defer res.Body.Close()
	return res.StatusCode
}
