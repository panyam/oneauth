// Example 10: Security — Attack Prevention
//
// This example demonstrates real attacks against JWT-based auth systems and
// how OneAuth prevents them. Each step shows the attack, why it works against
// naive implementations, and how OneAuth's defenses block it.
//
// Run:   go run ./examples/10-security/
// Docs:  Run with --readme to regenerate README.md
//
// See: https://nvd.nist.gov/vuln/detail/CVE-2015-9235 (algorithm confusion)
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/demokit"
	"github.com/panyam/oneauth/examples/refs"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

func main() {
	var ks *keys.InMemoryKeyStore
	var middleware *apiauth.APIMiddleware
	var rsaPrivKey *rsa.PrivateKey
	var pubPEM []byte

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

	// --- Setup ---
	demo.Step("Set up KeyStore with an RS256 app and an HS256 app").
		Ref(refs.RFC7517).
		Note("Two apps coexist: one with an RSA key pair (RS256), one with a shared secret (HS256). The resource server validates tokens from both.").
		Run(func() {
			ks = keys.NewInMemoryKeyStore()

			// RS256 app
			rsaPrivKey, _ = rsa.GenerateKey(rand.Reader, 2048)
			pubPEM, _ = utils.EncodePublicKeyPEM(&rsaPrivKey.PublicKey)
			ks.RegisterKey("app-rsa", pubPEM, "RS256")

			// HS256 app
			ks.RegisterKey("app-hmac", []byte("shared-secret-for-hs256-app"), "HS256")

			middleware = &apiauth.APIMiddleware{KeyStore: ks}

			fmt.Printf("    app-rsa:  RS256 (public key registered)\n")
			fmt.Printf("    app-hmac: HS256 (shared secret registered)\n")
		})

	// --- Attack 1: Algorithm confusion ---
	demo.Step("Attack 1: Algorithm confusion (CVE-2015-9235)").
		Ref(refs.CVE_2015_9235).
		Ref(refs.RFC7515).
		Arrow("Attacker", "Attacker", "Craft JWT: alg=HS256, sign with RSA public key").
		Arrow("Attacker", "RS", "Bearer: confused token").
		DashedArrow("RS", "Attacker", "401 Unauthorized (blocked)").
		Note("The attack: The attacker knows the RSA public key (it's public, served via JWKS). They craft a JWT with alg:HS256 and sign it using the public key bytes as the HMAC secret. A naive server reads alg:HS256, grabs the stored key bytes, and verifies — which passes because the attacker used those same bytes.\n\nOneAuth's defense: The middleware checks that the token's alg header matches the KeyRecord.Algorithm. Store says RS256, token says HS256 → mismatch → rejected before any signature check.").
		Run(func() {
			handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			// Legitimate RS256 token
			legit := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub": "alice", "client_id": "app-rsa", "type": "access",
				"scopes": []string{"read"}, "exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			})
			if kid, err := utils.ComputeKid(&rsaPrivKey.PublicKey, "RS256"); err == nil {
				legit.Header["kid"] = kid
			}
			legitToken, _ := legit.SignedString(rsaPrivKey)
			fmt.Printf("    Legitimate RS256 token: %d\n", validateToken(handler, legitToken))

			// Algorithm confusion: sign with public key as HMAC secret
			attack := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"sub": "attacker", "client_id": "app-rsa", "type": "access",
				"scopes": []string{"admin"}, "exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			})
			attackToken, _ := attack.SignedString(pubPEM) // public key as HMAC secret!
			fmt.Printf("    Algorithm confusion:    %d (blocked — alg mismatch)\n", validateToken(handler, attackToken))
		})

	// --- Attack 2: alg:none ---
	demo.Step("Attack 2: alg:none — no signature at all").
		Ref(refs.CVE_2015_9235).
		Arrow("Attacker", "Attacker", "Craft JWT: alg=none, no signature").
		Arrow("Attacker", "RS", "Bearer: unsigned token").
		DashedArrow("RS", "Attacker", "401 Unauthorized (blocked)").
		Note("The attack: The attacker sends a JWT with alg:none — no signature at all. Some JWT libraries accept this as valid.\n\nOneAuth uses golang-jwt/v5 which rejects alg:none by default unless explicitly opted in with UnsafeAllowNoneSignatureType.").
		Run(func() {
			handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			none := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
				"sub": "attacker", "client_id": "app-rsa", "type": "access",
				"scopes": []string{"admin"}, "exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			})
			noneToken, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
			fmt.Printf("    alg:none token: %d (blocked)\n", validateToken(handler, noneToken))
		})

	// --- Attack 3: Cross-app forgery ---
	demo.Step("Attack 3: Cross-app token forgery").
		Arrow("Attacker", "Attacker", "Sign JWT with app-A's key but claim client_id=app-B").
		Arrow("Attacker", "RS", "Bearer: cross-app token").
		DashedArrow("RS", "Attacker", "401 Unauthorized (blocked)").
		Note("The attack: App A's key is compromised. The attacker signs a token claiming to be App B (client_id=app-B) using App A's key. If the resource server only checks the signature and not which app owns the key, the token validates.\n\nOneAuth's defense: The middleware checks that the kid's owning client matches the client_id claim. App A's key → kid owned by app-A → client_id claim says app-B → mismatch → rejected.").
		Run(func() {
			// Register two apps
			registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
			regHandler := registrar.Handler()

			var clientIDs [2]string
			var secrets [2]string
			for i, domain := range []string{"app-a.com", "app-b.com"} {
				body, _ := json.Marshal(map[string]any{"client_domain": domain})
				req := httptest.NewRequest("POST", "/apps/register", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()
				regHandler.ServeHTTP(rr, req)
				var resp map[string]any
				json.NewDecoder(rr.Body).Decode(&resp)
				clientIDs[i] = resp["client_id"].(string)
				secrets[i] = resp["client_secret"].(string)
			}

			handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			// Cross-app: sign with app A's secret, claim app B's client_id
			crossToken, _ := admin.MintResourceToken(
				"eve", clientIDs[1], secrets[0], admin.AppQuota{}, []string{"read"}, nil)
			fmt.Printf("    Cross-app token (A's key, B's id): %d (blocked — kid/client_id mismatch)\n",
				validateToken(handler, crossToken))

			// Correct: app A's secret with app A's client_id
			correctToken, _ := admin.MintResourceToken(
				"alice", clientIDs[0], secrets[0], admin.AppQuota{}, []string{"read"}, nil)
			fmt.Printf("    Correct token (A's key, A's id):   %d ✓\n",
				validateToken(handler, correctToken))
		})

	// --- JWKS security ---
	demo.Step("JWKS security: only public keys, never secrets").
		Ref(refs.RFC7517).
		Arrow("Anyone", "AS", "GET /.well-known/jwks.json").
		DashedArrow("AS", "Anyone", "{keys: [RSA public key only]}").
		Note("JWKS serves only asymmetric public keys. HS256 secrets are excluded entirely. RSA keys include only public components (n, e) — private fields (d, p, q) are structurally absent from the JWK type.").
		Run(func() {
			jwksHandler := &keys.JWKSHandler{KeyStore: ks}
			srv := httptest.NewServer(http.HandlerFunc(jwksHandler.ServeHTTP))
			defer srv.Close()

			resp, _ := http.Get(srv.URL)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			var raw map[string]any
			json.Unmarshal(body, &raw)
			jwksKeys := raw["keys"].([]any)

			fmt.Printf("    Total apps in KeyStore: 2 (RSA + HMAC)\n")
			fmt.Printf("    Keys in JWKS:           %d (only RSA — HMAC secret excluded)\n", len(jwksKeys))

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

	demo.Execute()
}

func validateToken(handler http.Handler, token string) int {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rr, req)
	return rr.Code
}
