// Example 09: Key Rotation with Grace Periods
//
// In production, signing keys need to be rotated periodically. But you can't
// just swap keys — existing tokens signed with the old key would break. OneAuth
// solves this with a grace period: old keys stay valid for a window after
// rotation, then expire.
//
// Run:   go run ./examples/09-key-rotation/
// Docs:  Run with --readme to regenerate README.md
//
// See: https://www.rfc-editor.org/rfc/rfc7517 (JWK)
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/demokit"
	"github.com/panyam/oneauth/examples/refs"
	"github.com/panyam/oneauth/keys"
)

func main() {
	var regHandler http.Handler
	var ks keys.KeyStorage
	var kidStore *keys.KidStore
	var middleware *apiauth.APIMiddleware
	var clientID, oldSecret, newSecret string
	var oldToken, newToken string

	demo := demokit.New("09: Key Rotation with Grace Periods").
		Dir("09-key-rotation").
		Description("Non-UI | No infrastructure needed | Builds on Example 02").
		Actors(
			demokit.Actor("Admin", "Admin"),
			demokit.Actor("AS", "Auth Server"),
			demokit.Actor("RS", "Resource Server"),
		)

	demo.Section("About this example",
		"**Actors:** Admin, Auth Server (AS), Resource Server (RS).",
		"Think: Slack rotates its signing keys — existing bot tokens must keep working during the transition.",
		"[What are these?](../README.md#cast-of-characters)",
		"",
		"**The problem:** You rotate an app's signing key. Tokens signed with the old",
		"key are still in flight — users have them cached, they haven't expired yet.",
		"If the resource server only knows the new key, those tokens break.",
		"",
		"**The solution:** A grace period. After rotation, the old key stays valid for",
		"a configurable window. Both old and new tokens work. After the grace period,",
		"old tokens are rejected.",
		"",
		"```",
		"Time: ──────────────────────────────────────────────────►",
		"       ┌─── old key valid ───┐",
		"       │                     │ ← grace period",
		"       ├─── rotation ────────┤",
		"       │                     ├─── new key valid ──────►",
		"       │  both keys work     │  only new key works",
		"```",
	)

	// --- Setup ---
	demo.Step("Set up auth server with key rotation support").
		Ref(refs.RFC7517).
		Ref(refs.RFC7638).
		Note("The auth server uses a KidStore alongside the main KeyStore. On rotation, the old key moves to KidStore with a grace period TTL. The CompositeKeyLookup checks both.").
		Run(func() {
			ks = keys.NewInMemoryKeyStore()
			kidStore = keys.NewKidStore()

			registrar := admin.NewAppRegistrar(ks, admin.NewNoAuth())
			registrar.KidStore = kidStore
			registrar.DefaultGracePeriod = 100 * time.Millisecond // short for demo
			regHandler = registrar.Handler()

			// CompositeKeyLookup: check current keys first, then grace period keys
			composite := &keys.CompositeKeyLookup{
				Lookups: []keys.KeyLookup{ks, kidStore},
			}
			middleware = &apiauth.APIMiddleware{KeyStore: composite}

			fmt.Printf("    KeyStore:     in-memory (current keys)\n")
			fmt.Printf("    KidStore:     in-memory (grace period keys)\n")
			fmt.Printf("    Grace period: 100ms (short for demo)\n")
		})

	// --- Register and mint ---
	demo.Step("Register an app and mint a token with the original key").
		Ref(refs.RFC7519).
		Arrow("Admin", "AS", "POST /apps/register").
		DashedArrow("AS", "Admin", "{client_id, client_secret}").
		Arrow("Admin", "Admin", "MintResourceToken(alice, oldSecret)").
		Note("The app gets a client_secret (HS256). We mint a token for Alice — this token's kid header is derived from the old key.").
		Run(func() {
			body, _ := json.Marshal(map[string]any{"client_domain": "rotate.example.com"})
			req := httptest.NewRequest("POST", "/apps/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			regHandler.ServeHTTP(rr, req)

			var reg map[string]any
			json.NewDecoder(rr.Body).Decode(&reg)
			clientID = reg["client_id"].(string)
			oldSecret = reg["client_secret"].(string)

			oldToken, _ = admin.MintResourceToken(
				"alice", clientID, oldSecret,
				admin.AppQuota{}, []string{"read"}, nil)

			// Show the kid
			parser := jwt.NewParser()
			parsed, _, _ := parser.ParseUnverified(oldToken, jwt.MapClaims{})
			fmt.Printf("    client_id:   %s\n", clientID)
			fmt.Printf("    old secret:  %s...\n", oldSecret[:16])
			fmt.Printf("    old token kid: %s\n", parsed.Header["kid"])
		})

	// --- Rotate ---
	demo.Step("Rotate the key").
		Ref(refs.RFC7517).
		Arrow("Admin", "AS", "POST /apps/{id}/rotate").
		DashedArrow("AS", "Admin", "{client_secret: newSecret}").
		Note("Rotation replaces the key in the main KeyStore and moves the old key to KidStore with a grace period TTL. Both keys are now valid.").
		Run(func() {
			req := httptest.NewRequest("POST", "/apps/"+clientID+"/rotate", nil)
			rr := httptest.NewRecorder()
			regHandler.ServeHTTP(rr, req)

			var rot map[string]any
			json.NewDecoder(rr.Body).Decode(&rot)
			newSecret = rot["client_secret"].(string)

			newToken, _ = admin.MintResourceToken(
				"alice", clientID, newSecret,
				admin.AppQuota{}, []string{"read"}, nil)

			fmt.Printf("    new secret:  %s...\n", newSecret[:16])
			fmt.Printf("    different:   %v\n", oldSecret != newSecret)

			parser := jwt.NewParser()
			parsed, _, _ := parser.ParseUnverified(newToken, jwt.MapClaims{})
			fmt.Printf("    new token kid: %s\n", parsed.Header["kid"])
		})

	// --- During grace period ---
	demo.Step("During grace period — both tokens work").
		Ref(refs.RFC7638).
		Arrow("RS", "RS", "Validate old token → kid found in KidStore (grace) ✓").
		Arrow("RS", "RS", "Validate new token → kid found in KeyStore (current) ✓").
		Note("The CompositeKeyLookup checks the main KeyStore first, then falls back to KidStore. Old tokens find their key in the grace store; new tokens find theirs in the main store.").
		Run(func() {
			handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			oldResult := validateToken(handler, oldToken)
			newResult := validateToken(handler, newToken)

			fmt.Printf("    old token (during grace): %d ✓\n", oldResult)
			fmt.Printf("    new token:                %d ✓\n", newResult)
		})

	// --- After grace period ---
	demo.Step("After grace period — old token rejected").
		Arrow("RS", "RS", "Validate old token → kid not found anywhere ✗").
		Arrow("RS", "RS", "Validate new token → kid found in KeyStore ✓").
		Note("After the grace period expires (100ms in this demo), the old key is removed from KidStore. Tokens signed with it are now rejected.").
		Run(func() {
			// Wait for grace period to expire
			time.Sleep(120 * time.Millisecond)

			handler := middleware.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			oldResult := validateToken(handler, oldToken)
			newResult := validateToken(handler, newToken)

			fmt.Printf("    old token (after grace):  %d ✗ (correctly rejected)\n", oldResult)
			fmt.Printf("    new token:                %d ✓\n", newResult)
		})

	demo.Section("How it works under the hood",
		"```",
		"CompositeKeyLookup",
		"  ├── KeyStore (current keys)     ← new key lives here",
		"  └── KidStore (grace period)     ← old key lives here temporarily",
		"",
		"Token arrives with kid header:",
		"  1. Check KeyStore by kid → found? validate with that key",
		"  2. Not found → check KidStore by kid → found and not expired? validate",
		"  3. Not found anywhere → reject",
		"```",
		"",
		"The kid (Key ID) in the JWT header is a RFC 7638 thumbprint of the signing",
		"key. Each key has a unique kid, so the lookup is deterministic — there's no",
		"ambiguity about which key to use for verification.",
	)

	demo.Section("What's next?",
		"In [10 — Security](../10-security/), you'll see attack prevention:",
		"algorithm confusion (CVE-2015-9235), cross-app token forgery, and",
		"JWKS security properties.",
	)

	demo.Execute()
}

// validateToken runs a token through the middleware and returns the HTTP status.
func validateToken(handler http.Handler, token string) int {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rr, req)
	return rr.Code
}
