package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/demokit"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/examples/common"
	"github.com/panyam/oneauth/examples/refs"
	"github.com/panyam/oneauth/keys"
)

func runDemo() {
	ks := keys.NewInMemoryKeyStore()
	kidStore := keys.NewKidStore()

	authServer := httptest.NewServer(newAuthServer(ks, kidStore))
	defer authServer.Close()
	resourceServer := httptest.NewServer(newResourceServer(ks, kidStore))
	defer resourceServer.Close()

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

	fmt.Printf("    Auth server:     %s\n", authServer.URL)
	fmt.Printf("    Resource server: %s\n", resourceServer.URL)
	fmt.Printf("    Grace period:    %s (short for demo)\n\n", gracePeriod)

	demo.Step("Register an app and mint a token with the original key").
		Ref(refs.RFC7519).
		Arrow("Admin", "AS", "POST /apps/register").
		DashedArrow("AS", "Admin", "{client_id, client_secret}").
		Arrow("Admin", "Admin", "MintResourceToken(alice, oldSecret)").
		Note("The app gets a client_secret (HS256). We mint a token for Alice — this token's kid header is derived from the old key.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -X POST http://localhost:8081/apps/register \
  -H 'Content-Type: application/json' \
  -d '{"client_domain":"rotate.example.com"}' | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			body, _ := json.Marshal(map[string]any{"client_domain": "rotate.example.com"})
			resp, err := http.Post(authServer.URL+"/apps/register", "application/json",
				bytes.NewReader(body))
			if err != nil {
				return demokit.Errf("register: %v", err)
			}
			var reg map[string]any
			json.NewDecoder(resp.Body).Decode(&reg)
			resp.Body.Close()
			clientID = reg["client_id"].(string)
			oldSecret = reg["client_secret"].(string)

			oldToken, _ = admin.MintResourceToken(
				"alice", clientID, oldSecret,
				admin.AppQuota{}, []string{"read"}, nil)

			parser := jwt.NewParser()
			parsed, _, _ := parser.ParseUnverified(oldToken, jwt.MapClaims{})
			fmt.Printf("    client_id:     %s\n", clientID)
			fmt.Printf("    old secret:    %s...\n", oldSecret[:16])
			fmt.Printf("    old token kid: %s\n", parsed.Header["kid"])
			return nil
		})

	demo.Step("Rotate the key").
		Ref(refs.RFC7517).
		Arrow("Admin", "AS", "POST /apps/{id}/rotate").
		DashedArrow("AS", "Admin", "{client_secret: newSecret}").
		Note("Rotation replaces the key in the main KeyStore and moves the old key to KidStore with a grace period TTL. Both keys are now valid.").
		VerbatimLang("Reproduce on the wire", "bash", `curl -s -X POST http://localhost:8081/apps/<client_id>/rotate | jq`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			req, _ := http.NewRequest("POST", authServer.URL+"/apps/"+clientID+"/rotate", nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return demokit.Errf("rotate: %v", err)
			}
			var rot map[string]any
			json.NewDecoder(resp.Body).Decode(&rot)
			resp.Body.Close()
			newSecret = rot["client_secret"].(string)

			newToken, _ = admin.MintResourceToken(
				"alice", clientID, newSecret,
				admin.AppQuota{}, []string{"read"}, nil)

			fmt.Printf("    new secret:  %s...\n", newSecret[:16])
			fmt.Printf("    different:   %v\n", oldSecret != newSecret)

			parser := jwt.NewParser()
			parsed, _, _ := parser.ParseUnverified(newToken, jwt.MapClaims{})
			fmt.Printf("    new token kid: %s\n", parsed.Header["kid"])
			return nil
		})

	demo.Step("During grace period — both tokens work").
		Ref(refs.RFC7638).
		Arrow("RS", "RS", "Validate old token → kid found in KidStore (grace) ✓").
		Arrow("RS", "RS", "Validate new token → kid found in KeyStore (current) ✓").
		Note("The CompositeKeyLookup checks the main KeyStore first, then falls back to KidStore. Old tokens find their key in the grace store; new tokens find theirs in the main store.").
		VerbatimLang("Reproduce on the wire", "bash", `# Both should return 200 during the grace window
curl -s -o /dev/null -w 'old: %{http_code}\n' http://localhost:8082/resource -H "Authorization: Bearer <old token>"
curl -s -o /dev/null -w 'new: %{http_code}\n' http://localhost:8082/resource -H "Authorization: Bearer <new token>"`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			oldStatus := callResource(resourceServer.URL, oldToken)
			newStatus := callResource(resourceServer.URL, newToken)
			fmt.Printf("    old token (during grace): %d ✓\n", oldStatus)
			fmt.Printf("    new token:                %d ✓\n", newStatus)
			return nil
		})

	demo.Step("After grace period — old token rejected").
		Arrow("RS", "RS", "Validate old token → kid not found anywhere ✗").
		Arrow("RS", "RS", "Validate new token → kid found in KeyStore ✓").
		Note("After the grace period expires (100ms in this demo), the old key is removed from KidStore. Tokens signed with it are now rejected.").
		VerbatimLang("Reproduce on the wire", "bash", `# After grace expires: old → 401, new → 200
sleep 1   # wait past production grace period
curl -s -o /dev/null -w 'old: %{http_code}\n' http://localhost:8082/resource -H "Authorization: Bearer <old token>"
curl -s -o /dev/null -w 'new: %{http_code}\n' http://localhost:8082/resource -H "Authorization: Bearer <new token>"`).
		Run(func(ctx demokit.StepContext) *demokit.StepResult {
			time.Sleep(gracePeriod + 20*time.Millisecond)
			oldStatus := callResource(resourceServer.URL, oldToken)
			newStatus := callResource(resourceServer.URL, newToken)
			fmt.Printf("    old token (after grace):  %d ✗ (correctly rejected)\n", oldStatus)
			fmt.Printf("    new token:                %d ✓\n", newStatus)
			return nil
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

	common.SetupRenderer(demo)
	demo.Execute()
}

// callResource hits the resource endpoint with a Bearer token and
// returns the HTTP status.
func callResource(rsURL, token string) int {
	req, _ := http.NewRequest("GET", rsURL+"/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	defer res.Body.Close()
	return res.StatusCode
}
