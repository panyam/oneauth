// Package fapi2 sets up and runs the OpenID Foundation's FAPI 2.0 Security
// Profile plan (fapi2-security-profile-final-test-plan) against
// cmd/oneauth-server. It is the FAPI 2.0 mission's exercise (issue 98,
// issue 433): register the clients the plan needs, build the plan config,
// run every module, and report each module's result.
//
// The plan config here is pure (PlanConfig, BrowserAutomation, ...); the
// network side is in run.go.
package fapi2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// PlanName is the harness plan this exercise runs.
const PlanName = "fapi2-security-profile-final-test-plan"

// ClientKey is an ES256 key pair for one test client. ES256 is the only
// FAPI 2.0 algorithm oneauth can register a client key for (#330, #331).
type ClientKey struct {
	Private *ecdsa.PrivateKey
	KeyID   string
}

// NewClientKey generates a P-256 key with an RFC 7638 thumbprint as its kid.
func NewClientKey() (ClientKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ClientKey{}, err
	}
	k := ClientKey{Private: priv}
	k.KeyID = thumbprint(priv)
	return k, nil
}

// PublicJWK is the key's public half, as DCR registers it.
func (k ClientKey) PublicJWK() map[string]string {
	return map[string]string{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": k.KeyID,
		"x": b64(k.Private.X, 32), "y": b64(k.Private.Y, 32),
	}
}

// PrivateJWK adds `d`: the harness signs the client's assertions and DPoP
// proofs itself, so the plan config carries the private key.
func (k ClientKey) PrivateJWK() map[string]string {
	j := k.PublicJWK()
	j["d"] = b64(k.Private.D, 32)
	return j
}

// RegisteredClient is a client registered with oneauth through DCR.
type RegisteredClient struct {
	ID  string
	Key ClientKey
}

// User is the account the browser automation logs in as.
type User struct {
	Email    string
	Password string
}

// Setup is everything the plan config needs.
type Setup struct {
	// Alias names the plan in the harness and forms its redirect URI.
	Alias string
	// HarnessURL is the harness origin the redirect URI points at.
	HarnessURL string
	// IssuerURL is oneauth's public URL as the harness container reaches it
	// (https://host.docker.internal:<port>), which is also the token issuer.
	IssuerURL string
	// Scope is registered for both clients and requested by the plan.
	Scope   string
	Clients [2]RegisteredClient
	User    User
}

// PlanVariant is FAPI 2.0 as oneauth implements it: private_key_jwt client
// authentication, DPoP sender constraint, plain FAPI, and plain OAuth
// because oneauth issues no ID tokens yet (#339).
func PlanVariant() map[string]string {
	return map[string]string{
		"fapi_profile":               "plain_fapi",
		"client_auth_type":           "private_key_jwt",
		"sender_constrain":           "dpop",
		"openid":                     "plain_oauth",
		"authorization_request_type": "simple",
		"grant_management":           "disabled",
	}
}

// RedirectURI is where the harness receives authorization responses for a
// plan with this alias.
func RedirectURI(harnessURL, alias string) string {
	return fmt.Sprintf("%s/test/a/%s/callback", harnessURL, alias)
}

// SecondClientRedirectSuffix is the query the plan appends to the second
// client's redirect URI, to check that a registered URI's query is kept
// (RFC 6749 §3.1.2). The suffixed URI has to be the one registered, or the
// second client's PAR request fails as an unregistered redirect.
const SecondClientRedirectSuffix = "?dummy1=lorem&dummy2=ipsum"

// ClientRedirectURI is the redirect URI to register for the plan's client
// number i (0 for "client", 1 for "client2").
func ClientRedirectURI(harnessURL, alias string, i int) string {
	if i == 1 {
		return RedirectURI(harnessURL, alias) + SecondClientRedirectSuffix
	}
	return RedirectURI(harnessURL, alias)
}

// RegistrationRequest is the RFC 7591 body that registers one test client:
// confidential, private_key_jwt with the public key inline, DPoP-bound.
func RegistrationRequest(key ClientKey, redirectURI, scope string) map[string]any {
	return map[string]any{
		"client_name":                "oidf-fapi2-" + key.KeyID[:8],
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks":                       map[string]any{"keys": []map[string]string{key.PublicJWK()}},
		"dpop_bound_access_tokens":   true,
		"scope":                      scope,
	}
}

// BrowserTask is one harness browser-automation entry: while the harness's
// headless browser is on a URL matching Match, it runs Tasks in order.
type BrowserTask struct {
	Match string        `json:"match"`
	Tasks []BrowserStep `json:"tasks"`
}

// BrowserStep runs Commands when the current page matches Match. Each
// command is the harness's [action, locator type, locator, value...] form.
type BrowserStep struct {
	Task     string  `json:"task"`
	Match    string  `json:"match"`
	Optional bool    `json:"optional,omitempty"`
	Commands [][]any `json:"commands"`
}

// BrowserAutomation logs in on oneauth's login page, approves on its consent
// page, and waits for the harness callback to finish. Login is optional
// because the browser may already have a session.
//
// The modules that expect /authorize to refuse with an error page fail at
// the Consent step instead (no Approve button): the error page shares the
// /authorize URL, so the harness can't tell it apart by match.
func BrowserAutomation(s Setup) []BrowserTask {
	return []BrowserTask{{
		Match: s.IssuerURL + "/authorize*",
		Tasks: []BrowserStep{
			{Task: "Login", Match: s.IssuerURL + "/auth/login*", Optional: true, Commands: [][]any{
				{"text", "name", "username", s.User.Email},
				{"text", "name", "password", s.User.Password},
				{"click", "xpath", "//button[@type='submit']"},
			}},
			{Task: "Consent", Match: s.IssuerURL + "/authorize*", Commands: [][]any{
				{"click", "xpath", "//button[@value='approve']"},
			}},
			{Task: "Verify Complete", Match: "*/test/*/callback*", Commands: [][]any{
				{"wait", "id", "submission_complete", 10},
			}},
		},
	}}
}

// PlanConfig is the JSON configuration the harness takes for PlanName.
func PlanConfig(s Setup) map[string]any {
	client := func(c RegisteredClient) map[string]any {
		return map[string]any{
			"client_id":        c.ID,
			"scope":            s.Scope,
			"dpop_signing_alg": "ES256",
			"jwks":             map[string]any{"keys": []map[string]string{c.Key.PrivateJWK()}},
		}
	}
	return map[string]any{
		"alias":       s.Alias,
		"description": "oneauth FAPI 2.0 mission exercise (issue 98)",
		"server":      map[string]any{"discoveryUrl": s.IssuerURL + "/.well-known/openid-configuration"},
		"client":      client(s.Clients[0]),
		"client2":     client(s.Clients[1]),
		"resource": map[string]any{
			"resourceUrl":    s.IssuerURL + "/api/me",
			"resourceMethod": "GET",
		},
		"browser": BrowserAutomation(s),
	}
}

func b64(n *big.Int, size int) string {
	return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, size)))
}

// thumbprint is the RFC 7638 SHA-256 thumbprint of an EC public key.
func thumbprint(k *ecdsa.PrivateKey) string {
	canon, _ := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{"P-256", "EC", b64(k.X, 32), b64(k.Y, 32)})
	sum := sha256.Sum256(canon)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
