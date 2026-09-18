package keycloak_test

// RFC 9449 interop: OneAuth's resource-server enforcement against tokens a
// real Keycloak issued, rather than tokens OneAuth minted for itself.
//
// The rest of the DPoP test suite proves our two halves agree with each
// other. That is worth having and proves less than it looks: a shared
// misreading of the spec passes both sides. These tests put a different
// implementation on the issuing side, so `cnf.jkt`, the thumbprint
// computation and the proof format have to match somebody else's reading.
//
// Requires Keycloak started with the dpop preview feature:
//
//	make upkcl && make testkcl
//
// Tests skip when Keycloak is unreachable, and fail loudly when it is
// reachable but DPoP is off, because a silent skip there would hide exactly
// the regression this file exists to catch.
//
// References:
//   - RFC 9449 §5 (https://www.rfc-editor.org/rfc/rfc9449#section-5) — issuance
//   - RFC 9449 §7.1 (https://www.rfc-editor.org/rfc/rfc9449#section-7.1) — presenting a bound token
//   - RFC 9449 §7.2 (https://www.rfc-editor.org/rfc/rfc9449#section-7.2) — the Bearer downgrade
//   - See: https://github.com/panyam/oneauth/issues/371

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// dpopClientID is the realm client with "Require DPoP bound tokens" set
// (attribute dpop.bound.access.tokens), added to realm.json for this suite.
const dpopClientID = "test-dpop"

// dpopKey is one client key pair plus the helpers to prove possession of it.
type dpopKey struct {
	private *ecdsa.PrivateKey
	jwk     map[string]any
	jkt     string
}

func newDPoPKey(t *testing.T) *dpopKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encoded, err := json.Marshal(utils.ECDSAPublicKeyToJWK("", "ES256", &key.PublicKey))
	if err != nil {
		t.Fatalf("encode jwk: %v", err)
	}
	var members map[string]any
	if err := json.Unmarshal(encoded, &members); err != nil {
		t.Fatalf("decode jwk: %v", err)
	}
	for _, drop := range []string{"kid", "use", "key_ops", "alg"} {
		delete(members, drop)
	}
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return &dpopKey{private: key, jwk: members, jkt: jkt}
}

// proof mints a DPoP proof for one request. Hand-rolled rather than reusing
// the client SDK on purpose: this suite is checking the wire format against
// Keycloak, and driving both sides from our own helper would hide a
// disagreement about what that format is.
func (k *dpopKey) proof(t *testing.T, method, targetURL, accessToken string) string {
	t.Helper()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		t.Fatalf("jti: %v", err)
	}
	claims := jwt.MapClaims{
		"jti": base64.RawURLEncoding.EncodeToString(jti),
		"htm": method,
		"htu": targetURL,
		"iat": time.Now().Unix(),
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = k.jwk
	signed, err := token.SignedString(k.private)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	return signed
}

// keycloakDPoPToken runs a password grant against the DPoP-required client,
// with a proof attached, and returns the access token.
//
// A 400 here usually means Keycloak was started without --features=dpop.
// That is reported as a failure rather than a skip: a silently disabled
// preview feature would turn this whole file into a no-op that still
// reports success.
func keycloakDPoPToken(t *testing.T, key *dpopKey) string {
	t.Helper()
	tokenEndpoint := realmURL() + "/protocol/openid-connect/token"

	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {dpopClientID},
		"username":   {testUsername},
		"password":   {testPassword},
		"scope":      {"openid"},
	}
	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", key.proof(t, http.MethodPost, tokenEndpoint, ""))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Keycloak refused the DPoP token request (HTTP %d): %s\n"+
			"If this says the client or grant is unknown, the realm may predate the test-dpop client.\n"+
			"If it mentions an unsupported parameter or feature, Keycloak was likely started without "+
			"--features=dpop (see the Makefile's KC_IMAGE lines).", resp.StatusCode, body)
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode token response: %v (%s)", err, body)
	}
	if !strings.EqualFold(parsed.TokenType, "DPoP") {
		t.Fatalf("expected token_type DPoP from a DPoP-required client, got %q", parsed.TokenType)
	}
	return parsed.AccessToken
}

// newKeycloakBackedResource builds a OneAuth resource server that validates
// Keycloak's signatures via JWKS and enforces the DPoP binding.
func newKeycloakBackedResource(t *testing.T) (*httptest.Server, *apiauth.APIMiddleware) {
	t.Helper()
	jwks := keys.NewJWKSKeyStore(realmURL() + "/protocol/openid-connect/certs")
	if err := jwks.Start(); err != nil {
		t.Fatalf("start JWKS key store: %v", err)
	}
	t.Cleanup(jwks.Stop)

	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	mw := &apiauth.APIMiddleware{
		KeyStore:  jwks,
		JWTIssuer: realmURL(),
		DPoP: apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{
			BaseURL: "http://" + server.Listener.Addr().String(),
		}),
	}
	mux.Handle("GET /resource", mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"subject": apiauth.GetSubjectFromAPIContext(r.Context())})
	})))
	server.Start()
	t.Cleanup(server.Close)
	return server, mw
}

func callResource(t *testing.T, server *httptest.Server, scheme, token, proof string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("build resource request: %v", err)
	}
	req.Header.Set("Authorization", scheme+" "+token)
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("resource request: %v", err)
	}
	return resp
}

// The thumbprint we compute for a key must equal the one Keycloak puts in
// the token it issues for that key. This is the single most valuable
// assertion in the file: it checks our RFC 7638 implementation against a
// shipping IdP rather than against itself.
func TestKeycloakDPoP_ThumbprintAgreesWithKeycloak(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	key := newDPoPKey(t)

	token := keycloakDPoPToken(t, key)

	claims := parseJWTClaims(t, token)
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		t.Fatalf("Keycloak-issued token carries no cnf claim: %v", claims)
	}
	if got := cnf["jkt"]; got != key.jkt {
		t.Fatalf("thumbprint disagreement: Keycloak says %v, utils.ComputeKid says %s", got, key.jkt)
	}
}

// A Keycloak-issued bound token, presented to OneAuth's middleware with a
// proof for the same key, is accepted.
func TestKeycloakDPoP_MiddlewareAcceptsBoundToken(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	key := newDPoPKey(t)
	token := keycloakDPoPToken(t, key)
	server, _ := newKeycloakBackedResource(t)

	resp := callResource(t, server, "DPoP", token, key.proof(t, http.MethodGet, server.URL+"/resource", token))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for a valid Keycloak DPoP token, got %d: %s", resp.StatusCode, body)
	}
}

// RFC 9449 §7.2: a bound token presented as a bearer token must be refused.
// Whoever steals a token will always prefer the Bearer path, since it used
// to skip every DPoP check.
func TestKeycloakDPoP_MiddlewareRefusesBearerDowngrade(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	key := newDPoPKey(t)
	token := keycloakDPoPToken(t, key)
	server, _ := newKeycloakBackedResource(t)

	resp := callResource(t, server, "Bearer", token, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a Keycloak-bound token presented as Bearer must be refused, got %d", resp.StatusCode)
	}
}

// The stolen-token case: an attacker holding the token mints proofs with
// their own key, which do not match the cnf.jkt Keycloak bound it to.
func TestKeycloakDPoP_MiddlewareRefusesAnotherKey(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	key := newDPoPKey(t)
	token := keycloakDPoPToken(t, key)
	attacker := newDPoPKey(t)
	server, _ := newKeycloakBackedResource(t)

	resp := callResource(t, server, "DPoP", token, attacker.proof(t, http.MethodGet, server.URL+"/resource", token))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a proof signed by a different key must be refused, got %d", resp.StatusCode)
	}
}

// Without the ath check, a proof captured alongside one token could be
// replayed with another token the same client holds.
func TestKeycloakDPoP_MiddlewareRefusesMismatchedATH(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	key := newDPoPKey(t)
	token := keycloakDPoPToken(t, key)
	other := keycloakDPoPToken(t, key)
	server, _ := newKeycloakBackedResource(t)

	resp := callResource(t, server, "DPoP", token, key.proof(t, http.MethodGet, server.URL+"/resource", other))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a proof whose ath names a different token must be refused, got %d", resp.StatusCode)
	}
}

// A token from an ordinary Keycloak client carries no cnf, and the same
// middleware still accepts it as a bearer token. This is what makes DPoP
// adoptable one client at a time rather than fleet-wide.
func TestKeycloakDPoP_UnboundKeycloakTokenStillWorks(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	tokenResp := getPasswordToken(t, realmURL()+"/protocol/openid-connect/token",
		confidentialClientID, confidentialClientSecret, testUsername, testPassword)
	server, _ := newKeycloakBackedResource(t)

	resp := callResource(t, server, "Bearer", tokenResp.AccessToken, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("an unbound Keycloak token must still work as Bearer, got %d: %s", resp.StatusCode, body)
	}
}
