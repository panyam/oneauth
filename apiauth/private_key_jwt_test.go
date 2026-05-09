package apiauth_test

// Server-side tests for `private_key_jwt` client authentication on the
// token endpoint (RFC 7521 §4.2 + RFC 7523 §2.2 + OIDC Core §9).
//
// References:
//   - RFC 7521 §4.2 (https://www.rfc-editor.org/rfc/rfc7521#section-4.2)
//     defines the `client_assertion_type` URN and the assertion as a
//     client authentication mechanism.
//   - RFC 7523 §3   (https://www.rfc-editor.org/rfc/rfc7523#section-3)
//     enumerates the JWT validation rules: iss/sub/aud/exp/jti.
//   - OIDC Core §9  (https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
//     specifies private_key_jwt for OAuth/OIDC clients.
//   - Algorithm-confusion: CVE-2016-10555 / CWE-327 — see WithValidMethods
//     in apiauth/client_authenticator.go.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// pkjwtFixture holds the test AS + a freshly minted RSA keypair the
// "test-app" client uses to sign assertions. The public half is
// stored in the AS keystore (PEM bytes + Algorithm=RS256), exactly
// mirroring how `admin/registrar.go` provisions a private_key_jwt
// client during DCR.
type pkjwtFixture struct {
	t          *testing.T
	auth       *apiauth.APIAuth
	clientID   string
	privateKey *rsa.PrivateKey
	tokenURL   string // canonical aud value for assertions
}

func newPKJWTFixture(t *testing.T) *pkjwtFixture {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubPEM, err := utils.EncodePublicKeyPEM(&priv.PublicKey)
	require.NoError(t, err)

	ks := keys.NewInMemoryKeyStore()
	const clientID = "test-app"
	require.NoError(t, ks.PutKey(&keys.KeyRecord{
		ClientID:  clientID,
		Key:       pubPEM,
		Algorithm: "RS256",
	}))

	auth := &apiauth.APIAuth{
		JWTSecretKey:        "server-jwt-secret-key-32chars!!",
		JWTIssuer:           "test-issuer",
		ClientKeyStore:      ks,
		ClientAuthenticator: apiauth.NewClientAuthenticator(ks),
		// Constrained set so we know the test exercises the audience
		// match logic deterministically (no fallback to derived URL).
		AcceptedAudiences: []string{"https://oneauth.example.com/api/token"},
	}
	return &pkjwtFixture{
		t:          t,
		auth:       auth,
		clientID:   clientID,
		privateKey: priv,
		tokenURL:   "https://oneauth.example.com/api/token",
	}
}

// signAssertion signs a JWT with the fixture's private key. Override
// any of the standard claims via `mutate` to construct invalid
// variants for the negative cases.
func (f *pkjwtFixture) signAssertion(mutate func(claims jwt.MapClaims, header map[string]any)) string {
	f.t.Helper()
	jti := make([]byte, 16)
	_, err := rand.Read(jti)
	require.NoError(f.t, err)

	claims := jwt.MapClaims{
		"iss": f.clientID,
		"sub": f.clientID,
		"aud": f.tokenURL,
		"jti": base64.RawURLEncoding.EncodeToString(jti),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(60 * time.Second).Unix(),
	}
	header := map[string]any{}
	if mutate != nil {
		mutate(claims, header)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	for k, v := range header {
		tok.Header[k] = v
	}
	signed, err := tok.SignedString(f.privateKey)
	require.NoError(f.t, err)
	return signed
}

// postTokenForm POSTs a form-encoded token request to the fixture's
// AS handler and returns the response.
func (f *pkjwtFixture) postTokenForm(form map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()
	values := make([]string, 0, len(form))
	for k, v := range form {
		values = append(values, k+"="+v)
	}
	body := strings.Join(values, "&")
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "oneauth.example.com"
	req.TLS = nil // derived audience falls back to plain http; we set AcceptedAudiences explicitly
	rr := httptest.NewRecorder()
	http.HandlerFunc(f.auth.ServeHTTP).ServeHTTP(rr, req)
	return rr
}

// TestPrivateKeyJWT_Success verifies the happy path: a correctly-signed
// assertion with all required claims yields an access token whose `sub`
// equals the client_id (RFC 6749 §4.4 — client_credentials grant).
func TestPrivateKeyJWT_Success(t *testing.T) {
	f := newPKJWTFixture(t)
	assertion := f.signAssertion(nil)

	rr := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_id":             f.clientID,
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      assertion,
	})

	require.Equal(t, http.StatusOK, rr.Code, "expected 200; body=%s", rr.Body.String())
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.NotEmpty(t, resp["access_token"], "expected access_token")

	sub, _, err := f.auth.ValidateAccessToken(resp["access_token"].(string))
	require.NoError(t, err)
	assert.Equal(t, f.clientID, sub, "minted token sub MUST equal client_id")
}

// TestPrivateKeyJWT_RejectsWrongIssuer — RFC 7521 §4.1: the assertion's
// iss MUST equal the authenticated client_id. A mismatch is a forgery
// signal (or attempt to impersonate a different client).
func TestPrivateKeyJWT_RejectsWrongIssuer(t *testing.T) {
	f := newPKJWTFixture(t)
	assertion := f.signAssertion(func(c jwt.MapClaims, _ map[string]any) {
		c["iss"] = "attacker-client"
	})
	rr := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_id":             f.clientID,
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      assertion,
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "iss != sub MUST be invalid_client")
}

// TestPrivateKeyJWT_RejectsIssSubMismatch — RFC 7521 §4.1 also requires
// iss == sub for the JWT-as-client-authentication shape; an assertion
// where they differ violates the spec.
func TestPrivateKeyJWT_RejectsIssSubMismatch(t *testing.T) {
	f := newPKJWTFixture(t)
	assertion := f.signAssertion(func(c jwt.MapClaims, _ map[string]any) {
		c["sub"] = "different-subject"
	})
	rr := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      assertion,
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestPrivateKeyJWT_RejectsWrongAudience — RFC 7523 §3 item 3: the AS
// MUST verify the assertion is intended for itself. An assertion
// destined for someone else's token endpoint must not authenticate.
func TestPrivateKeyJWT_RejectsWrongAudience(t *testing.T) {
	f := newPKJWTFixture(t)
	assertion := f.signAssertion(func(c jwt.MapClaims, _ map[string]any) {
		c["aud"] = "https://other-as.example.com/api/token"
	})
	rr := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      assertion,
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestPrivateKeyJWT_RejectsExpired — RFC 7523 §3 item 4: assertions
// MUST be rejected if exp is in the past (tokens with no exp are also
// rejected; tested implicitly via the missing-exp variant).
func TestPrivateKeyJWT_RejectsExpired(t *testing.T) {
	f := newPKJWTFixture(t)
	assertion := f.signAssertion(func(c jwt.MapClaims, _ map[string]any) {
		c["iat"] = time.Now().Add(-2 * time.Minute).Unix()
		c["exp"] = time.Now().Add(-1 * time.Minute).Unix()
	})
	rr := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      assertion,
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestPrivateKeyJWT_RejectsLifetimeOverCap — OneAuth bounds assertion
// lifetime to MaxClientAssertionLifetime (5 min) so a leaked assertion
// has a small replay window. Lifetimes beyond the cap are rejected
// even if exp is otherwise valid.
func TestPrivateKeyJWT_RejectsLifetimeOverCap(t *testing.T) {
	f := newPKJWTFixture(t)
	assertion := f.signAssertion(func(c jwt.MapClaims, _ map[string]any) {
		c["iat"] = time.Now().Unix()
		c["exp"] = time.Now().Add(2 * apiauth.MaxClientAssertionLifetime).Unix()
	})
	rr := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      assertion,
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestPrivateKeyJWT_RejectsReplayedJTI — RFC 7523 §3 item 7: the AS
// MUST reject reuse of the same `jti` within the assertion's lifetime
// (replay protection).
func TestPrivateKeyJWT_RejectsReplayedJTI(t *testing.T) {
	f := newPKJWTFixture(t)
	assertion := f.signAssertion(nil)

	// First use succeeds.
	rr1 := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      assertion,
	})
	require.Equal(t, http.StatusOK, rr1.Code, "first use should succeed")

	// Second use with the same jti must fail.
	rr2 := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      assertion,
	})
	assert.Equal(t, http.StatusUnauthorized, rr2.Code, "replayed jti must be rejected")
}

// TestPrivateKeyJWT_RejectsMissingJTI — jti is mandatory under RFC 7523
// §3 because without it the AS cannot perform replay protection. An
// assertion lacking a jti is rejected even when otherwise valid.
func TestPrivateKeyJWT_RejectsMissingJTI(t *testing.T) {
	f := newPKJWTFixture(t)
	assertion := f.signAssertion(func(c jwt.MapClaims, _ map[string]any) {
		delete(c, "jti")
	})
	rr := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      assertion,
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestPrivateKeyJWT_RejectsBadAssertionType — RFC 7521 §4.2 specifies
// the assertion-type URN exactly. Any other value (including the empty
// string) MUST be rejected as malformed.
func TestPrivateKeyJWT_RejectsBadAssertionType(t *testing.T) {
	f := newPKJWTFixture(t)
	assertion := f.signAssertion(nil)
	rr := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:saml2-bearer",
		"client_assertion":      assertion,
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestPrivateKeyJWT_RejectsAlgConfusion — CVE-2016-10555-class attack:
// a client could attempt to swap the JWT alg from RS256 (registered)
// to HS256, signing the assertion with the public key as an HMAC
// secret. WithValidMethods locks the alg to what was registered.
func TestPrivateKeyJWT_RejectsAlgConfusion(t *testing.T) {
	f := newPKJWTFixture(t)

	// Re-encode the public key as PEM, then sign an HS256 assertion
	// using those bytes as the HMAC secret — the classic forge.
	pubPEM, err := utils.EncodePublicKeyPEM(&f.privateKey.PublicKey)
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"iss": f.clientID,
		"sub": f.clientID,
		"aud": f.tokenURL,
		"jti": "alg-confusion-test",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(60 * time.Second).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	forged, err := tok.SignedString(pubPEM)
	require.NoError(t, err)

	rr := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      forged,
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "HS256 forgery against RS256-registered client must be rejected")
}

// TestPrivateKeyJWT_RejectsUnknownClient — when `iss` names a client
// the AS hasn't seen, GetKey returns nil and we surface invalid_client
// (no leaked information about which clients exist).
func TestPrivateKeyJWT_RejectsUnknownClient(t *testing.T) {
	f := newPKJWTFixture(t)
	assertion := f.signAssertion(func(c jwt.MapClaims, _ map[string]any) {
		c["iss"] = "ghost-client"
		c["sub"] = "ghost-client"
	})
	rr := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      assertion,
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestPrivateKeyJWT_AcceptsMultipleAudiences — interop: real-world
// clients (Auth0, Keycloak, Authlete) send `aud` as either the token
// endpoint URL or the AS issuer URL. Our authenticator must accept any
// configured audience.
func TestPrivateKeyJWT_AcceptsMultipleAudiences(t *testing.T) {
	f := newPKJWTFixture(t)
	f.auth.AcceptedAudiences = []string{
		"https://oneauth.example.com",         // issuer
		"https://oneauth.example.com/api/token", // endpoint URL
	}
	assertion := f.signAssertion(func(c jwt.MapClaims, _ map[string]any) {
		c["aud"] = "https://oneauth.example.com" // issuer-form aud
	})
	rr := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      assertion,
	})
	require.Equal(t, http.StatusOK, rr.Code, "issuer-form aud must be accepted; body=%s", rr.Body.String())
}
