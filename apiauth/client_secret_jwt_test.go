package apiauth_test

// Server-side tests for `client_secret_jwt` client authentication on the
// token endpoint (RFC 7521 §4.2 + RFC 7523 §2.2 + OIDC Core §9). The
// general JWT-assertion pipeline shipped under issue 158
// (private_key_jwt); this file pins the symmetric variant covered by
// issue 159.
//
// References:
//   - RFC 7521 §4.2 (https://www.rfc-editor.org/rfc/rfc7521#section-4.2)
//   - RFC 7523 §3   (https://www.rfc-editor.org/rfc/rfc7523#section-3)
//   - OIDC Core §9  (https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
//   - Algorithm-confusion: CVE-2016-10555 / CWE-327 (WithValidMethods locks alg).

import (
	"context"
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

// csjwtFixture holds the test AS + an HMAC secret the "test-app"
// client uses to sign assertions. The same secret bytes are stored in
// the AS keystore under Algorithm matching the test variant
// (HS256/384/512). Mirrors the private_key_jwt fixture, but symmetric.
type csjwtFixture struct {
	t        *testing.T
	auth     *apiauth.APIAuth
	clientID string
	secret   []byte
	alg      string // HS256 / HS384 / HS512
	tokenURL string // canonical aud value for assertions
}

func newCSJWTFixture(t *testing.T, alg string) *csjwtFixture {
	t.Helper()
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	ks := keys.NewInMemoryKeyStore()
	const clientID = "test-app"
	_, err = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID:  clientID,
		Key:       secret,
		Algorithm: alg,
	}})
	require.NoError(t, err)

	auth := &apiauth.APIAuth{
		JWTSecretKey:        "server-jwt-secret-key-32chars!!",
		JWTIssuer:           "test-issuer",
		ClientKeyStore:      ks,
		ClientAuthenticator: apiauth.NewClientAuthenticator(ks),
		AcceptedAudiences:   []string{"https://oneauth.example.com/api/token"},
	}
	return &csjwtFixture{
		t:        t,
		auth:     auth,
		clientID: clientID,
		secret:   secret,
		alg:      alg,
		tokenURL: "https://oneauth.example.com/api/token",
	}
}

// signAssertion signs a JWT with the fixture's HMAC secret using the
// fixture's algorithm. Override claims via `mutate` for negative cases.
func (f *csjwtFixture) signAssertion(mutate func(claims jwt.MapClaims, header map[string]any)) string {
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

	method := jwt.GetSigningMethod(f.alg)
	require.NotNil(f.t, method, "unknown signing method %q", f.alg)
	tok := jwt.NewWithClaims(method, claims)
	for k, v := range header {
		tok.Header[k] = v
	}
	signed, err := tok.SignedString(f.secret)
	require.NoError(f.t, err)
	return signed
}

func (f *csjwtFixture) postTokenForm(form map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()
	values := make([]string, 0, len(form))
	for k, v := range form {
		values = append(values, k+"="+v)
	}
	body := strings.Join(values, "&")
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "oneauth.example.com"
	rr := httptest.NewRecorder()
	http.HandlerFunc(f.auth.ServeHTTP).ServeHTTP(rr, req)
	return rr
}

// TestClientSecretJWT_Success_AllSymmetricAlgs verifies the happy path
// for every standard HMAC algorithm (HS256/384/512). Each yields an
// access token whose `sub` equals the client_id.
func TestClientSecretJWT_Success_AllSymmetricAlgs(t *testing.T) {
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		t.Run(alg, func(t *testing.T) {
			f := newCSJWTFixture(t, alg)
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
		})
	}
}

// TestClientSecretJWT_MethodClassification verifies the
// ClientAuthenticator response surface — Method is "client_secret_jwt"
// for HMAC clients (not "private_key_jwt"). Distinguishes the symmetric
// path from the asymmetric one for downstream audit / metrics.
func TestClientSecretJWT_MethodClassification(t *testing.T) {
	f := newCSJWTFixture(t, "HS256")
	assertion := f.signAssertion(nil)

	authn := apiauth.NewClientAuthenticator(f.auth.ClientKeyStore)
	resp, err := authn.AuthenticateClient(context.Background(), &apiauth.AuthenticateClientRequest{
		ClientID:            f.clientID,
		ClientAssertion:     assertion,
		ClientAssertionType: apiauth.ClientAssertionTypeJWTBearer,
		Audiences:           []string{f.tokenURL},
	})
	require.NoError(t, err)
	assert.Equal(t, f.clientID, resp.ClientID)
	assert.Equal(t, "client_secret_jwt", resp.Method, "Method MUST be client_secret_jwt for HMAC clients")
}

// TestClientSecretJWT_RejectsWrongSecret verifies that a JWT signed with
// the wrong HMAC secret is rejected. Even with iss/sub/aud all valid,
// signature verification fails because the AS-stored secret differs
// from what was used to sign.
func TestClientSecretJWT_RejectsWrongSecret(t *testing.T) {
	f := newCSJWTFixture(t, "HS256")
	wrongSecret := make([]byte, 32)
	_, err := rand.Read(wrongSecret)
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"iss": f.clientID,
		"sub": f.clientID,
		"aud": f.tokenURL,
		"jti": "wrong-secret-test",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(60 * time.Second).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	forged, err := tok.SignedString(wrongSecret)
	require.NoError(t, err)

	rr := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      forged,
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestClientSecretJWT_RejectsAlgConfusion_HSToRSAttacker covers the
// inverse of the private_key_jwt case: an attacker tries to forge an
// assertion against an HS256-registered client by submitting an RS256
// JWT signed with a freshly minted key. WithValidMethods locks the
// verifier to the registered alg, so the RS256 attack fails on alg
// mismatch before signature verification.
func TestClientSecretJWT_RejectsAlgConfusion_HSToRSAttacker(t *testing.T) {
	f := newCSJWTFixture(t, "HS256")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	claims := jwt.MapClaims{
		"iss": f.clientID,
		"sub": f.clientID,
		"aud": f.tokenURL,
		"jti": "alg-confusion-hs-to-rs",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(60 * time.Second).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	forged, err := tok.SignedString(priv)
	require.NoError(t, err)

	rr := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      forged,
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "RS256 assertion against HS256-registered client MUST be rejected")
}

// TestClientSecretJWT_RejectsWrongAudience confirms the shared
// assertion-validation pipeline (aud check) applies to HMAC clients too —
// the gate removal in #159 doesn't accidentally bypass anything.
func TestClientSecretJWT_RejectsWrongAudience(t *testing.T) {
	f := newCSJWTFixture(t, "HS256")
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

// TestClientSecretJWT_RejectsReplayedJTI confirms the JTI replay store
// applies to HMAC clients too — same shared logic, no accidental
// bypass for the symmetric path.
func TestClientSecretJWT_RejectsReplayedJTI(t *testing.T) {
	f := newCSJWTFixture(t, "HS256")
	assertion := f.signAssertion(nil)

	rr1 := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      assertion,
	})
	require.Equal(t, http.StatusOK, rr1.Code, "first use should succeed")

	rr2 := f.postTokenForm(map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer,
		"client_assertion":      assertion,
	})
	assert.Equal(t, http.StatusUnauthorized, rr2.Code, "replayed jti must be rejected even for HMAC clients")
}

// TestClientSecretJWT_RejectsLifetimeOverCap confirms the
// MaxClientAssertionLifetime ceiling applies to HMAC clients too.
func TestClientSecretJWT_RejectsLifetimeOverCap(t *testing.T) {
	f := newCSJWTFixture(t, "HS256")
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

// utils import kept to mirror private_key_jwt_test.go's symmetry; if
// unused at the var-level it's only via the keys.KeyRecord literal.
var _ = utils.IsAsymmetricAlg
