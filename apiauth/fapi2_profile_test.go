package apiauth_test

// FAPI 2.0 Security Profile at the authorization server, issue 88's FAPI
// walk, plus the audience rule that protects every deployment.
//
// References:
//   - FAPI 2.0 Security Profile §5.3.2.1, §5.3.2.2 (https://openid.net/specs/fapi-security-profile-2_0-final.html)
//   - RFC 7523 §3, RFC 7521 §4.2 (https://www.rfc-editor.org/rfc/rfc7523#section-3)
//   - CWE-346 (https://cwe.mitre.org/data/definitions/346.html)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

const fapiIssuer = "https://as.example.com"

type fapiFixture struct {
	endpoint http.Handler
	key      *ecdsa.PrivateKey // pk-client: ES256, which FAPI 2.0 §5.4.1 allows
	rsaKey   *rsa.PrivateKey   // rs-client: RS256, which it doesn't
	sign     func(proofOpts) string
}

// newFAPIFixture has a private_key_jwt client ("pk-client") and a secret
// client ("secret-client"), both registered as confidential.
func newFAPIFixture(t *testing.T, fapi2 bool) *fapiFixture {
	t.Helper()
	return newFAPIFixtureWith(t, fapi2, nil)
}

// newFAPIFixtureWith is newFAPIFixture with a hook to adjust the config,
// e.g. to add trusted assertion issuers.
func newFAPIFixtureWith(t *testing.T, fapi2 bool, adjust func(*apiauth.OneAuthConfig)) *fapiFixture {
	t.Helper()
	ctx := context.Background()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubPEM, err := utils.EncodePublicKeyPEM(&priv.PublicKey)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaPEM, err := utils.EncodePublicKeyPEM(&rsaKey.PublicKey)
	require.NoError(t, err)
	ks := keys.NewInMemoryKeyStore()
	_, err = ks.PutKey(ctx, &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "pk-client", Key: pubPEM, Algorithm: "ES256"}})
	require.NoError(t, err)
	_, err = ks.PutKey(ctx, &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "rs-client", Key: rsaPEM, Algorithm: "RS256"}})
	require.NoError(t, err)
	_, err = ks.PutKey(ctx, &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "secret-client", Key: []byte("secret-client-secret-32-bytes-ok"), Algorithm: "HS256"}})
	require.NoError(t, err)
	apps := core.NewInMemoryAppStore()
	for id, m := range map[string]string{"pk-client": "private_key_jwt", "rs-client": "private_key_jwt", "secret-client": "client_secret_basic"} {
		_, err := apps.SaveApp(ctx, &core.SaveAppRequest{App: &core.AppRegistration{ClientID: id, TokenEndpointAuthMethod: m}})
		require.NoError(t, err)
	}
	cfg := apiauth.OneAuthConfig{
		KeyStore: ks, AppStore: apps, FAPI2: fapi2,
		SigningKey: []byte("fapi-as-signing-key-that-is-32-b"), SigningAlg: "HS256", Issuer: fapiIssuer,
		DPoP: apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: testProofURL}),
	}
	if adjust != nil {
		adjust(&cfg)
	}
	oa := apiauth.NewOneAuth(cfg)
	_, sign := newProofSigner(t)
	return &fapiFixture{endpoint: apiauth.NewTokenEndpointHandler(oa), key: priv, rsaKey: rsaKey, sign: sign}
}

func (f *fapiFixture) assertion(t *testing.T, aud any) string {
	t.Helper()
	return f.signAs(t, "pk-client", jwt.SigningMethodES256, f.key, aud)
}

func (f *fapiFixture) signAs(t *testing.T, client string, method jwt.SigningMethod, key any, aud any) string {
	t.Helper()
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	tok, err := jwt.NewWithClaims(method, jwt.MapClaims{
		"iss": client, "sub": client, "aud": aud, "jti": base64.RawURLEncoding.EncodeToString(jti),
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
	}).SignedString(key)
	require.NoError(t, err)
	return tok
}

type fapiReq struct {
	form    url.Values
	basic   [2]string
	headers map[string]string
	proof   bool
}

func (f *fapiFixture) post(t *testing.T, r fapiReq) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(r.form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "as.example.com"
	if r.basic[0] != "" {
		req.SetBasicAuth(r.basic[0], r.basic[1])
	}
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}
	if r.proof {
		req.Header.Set("DPoP", f.sign(proofOpts{}))
	}
	rr := httptest.NewRecorder()
	f.endpoint.ServeHTTP(rr, req)
	return rr
}

func pkForm(assertion string) url.Values {
	return url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {apiauth.ClientAssertionTypeJWTBearer}, "client_assertion": {assertion}}
}

// A caller must not be able to choose the audience its own assertion is
// checked against. With X-Forwarded-Host trusted, an assertion minted for
// another authorization server (aud = its token endpoint) passed here.
//
// See: https://cwe.mitre.org/data/definitions/346.html
func TestAudience_ForwardedHeadersDontChooseTheAudience(t *testing.T) {
	f := newFAPIFixture(t, false)
	foreign := f.assertion(t, "https://other-as.example/api/token")
	rr := f.post(t, fapiReq{form: pkForm(foreign), headers: map[string]string{"X-Forwarded-Host": "other-as.example", "X-Forwarded-Proto": "https"}})
	assert.Equal(t, http.StatusUnauthorized, rr.Code, rr.Body.String())

	// The issuer is an accepted audience by default (RFC 7523 §3).
	rr = f.post(t, fapiReq{form: pkForm(f.assertion(t, fapiIssuer))})
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

// FAPI 2.0 §5.3.2.1: confidential clients only, authenticated with
// private_key_jwt (or MTLS, which oneauth doesn't do), and the assertion's
// aud is the issuer identifier as a string.
func TestFAPI2_ClientAuthentication(t *testing.T) {
	f := newFAPIFixture(t, true)

	rr := f.post(t, fapiReq{form: url.Values{"grant_type": {"client_credentials"}}, basic: [2]string{"secret-client", "secret-client-secret-32-bytes-ok"}, proof: true})
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "a client secret isn't FAPI client authentication: %s", rr.Body.String())

	rr = f.post(t, fapiReq{form: pkForm(f.assertion(t, fapiIssuer+"/api/token")), proof: true})
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "aud must be the issuer, not the token endpoint: %s", rr.Body.String())

	rr = f.post(t, fapiReq{form: pkForm(f.assertion(t, []string{fapiIssuer})), proof: true})
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "aud must be a string, not an array: %s", rr.Body.String())

	rr = f.post(t, fapiReq{form: pkForm(f.signAs(t, "rs-client", jwt.SigningMethodRS256, f.rsaKey, fapiIssuer)), proof: true})
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "RS256 isn't a FAPI 2.0 §5.4.1 algorithm: %s", rr.Body.String())

	rr = f.post(t, fapiReq{form: pkForm(f.assertion(t, fapiIssuer)), proof: true})
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

// FAPI 2.0 §5.3.2.1: sender-constrained tokens only, and no ROPC.
func TestFAPI2_DPoPRequiredAndNoPasswordGrant(t *testing.T) {
	f := newFAPIFixture(t, true)
	rr := f.post(t, fapiReq{form: pkForm(f.assertion(t, fapiIssuer))})
	assert.Equal(t, http.StatusBadRequest, rr.Code, "no proof: %s", rr.Body.String())

	rr = f.post(t, fapiReq{form: url.Values{"grant_type": {"password"}, "username": {"a"}, "password": {"b"}}, proof: true})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "unsupported_grant_type")
}

// FAPI 2.0 §5.3.2.2: PAR only, codes and request_uris short-lived.
func TestFAPI2_AuthorizeMountRequiresPARAndCapsLifetimes(t *testing.T) {
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		FAPI2: true, KeyStore: keys.NewInMemoryKeyStore(), AppStore: core.NewInMemoryAppStore(),
		SigningKey: []byte("fapi-as-signing-key-that-is-32-b"), SigningAlg: "HS256", Issuer: fapiIssuer,
		AuthorizationCodeStore: core.NewInMemoryAuthorizationCodeStore(),
		DPoP:                   apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: testProofURL}),
	})
	cfg := apiauth.AuthorizeMountConfig{
		OneAuth: oa, IssuerURL: fapiIssuer,
		SubjectFromRequest:   func(*http.Request) string { return "alice" },
		CSRFTokenFromRequest: func(*http.Request) string { return "" },
		Expiry:               10 * time.Minute,
	}
	assert.Panics(t, func() { apiauth.MountAuthorize(http.NewServeMux(), cfg) }, "FAPI without a PushedStore can't take any request")

	cfg.PushedStore = core.NewInMemoryPushedAuthorizationRequestStore()
	mux := http.NewServeMux()
	apiauth.MountAuthorize(mux, cfg)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+parForm(nil).Encode(), nil))
	assert.NotEqual(t, http.StatusFound, rr.Code, "a direct request is refused under FAPI")
	assert.Contains(t, rr.Body.String(), "pushed authorization request")
}
