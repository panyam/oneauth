package apiauth

// JARM at /authorize (issue 411). A client that asks for response_mode=jwt
// or one of query.jwt, fragment.jwt and form_post.jwt gets its
// authorization response as one `response` parameter: a JWT signed with
// the AS key, carrying iss, aud, exp and the response parameters. Errors
// that go to the redirect_uri are signed too.
//
// See: https://openid.net/specs/oauth-v2-jarm.html
// See: https://github.com/panyam/oneauth/issues/411

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jarmFixture mounts /authorize with JARM on. key verifies the responses.
type jarmFixture struct {
	*formPostFixture
	key *ecdsa.PrivateKey
}

func newJARMFixture(t *testing.T, autoApprove, implicit bool) *jarmFixture {
	t.Helper()
	var key *ecdsa.PrivateKey
	fx := newAuthorizeFixture(t, autoApprove, implicit, func(cfg *OneAuthConfig, k *ecdsa.PrivateKey) {
		cfg.JARM = &JARMConfig{}
		key = k
	})
	return &jarmFixture{formPostFixture: fx, key: key}
}

// claims verifies a response JWT against the fixture key and returns its
// claims. It checks the header carries the key's kid.
func (fx *jarmFixture) claims(t *testing.T, response string) jwt.MapClaims {
	t.Helper()
	require.NotEmpty(t, response, "want a `response` parameter")
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(response, claims, func(*jwt.Token) (any, error) { return &fx.key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithExpirationRequired())
	require.NoError(t, err)
	kid, err := utils.ComputeKid(fx.key, "ES256")
	require.NoError(t, err)
	assert.Equal(t, kid, tok.Header["kid"], "the kid lets a client find the key in the JWKS")
	return claims
}

// redirectParams returns the query and fragment parameters of a 302.
func redirectParams(t *testing.T, rec *httptest.ResponseRecorder) (query, fragment url.Values) {
	t.Helper()
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "https://app.example/cb", loc.Scheme+"://"+loc.Host+loc.Path)
	frag, err := url.ParseQuery(loc.Fragment)
	require.NoError(t, err)
	return loc.Query(), frag
}

// The response carries only `response`: state, code and the RFC 9207 iss
// all move inside the JWT, which has iss, aud = client_id and a short exp.
// See: https://openid.net/specs/oauth-v2-jarm.html#section-2.1
func TestJARM_JWTModeSignsTheCodeResponse(t *testing.T) {
	fx := newJARMFixture(t, true, false)
	query, frag := redirectParams(t, fx.get(formPostQuery(t, "jwt")))
	assert.Empty(t, frag.Get("response"), "jwt means query.jwt for the code flow")
	assert.Equal(t, []string{"response"}, paramNames(query), "nothing but the JWT goes on the URL")

	claims := fx.claims(t, query.Get("response"))
	assert.Equal(t, formPostIssuer, claims["iss"])
	assert.Equal(t, "fp", claims["aud"])
	assert.NotEmpty(t, claims["code"])
	assert.Equal(t, "st-1", claims["state"])
	exp, err := claims.GetExpirationTime()
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(DefaultAuthorizationResponseExpiry), exp.Time, 5*time.Second)
}

// Each *.jwt mode delivers the JWT the way its base mode delivers
// parameters.
// See: https://openid.net/specs/oauth-v2-jarm.html#section-2.3
func TestJARM_ExplicitModesDeliverInTheirBaseMode(t *testing.T) {
	fx := newJARMFixture(t, true, false)

	query, frag := redirectParams(t, fx.get(formPostQuery(t, "query.jwt")))
	assert.Empty(t, frag.Get("response"))
	assert.NotEmpty(t, fx.claims(t, query.Get("response"))["code"])

	query, frag = redirectParams(t, fx.get(formPostQuery(t, "fragment.jwt")))
	assert.Empty(t, query, "fragment.jwt puts nothing in the query")
	assert.Equal(t, []string{"response"}, paramNames(frag))
	assert.NotEmpty(t, fx.claims(t, frag.Get("response"))["code"])

	posted := formPostPage(t, fx.get(formPostQuery(t, "form_post.jwt")))
	assert.Equal(t, []string{"response"}, paramNames(posted))
	assert.NotEmpty(t, fx.claims(t, posted.Get("response"))["code"])
}

// An error that goes to the redirect_uri is signed too, so a client can
// tell the AS sent it.
// See: https://openid.net/specs/oauth-v2-jarm.html#section-4.1.2
func TestJARM_ErrorsAreSigned(t *testing.T) {
	fx := newJARMFixture(t, false, false)
	q := formPostQuery(t, "jwt")
	q.Set("prompt", "none")
	query, _ := redirectParams(t, fx.get(q))
	assert.Equal(t, []string{"response"}, paramNames(query))
	claims := fx.claims(t, query.Get("response"))
	assert.Equal(t, "consent_required", claims["error"])
	assert.Equal(t, "st-1", claims["state"])
	assert.Equal(t, "fp", claims["aud"])
	assert.Nil(t, claims["code"])
}

// For the implicit types jwt means fragment.jwt, and the tokens go inside
// the JWT. query.jwt would put them in the URL, so it is refused, with
// the error in the default mode, unsigned, since the mode was the problem.
// See: https://openid.net/specs/oauth-v2-jarm.html#section-2.3.1
func TestJARM_ImplicitTypes(t *testing.T) {
	fx := newJARMFixture(t, true, true)
	query, frag := redirectParams(t, fx.get(implicitFormPostQuery("id_token", "jwt")))
	assert.Empty(t, query)
	claims := fx.claims(t, frag.Get("response"))
	assert.NotEmpty(t, claims["id_token"])
	assert.Equal(t, "st-1", claims["state"])

	query, frag = redirectParams(t, fx.get(implicitFormPostQuery("id_token", "query.jwt")))
	assert.Empty(t, query)
	assert.Equal(t, "invalid_request", frag.Get("error"))
	assert.Empty(t, frag.Get("response"))
}

// A pushed request keeps response_mode=jwt.
// See: https://www.rfc-editor.org/rfc/rfc9126#section-4
func TestJARM_ThroughPAR(t *testing.T) {
	fx := newJARMFixture(t, true, false)
	push := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(formPostQuery(t, "jwt").Encode()))
	push.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	fx.mux.ServeHTTP(rec, push)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var body struct {
		RequestURI string `json:"request_uri"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	query, _ := redirectParams(t, fx.get(url.Values{"client_id": {"fp"}, "request_uri": {body.RequestURI}}))
	assert.NotEmpty(t, fx.claims(t, query.Get("response"))["code"])
}

func TestJARM_ResponseModesSupported(t *testing.T) {
	signer := &failingSigner{}
	h := &AuthorizationHandler{ResponseSigner: signer}
	assert.Equal(t, []string{"query", "form_post", "jwt", "query.jwt", "fragment.jwt", "form_post.jwt"}, h.ResponseModesSupported())
	h.Implicit = &ImplicitTokens{}
	assert.Equal(t, []string{"query", "fragment", "form_post", "jwt", "query.jwt", "fragment.jwt", "form_post.jwt"}, h.ResponseModesSupported())
}

// failingSigner can't sign anything.
type failingSigner struct{}

func (failingSigner) SignAuthorizationResponse(context.Context, *SignAuthorizationResponseRequest) (*SignAuthorizationResponseResponse, error) {
	return nil, errors.New("key unavailable")
}
func (failingSigner) AuthorizationSigningAlgs() []string { return []string{"ES256"} }

// A response the AS can't sign is never sent unsigned: the user sees an
// error page, and no code reaches the redirect_uri.
func TestJARM_SigningFailureShowsAnErrorPage(t *testing.T) {
	fx := newAuthorizeFixture(t, true, false, func(cfg *OneAuthConfig, _ *ecdsa.PrivateKey) {
		cfg.JARM = &JARMConfig{Signer: failingSigner{}}
	})
	for _, mode := range []string{"jwt", "form_post.jwt"} {
		rec := fx.get(formPostQuery(t, mode))
		assert.Empty(t, rec.Header().Get("Location"), mode)
		assert.GreaterOrEqual(t, rec.Code, 400, mode)
		assert.NotContains(t, rec.Body.String(), `name="code"`, mode)
		assert.NotContains(t, rec.Body.String(), `name="response"`, mode)
	}
}

// An HMAC secret can't sign a response a client verifies against the JWKS.
func TestNewJWTAuthorizationResponseSigner_RefusesHMAC(t *testing.T) {
	_, err := NewJWTAuthorizationResponseSigner(JWTAuthorizationResponseSignerConfig{
		SigningKey: []byte("0123456789abcdef0123456789abcdef"), SigningAlg: "HS256", Issuer: formPostIssuer,
	})
	assert.Error(t, err)
}

func paramNames(v url.Values) []string {
	out := make([]string, 0, len(v))
	for k := range v {
		out = append(out, k)
	}
	return out
}

func TestOneAuth_AuthorizationSigningAlgs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	on := NewOneAuth(OneAuthConfig{SigningKey: key, SigningAlg: "ES256", Issuer: formPostIssuer, JARM: &JARMConfig{}})
	assert.Equal(t, []string{"ES256"}, on.AuthorizationSigningAlgs())
	off := NewOneAuth(OneAuthConfig{SigningKey: key, SigningAlg: "ES256", Issuer: formPostIssuer})
	assert.Nil(t, off.AuthorizationSigningAlgs())
}

// JARM on an HS256 server would sign with a secret clients can't verify
// against the JWKS, so NewOneAuth refuses it at startup.
func TestNewOneAuth_JARMNeedsAnAsymmetricKey(t *testing.T) {
	assert.Panics(t, func() {
		NewOneAuth(OneAuthConfig{SigningKey: []byte("0123456789abcdef0123456789abcdef"), Issuer: formPostIssuer, JARM: &JARMConfig{}})
	})
}
