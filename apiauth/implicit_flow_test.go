package apiauth

// The OIDC implicit flow, opt-in (OIDC Core §3.2, issue 507): with
// OneAuthConfig.AllowImplicit, a client registered for "id_token" or
// "id_token token" gets its tokens in the redirect's fragment, never the
// query, with no code and no refresh token. RFC 9700 §2.1.2 advises
// against implicit, so it's off unless both the server and the client ask.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
// See: https://github.com/panyam/oneauth/issues/507

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type implicitFixture struct {
	mux *http.ServeMux
	key *ecdsa.PrivateKey
	oa  *OneAuth
}

func newImplicitFixture(t *testing.T, allow bool, responseTypes ...string) *implicitFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	apps := core.NewInMemoryAppStore()
	_, err = apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID: "imp", RedirectURIs: []string{"https://app.example/cb"}, ResponseTypes: responseTypes, TokenEndpointAuthMethod: "none",
	}})
	require.NoError(t, err)
	oa := NewOneAuth(OneAuthConfig{
		SigningKey: key, SigningAlg: "ES256", VerifyKey: &key.PublicKey, Issuer: "https://as.example",
		AuthorizationCodeStore: core.NewInMemoryAuthorizationCodeStore(), AppStore: apps, AllowImplicit: allow,
		OIDC: &OIDCConfig{UserClaims: func(_ context.Context, subject string, scopes []string) (map[string]any, error) {
			out := map[string]any{}
			for _, s := range scopes {
				if s == "email" {
					out["email"] = subject + "@example.com"
				}
			}
			return out, nil
		}},
	})
	mux := http.NewServeMux()
	MountAuthorize(mux, AuthorizeMountConfig{
		OneAuth: oa, IssuerURL: "https://as.example",
		SubjectFromRequest:   func(*http.Request) string { return "alice" },
		CSRFTokenFromRequest: func(*http.Request) string { return "csrf" },
		AutoApproveSubject:   "alice",
	})
	return &implicitFixture{mux: mux, key: key, oa: oa}
}

// authorize sends an implicit request and returns the redirect's query and
// fragment parameters.
func (fx *implicitFixture) authorize(t *testing.T, responseType, scope, nonce string) (query, fragment url.Values) {
	t.Helper()
	v := url.Values{"client_id": {"imp"}, "redirect_uri": {"https://app.example/cb"}, "response_type": {responseType}, "scope": {scope}, "state": {"st"}}
	if nonce != "" {
		v.Set("nonce", nonce)
	}
	rr := httptest.NewRecorder()
	fx.mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+v.Encode(), nil))
	require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "app.example", loc.Host)
	frag, err := url.ParseQuery(loc.Fragment)
	require.NoError(t, err)
	return loc.Query(), frag
}

func (fx *implicitFixture) idTokenClaims(t *testing.T, raw string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return &fx.key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithAudience("imp"), jwt.WithIssuer("https://as.example"))
	require.NoError(t, err)
	return claims
}

func TestImplicit_IDTokenTokenInTheFragment(t *testing.T) {
	fx := newImplicitFixture(t, true, "id_token token")
	query, frag := fx.authorize(t, "id_token token", "openid email", "n-1")
	assert.Empty(t, query, "nothing in the query (OIDC Core §3.2.2.5)")
	assert.Empty(t, frag.Get("code"))
	assert.Empty(t, frag.Get("refresh_token"))
	assert.Equal(t, "st", frag.Get("state"))
	assert.Equal(t, "Bearer", frag.Get("token_type"))
	assert.NotEmpty(t, frag.Get("expires_in"))

	at := frag.Get("access_token")
	require.NotEmpty(t, at)
	info, err := fx.oa.Validator.ValidateToken(context.Background(), &ValidateTokenRequest{Token: at})
	require.NoError(t, err)
	assert.Equal(t, "alice", info.Info.Subject)

	claims := fx.idTokenClaims(t, frag.Get("id_token"))
	assert.Equal(t, "n-1", claims["nonce"])
	sum := sha256.Sum256([]byte(at))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:16]), claims["at_hash"], "at_hash binds the access token (§3.2.2.10)")
	assert.Nil(t, claims["email"], "with an access token, scope claims come from userinfo (§5.4)")
}

// With no access token, the scope's claims go in the ID token (OIDC Core
// §5.4).
func TestImplicit_IDTokenOnlyCarriesScopeClaims(t *testing.T) {
	fx := newImplicitFixture(t, true, "id_token")
	_, frag := fx.authorize(t, "id_token", "openid email", "n-2")
	assert.Empty(t, frag.Get("access_token"))
	claims := fx.idTokenClaims(t, frag.Get("id_token"))
	assert.Equal(t, "alice@example.com", claims["email"])
	assert.Nil(t, claims["at_hash"])
}

// Errors for an implicit request go in the fragment too (RFC 6749
// §4.2.2.1).
func TestImplicit_Refusals(t *testing.T) {
	for name, tc := range map[string]struct {
		registered []string
		rtype      string
		scope      string
		nonce      string
		want       string
	}{
		"no nonce (§3.2.2.1)":        {[]string{"id_token"}, "id_token", "openid", "", "invalid_request"},
		"no openid scope":            {[]string{"id_token"}, "id_token", "email", "n", "invalid_scope"},
		"client registered for code": {nil, "id_token token", "openid", "n", "unauthorized_client"},
		"other implicit type only":   {[]string{"id_token"}, "id_token token", "openid", "n", "unauthorized_client"},
	} {
		fx := newImplicitFixture(t, true, tc.registered...)
		query, frag := fx.authorize(t, tc.rtype, tc.scope, tc.nonce)
		assert.Empty(t, query, name)
		assert.Equal(t, tc.want, frag.Get("error"), name)
		assert.Equal(t, "st", frag.Get("state"), name)
		assert.Empty(t, frag.Get("id_token"), name)
	}
}

// A server without AllowImplicit refuses the implicit types as before,
// whatever the client registered.
func TestImplicit_OffByDefault(t *testing.T) {
	fx := newImplicitFixture(t, false, "id_token token")
	query, frag := fx.authorize(t, "id_token token", "openid", "n")
	assert.Equal(t, "unsupported_response_type", query.Get("error"))
	assert.Empty(t, frag.Get("id_token"))
}

// Implicit needs OIDC (it returns an ID token), and FAPI 2.0 forbids it.
func TestImplicit_ConfigChecks(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Panics(t, func() {
		NewOneAuth(OneAuthConfig{SigningKey: key, SigningAlg: "ES256", AllowImplicit: true})
	}, "no OIDC")
	assert.Panics(t, func() {
		NewOneAuth(OneAuthConfig{SigningKey: key, SigningAlg: "ES256", AllowImplicit: true, FAPI2: true, OIDC: &OIDCConfig{}})
	}, "FAPI 2.0")
}

// The implicit flow's ID token reports acr and amr like the code flow's
// (OIDC Core §2, issue 485), since both come from the same hook.
func TestImplicit_IDTokenCarriesACRAndAMR(t *testing.T) {
	fx := newImplicitFixture(t, true, ResponseTypeIDToken)
	fx.mux = http.NewServeMux()
	MountAuthorize(fx.mux, AuthorizeMountConfig{
		OneAuth: fx.oa, IssuerURL: "https://as.example",
		SubjectFromRequest:   func(*http.Request) string { return "alice" },
		CSRFTokenFromRequest: func(*http.Request) string { return "csrf" },
		AutoApproveSubject:   "alice",
		AuthContextFromRequest: func(_ *http.Request, acrValues []string) AuthContext {
			return AuthContext{ACR: "1", AMR: []string{"pwd"}}
		},
	})
	_, frag := fx.authorize(t, ResponseTypeIDToken, "openid", "n-1")
	claims := fx.idTokenClaims(t, frag.Get("id_token"))
	assert.Equal(t, "1", claims["acr"])
	assert.Equal(t, []any{"pwd"}, claims["amr"])
}
