package oidc_test

// The OIDC sign-in provider against oidctest, the fake issuer apps use
// too. The fake checks PKCE and signs ID tokens with a real key, and its
// With* options make it misbehave.
// HandleUser must run only for an ID token whose signature, iss, aud,
// exp, nonce and at_hash all check out.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
// See: https://www.rfc-editor.org/rfc/rfc8628
// See: https://github.com/panyam/oneauth/issues/542
// See: https://github.com/panyam/oneauth/issues/566

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/oauth2/oidc"
	"github.com/panyam/oneauth/oauth2/oidc/oidctest"
)

const (
	testClientID = "app"
	testSecret   = "app-secret"
	testSub      = "user-42"
)

// newIssuer starts the fake issuer with the app's client and one person,
// who is signed in for the web flow.
func newIssuer(t *testing.T, opts ...oidctest.Option) *oidctest.Server {
	t.Helper()
	iss := oidctest.New(t, append([]oidctest.Option{oidctest.WithClient(testClientID, testSecret)}, opts...)...)
	iss.AddUser(testSub, map[string]any{"email": "ada@example.com", "email_verified": true})
	iss.SignInAs(testSub)
	return iss
}

// tamper changes the ID token's payload after signing, so its signature
// no longer matches.
func tamper(resp map[string]any) {
	parts := strings.Split(resp["id_token"].(string), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	payload = []byte(strings.Replace(string(payload), testSub, "user-99", 1))
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	resp["id_token"] = strings.Join(parts, ".")
}

type signedIn struct {
	called   bool
	provider string
	claims   map[string]any
}

func newProvider(t *testing.T, iss *oidctest.Server) (*oidc.Provider, *signedIn) {
	t.Helper()
	got := &signedIn{}
	p, err := oidc.New(context.Background(), oidc.Config{
		Issuer: iss.URL, ClientID: testClientID, ClientSecret: testSecret,
		CallbackURL: "http://app.test/auth/oidc/callback/",
		HandleUser: func(authtype, provider string, token *xoauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			got.called, got.provider, got.claims = true, provider, userInfo
			w.WriteHeader(http.StatusOK)
		},
	})
	require.NoError(t, err)
	return p, got
}

// startSignIn runs GET / on the provider, then sends the browser to the
// fake's authorize endpoint, which redirects back with a code for the
// signed-in person. It returns the provider's cookies, the authorize URL,
// and the query the fake sent back to the callback.
func startSignIn(t *testing.T, p *oidc.Provider) ([]*http.Cookie, *url.URL, url.Values) {
	t.Helper()
	rr := httptest.NewRecorder()
	p.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusFound, rr.Code)
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(loc.String())
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	back, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/auth/oidc/callback/", back.Path)
	return rr.Result().Cookies(), loc, back.Query()
}

func finishSignIn(p *oidc.Provider, cookies []*http.Cookie, state, code string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/callback/?"+url.Values{"state": {state}, "code": {code}}.Encode(), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	p.Handler().ServeHTTP(rr, req)
	return rr
}

func TestOIDCSignIn_WebFlow(t *testing.T) {
	iss := newIssuer(t)
	p, got := newProvider(t, iss)
	cookies, loc, back := startSignIn(t, p)

	q := loc.Query()
	assert.Equal(t, iss.URL+"/authorize", loc.Scheme+"://"+loc.Host+loc.Path)
	assert.Equal(t, "openid email profile", q.Get("scope"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.NotEmpty(t, q.Get("nonce"))
	assert.NotEqual(t, q.Get("nonce"), q.Get("state"))
	assert.Equal(t, q.Get("state"), back.Get("state"))

	rr := finishSignIn(p, cookies, back.Get("state"), back.Get("code"))
	require.True(t, got.called, rr.Body.String())
	assert.Equal(t, "oidc", got.provider)
	assert.Equal(t, testSub, got.claims["sub"])
	assert.Equal(t, "ada@example.com", got.claims["email"])
	assert.Equal(t, q.Get("nonce"), got.claims["nonce"])
}

func TestOIDCSignIn_RefusesBadIDTokens(t *testing.T) {
	for name, opt := range map[string]oidctest.Option{
		"tampered signature": oidctest.WithTokenResponse(tamper),
		"wrong nonce":        oidctest.WithIDTokenClaims(func(c map[string]any) { c["nonce"] = "not-the-nonce" }),
		"wrong audience":     oidctest.WithIDTokenClaims(func(c map[string]any) { c["aud"] = "someone-else" }),
		"no id_token":        oidctest.WithTokenResponse(func(r map[string]any) { delete(r, "id_token") }),
	} {
		t.Run(name, func(t *testing.T) {
			iss := newIssuer(t, opt)
			p, got := newProvider(t, iss)
			cookies, _, back := startSignIn(t, p)
			rr := finishSignIn(p, cookies, back.Get("state"), back.Get("code"))
			assert.False(t, got.called)
			assert.Equal(t, http.StatusTemporaryRedirect, rr.Code)
			assert.Equal(t, "/auth/failed", rr.Header().Get("Location"))
		})
	}
}

func TestOIDCSignIn_RefusesCallbackNotStartedHere(t *testing.T) {
	without := func(cookies []*http.Cookie, name string) []*http.Cookie {
		var out []*http.Cookie
		for _, c := range cookies {
			if c.Name != name {
				out = append(out, c)
			}
		}
		return out
	}
	for name, tc := range map[string]struct {
		drop     string
		badState bool
	}{
		"state mismatch":   {badState: true},
		"no state cookie":  {drop: "oauthstate"},
		"no nonce cookie":  {drop: oidc.NonceCookieName},
		"no PKCE verifier": {drop: "pkce_verifier"},
	} {
		t.Run(name, func(t *testing.T) {
			iss := newIssuer(t)
			p, got := newProvider(t, iss)
			cookies, _, back := startSignIn(t, p)
			state := back.Get("state")
			if tc.badState {
				state = "forged"
			}
			rr := finishSignIn(p, without(cookies, tc.drop), state, back.Get("code"))
			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.False(t, got.called)
		})
	}
}

func TestOIDCSignIn_New(t *testing.T) {
	handle := func(string, string, *xoauth2.Token, map[string]any, http.ResponseWriter, *http.Request) {}

	liar := newIssuer(t, oidctest.WithDiscovery(func(doc map[string]any) { doc["issuer"] = "https://evil.example" }))
	_, err := oidc.New(context.Background(), oidc.Config{Issuer: liar.URL, ClientID: testClientID, HandleUser: handle})
	assert.ErrorIs(t, err, client.ErrMetadataIssuerMismatch)

	iss := newIssuer(t)
	_, err = oidc.New(context.Background(), oidc.Config{Issuer: "http://idp.example.com", ClientID: testClientID, HandleUser: handle})
	assert.ErrorContains(t, err, "must use https")

	_, err = oidc.New(context.Background(), oidc.Config{Issuer: iss.URL, HandleUser: handle})
	assert.ErrorContains(t, err, "ClientID")

	p, err := oidc.New(context.Background(), oidc.Config{Issuer: iss.URL, ClientID: testClientID, HandleUser: handle})
	require.NoError(t, err)
	assert.Equal(t, iss.URL+"/device_authorization", p.Metadata().DeviceAuthorizationEndpoint)
}

// The person approves after the provider's first poll, so the provider
// sees authorization_pending once before the tokens.
func TestOIDCSignIn_DeviceFlow(t *testing.T) {
	iss := newIssuer(t)
	p, _ := newProvider(t, iss)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	da, err := p.DeviceAuth(ctx)
	require.NoError(t, err)
	assert.Regexp(t, `^[A-Z]{4}-[A-Z]{4}$`, da.UserCode)

	approved := make(chan bool, 1)
	go func() {
		time.Sleep(1500 * time.Millisecond)
		approved <- iss.Approve(da.UserCode, testSub)
	}()
	token, claims, err := p.DeviceAccessToken(ctx, da)
	require.NoError(t, err)
	require.True(t, <-approved)
	assert.NotEmpty(t, token.AccessToken)
	assert.Equal(t, testSub, claims.Subject)
	assert.Equal(t, iss.URL, claims.Issuer)
}

func TestOIDCSignIn_DeviceFlowRefusesTamperedIDToken(t *testing.T) {
	iss := newIssuer(t, oidctest.WithTokenResponse(tamper))
	p, _ := newProvider(t, iss)
	da, err := p.DeviceAuth(context.Background())
	require.NoError(t, err)
	require.True(t, iss.Approve(da.UserCode, testSub))
	_, _, err = p.DeviceAccessToken(context.Background(), da)
	assert.ErrorIs(t, err, client.ErrInvalidIDToken)
}

// A denied code ends polling with access_denied. Before the provider set
// AuthStyle, x/oauth2 resent each failed poll at once, the fake answered
// the resend with slow_down, and polling ran to the deadline.
//
// See: https://www.rfc-editor.org/rfc/rfc8628#section-3.5
func TestOIDCSignIn_DeviceFlowDenied(t *testing.T) {
	iss := newIssuer(t)
	p, _ := newProvider(t, iss)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	da, err := p.DeviceAuth(ctx)
	require.NoError(t, err)
	require.True(t, iss.Deny(da.UserCode))
	_, _, err = p.DeviceAccessToken(ctx, da)
	var re *xoauth2.RetrieveError
	require.ErrorAs(t, err, &re, "polling should end with the provider's answer, not the deadline")
	assert.Equal(t, "access_denied", re.ErrorCode)
}

func TestOIDCSignIn_NoDeviceEndpoint(t *testing.T) {
	iss := newIssuer(t, oidctest.WithDiscovery(func(doc map[string]any) { delete(doc, "device_authorization_endpoint") }))
	p, _ := newProvider(t, iss)
	_, err := p.DeviceAuth(context.Background())
	assert.True(t, errors.Is(err, oidc.ErrNoDeviceEndpoint))
}
