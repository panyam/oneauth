package oidc_test

// The OIDC sign-in provider against a fake issuer. The fake checks PKCE
// and signs ID tokens with a real key, and the knobs make it misbehave.
// HandleUser must run only for an ID token whose signature, iss, aud,
// exp, nonce and at_hash all check out.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
// See: https://www.rfc-editor.org/rfc/rfc8628
// See: https://github.com/panyam/oneauth/issues/542

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/oauth2/oidc"
	"github.com/panyam/oneauth/utils"
)

const (
	testClientID = "app"
	testSecret   = "app-secret"
	goodCode     = "good-code"
)

type pendingAuth struct{ challenge, nonce string }

// fakeIssuer is a minimal OpenID Provider: discovery, JWKS, token
// (authorization_code and device_code) and device authorization.
type fakeIssuer struct {
	srv  *httptest.Server
	key  *ecdsa.PrivateKey
	mu   sync.Mutex
	auth pendingAuth // the authorize request the test "sent" for goodCode

	// knobs
	noDevice       bool
	noEndSession   bool
	claimIssuer    string // discovery issuer override
	tamper         bool
	wrongNonce     bool
	wrongAud       bool
	omitIDToken    bool
	devicePending  int
	deviceApproved bool
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	f := &fakeIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer":                 f.issuer(),
			"authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint":         f.srv.URL + "/token",
			"jwks_uri":               f.srv.URL + "/jwks",
		}
		if f.claimIssuer != "" {
			doc["issuer"] = f.claimIssuer
		}
		if !f.noDevice {
			doc["device_authorization_endpoint"] = f.srv.URL + "/device"
		}
		if !f.noEndSession {
			doc["end_session_endpoint"] = f.srv.URL + "/logout?tenant=keep"
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(utils.JWKSet{Keys: []utils.JWK{utils.ECDSAPublicKeyToJWK("k1", "ES256", &key.PublicKey)}})
	})
	mux.HandleFunc("POST /device", func(w http.ResponseWriter, r *http.Request) {
		// RFC 8628 §3.1: a confidential client authenticates here too.
		_ = r.ParseForm()
		if r.PostForm.Get("client_id") != testClientID || r.PostForm.Get("client_secret") != testSecret {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dev-1", "user_code": "ABCD-EFGH",
			"verification_uri": f.srv.URL + "/activate", "expires_in": 60, "interval": 1,
		})
	})
	mux.HandleFunc("POST /token", f.token)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) issuer() string { return f.srv.URL }

func (f *fakeIssuer) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if id, secret, _ := r.BasicAuth(); id != testClientID || secret != testSecret {
		if r.PostForm.Get("client_id") != testClientID || r.PostForm.Get("client_secret") != testSecret {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
	}
	nonce := ""
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		f.mu.Lock()
		auth := f.auth
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if r.PostForm.Get("code") != goodCode || base64.RawURLEncoding.EncodeToString(sum[:]) != auth.challenge {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		nonce = auth.nonce
	case "urn:ietf:params:oauth:grant-type:device_code":
		f.mu.Lock()
		pending := f.devicePending > 0
		if pending {
			f.devicePending--
		}
		f.mu.Unlock()
		if pending {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
			return
		}
	default:
		http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
		return
	}
	resp := map[string]any{"access_token": "at-1", "token_type": "Bearer", "expires_in": 300}
	if !f.omitIDToken {
		resp["id_token"] = f.idToken(nonce, "at-1")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeIssuer) idToken(nonce, accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	claims := jwt.MapClaims{
		"iss": f.issuer(), "sub": "user-42", "aud": testClientID,
		"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(),
		"email": "ada@example.com", "email_verified": true,
		"at_hash": base64.RawURLEncoding.EncodeToString(sum[:16]),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if f.wrongNonce {
		claims["nonce"] = "not-the-nonce"
	}
	if f.wrongAud {
		claims["aud"] = "someone-else"
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = "k1"
	signed, err := tok.SignedString(f.key)
	if err != nil {
		panic(err)
	}
	if f.tamper {
		parts := strings.Split(signed, ".")
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		payload = []byte(strings.Replace(string(payload), "user-42", "user-99", 1))
		parts[1] = base64.RawURLEncoding.EncodeToString(payload)
		signed = strings.Join(parts, ".")
	}
	return signed
}

type signedIn struct {
	called   bool
	provider string
	claims   map[string]any
}

func newProvider(t *testing.T, f *fakeIssuer) (*oidc.Provider, *signedIn) {
	t.Helper()
	got := &signedIn{}
	p, err := oidc.New(context.Background(), oidc.Config{
		Issuer: f.issuer(), ClientID: testClientID, ClientSecret: testSecret,
		CallbackURL: "http://app.test/auth/oidc/callback/",
		HandleUser: func(authtype, provider string, token *xoauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
			got.called, got.provider, got.claims = true, provider, userInfo
			w.WriteHeader(http.StatusOK)
		},
	})
	require.NoError(t, err)
	return p, got
}

// startSignIn runs GET / and records the authorize request on the fake,
// as the provider's authorize page would. It returns the browser cookies
// and the authorize URL.
func startSignIn(t *testing.T, p *oidc.Provider, f *fakeIssuer) ([]*http.Cookie, *url.URL) {
	t.Helper()
	rr := httptest.NewRecorder()
	p.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusFound, rr.Code)
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	q := loc.Query()
	f.mu.Lock()
	f.auth = pendingAuth{challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
	f.mu.Unlock()
	return rr.Result().Cookies(), loc
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
	f := newFakeIssuer(t)
	p, got := newProvider(t, f)
	cookies, loc := startSignIn(t, p, f)

	q := loc.Query()
	assert.Equal(t, f.srv.URL+"/authorize", loc.Scheme+"://"+loc.Host+loc.Path)
	assert.Equal(t, "openid email profile", q.Get("scope"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.NotEmpty(t, q.Get("nonce"))
	assert.NotEqual(t, q.Get("nonce"), q.Get("state"))

	rr := finishSignIn(p, cookies, q.Get("state"), goodCode)
	require.True(t, got.called, rr.Body.String())
	assert.Equal(t, "oidc", got.provider)
	assert.Equal(t, "user-42", got.claims["sub"])
	assert.Equal(t, "ada@example.com", got.claims["email"])
	assert.Equal(t, q.Get("nonce"), got.claims["nonce"])
}

func TestOIDCSignIn_RefusesBadIDTokens(t *testing.T) {
	for name, knob := range map[string]func(*fakeIssuer){
		"tampered signature": func(f *fakeIssuer) { f.tamper = true },
		"wrong nonce":        func(f *fakeIssuer) { f.wrongNonce = true },
		"wrong audience":     func(f *fakeIssuer) { f.wrongAud = true },
		"no id_token":        func(f *fakeIssuer) { f.omitIDToken = true },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeIssuer(t)
			knob(f)
			p, got := newProvider(t, f)
			cookies, loc := startSignIn(t, p, f)
			rr := finishSignIn(p, cookies, loc.Query().Get("state"), goodCode)
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
			f := newFakeIssuer(t)
			p, got := newProvider(t, f)
			cookies, loc := startSignIn(t, p, f)
			state := loc.Query().Get("state")
			if tc.badState {
				state = "forged"
			}
			rr := finishSignIn(p, without(cookies, tc.drop), state, goodCode)
			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.False(t, got.called)
		})
	}
}

func TestOIDCSignIn_New(t *testing.T) {
	f := newFakeIssuer(t)
	handle := func(string, string, *xoauth2.Token, map[string]any, http.ResponseWriter, *http.Request) {}

	f.claimIssuer = "https://evil.example"
	_, err := oidc.New(context.Background(), oidc.Config{Issuer: f.issuer(), ClientID: testClientID, HandleUser: handle})
	assert.ErrorIs(t, err, client.ErrMetadataIssuerMismatch)
	f.claimIssuer = ""

	_, err = oidc.New(context.Background(), oidc.Config{Issuer: "http://idp.example.com", ClientID: testClientID, HandleUser: handle})
	assert.ErrorContains(t, err, "must use https")

	_, err = oidc.New(context.Background(), oidc.Config{Issuer: f.issuer(), HandleUser: handle})
	assert.ErrorContains(t, err, "ClientID")

	p, err := oidc.New(context.Background(), oidc.Config{Issuer: f.issuer(), ClientID: testClientID, HandleUser: handle})
	require.NoError(t, err)
	assert.Equal(t, f.srv.URL+"/device", p.Metadata().DeviceAuthorizationEndpoint)
}

func TestOIDCSignIn_DeviceFlow(t *testing.T) {
	f := newFakeIssuer(t)
	f.devicePending = 1
	p, _ := newProvider(t, f)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	da, err := p.DeviceAuth(ctx)
	require.NoError(t, err)
	assert.Equal(t, "ABCD-EFGH", da.UserCode)

	token, claims, err := p.DeviceAccessToken(ctx, da)
	require.NoError(t, err)
	assert.Equal(t, "at-1", token.AccessToken)
	assert.Equal(t, "user-42", claims.Subject)
	assert.Equal(t, f.issuer(), claims.Issuer)
}

func TestOIDCSignIn_DeviceFlowRefusesTamperedIDToken(t *testing.T) {
	f := newFakeIssuer(t)
	f.tamper = true
	p, _ := newProvider(t, f)
	da, err := p.DeviceAuth(context.Background())
	require.NoError(t, err)
	_, _, err = p.DeviceAccessToken(context.Background(), da)
	assert.ErrorIs(t, err, client.ErrInvalidIDToken)
}

func TestOIDCSignIn_NoDeviceEndpoint(t *testing.T) {
	f := newFakeIssuer(t)
	f.noDevice = true
	p, _ := newProvider(t, f)
	_, err := p.DeviceAuth(context.Background())
	assert.True(t, errors.Is(err, oidc.ErrNoDeviceEndpoint))
}
