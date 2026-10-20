package client

// LoginWithBrowser with VerifyIDToken: a nonce goes on the authorization
// request, and the ID token from the code exchange must come back and pass
// VerifyIDToken before the credential is stored.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
// See: https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
// See: https://github.com/panyam/oneauth/issues/453

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/utils"
)

// oidcMockAS is an AS that issues ES256 ID tokens. nonceOverride, when
// set, replaces the nonce the authorization request sent, and omitIDToken
// leaves the ID token out of the token response.
type oidcMockAS struct {
	srv           *httptest.Server
	nonceOverride string
	omitIDToken   bool

	mu        sync.Mutex
	sentNonce string
	sentScope string
}

func newOIDCMockAS(t *testing.T) *oidcMockAS {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kid, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	jwk, err := utils.PublicKeyToJWK(kid, "ES256", &key.PublicKey)
	require.NoError(t, err)

	as := &oidcMockAS{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           as.srv.URL,
			"authorization_endpoint":           as.srv.URL + "/authorize",
			"token_endpoint":                   as.srv.URL + "/token",
			"jwks_uri":                         as.srv.URL + "/jwks",
			"code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(utils.JWKSet{Keys: []utils.JWK{jwk}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		as.mu.Lock()
		as.sentNonce, as.sentScope = q.Get("nonce"), q.Get("scope")
		as.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=c-453&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		as.mu.Lock()
		nonce := as.sentNonce
		as.mu.Unlock()
		if as.nonceOverride != "" {
			nonce = as.nonceOverride
		}
		resp := map[string]any{"access_token": idtAccess, "token_type": "Bearer", "expires_in": 300}
		if !as.omitIDToken {
			claims := idtClaims()
			claims["iss"], claims["aud"], claims["nonce"] = as.srv.URL, r.FormValue("client_id"), nonce
			tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			tok.Header["kid"] = kid
			resp["id_token"], _ = tok.SignedString(key)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	as.srv = httptest.NewServer(mux)
	t.Cleanup(as.srv.Close)
	return as
}

// sent returns the nonce and scope the authorization request carried.
func (as *oidcMockAS) sent() (nonce, scope string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.sentNonce, as.sentScope
}

func (as *oidcMockAS) login(t *testing.T, verify bool) (*ServerCredential, error) {
	t.Helper()
	return NewAuthClient(as.srv.URL, nil).LoginWithBrowser(context.Background(), &BrowserLoginRequest{
		ClientID:      idtClient,
		Scopes:        []string{"email"},
		Timeout:       5 * time.Second,
		VerifyIDToken: verify,
		OpenBrowser: func(authURL string) error {
			go simulateBrowser(authURL)
			return nil
		},
	})
}

func TestLoginWithBrowser_VerifyIDToken(t *testing.T) {
	as := newOIDCMockAS(t)
	cred, err := as.login(t, true)
	require.NoError(t, err)

	nonce, scope := as.sent()
	assert.Len(t, nonce, 22, "a fresh 128-bit nonce, base64url")
	assert.Equal(t, "email openid", scope, "openid is added when missing")
	require.NotNil(t, cred.IDTokenClaims)
	assert.Equal(t, nonce, cred.IDTokenClaims.Nonce)
	assert.Equal(t, "user-1", cred.UserID)
	assert.Equal(t, "ada@example.com", cred.UserEmail)
	assert.NotEmpty(t, cred.IDToken)
}

func TestLoginWithBrowser_VerifyIDTokenRefusesAnotherNonce(t *testing.T) {
	as := newOIDCMockAS(t)
	as.nonceOverride = "n-replayed-from-another-login"
	_, err := as.login(t, true)
	require.ErrorIs(t, err, ErrInvalidIDToken)
	assert.Contains(t, err.Error(), "nonce")
}

func TestLoginWithBrowser_VerifyIDTokenRequiresAnIDToken(t *testing.T) {
	as := newOIDCMockAS(t)
	as.omitIDToken = true
	_, err := as.login(t, true)
	require.ErrorIs(t, err, ErrInvalidIDToken)
}

// Without VerifyIDToken the login is unchanged: no nonce, no openid
// added, and an ID token in the response is kept as received but not
// checked.
func TestLoginWithBrowser_IDTokenKeptUnverifiedByDefault(t *testing.T) {
	as := newOIDCMockAS(t)
	as.nonceOverride = "n-unchecked"
	cred, err := as.login(t, false)
	require.NoError(t, err)

	nonce, scope := as.sent()
	assert.Empty(t, nonce)
	assert.Equal(t, "email", scope)
	assert.NotEmpty(t, cred.IDToken)
	assert.Nil(t, cred.IDTokenClaims)
	assert.Empty(t, cred.UserID)
}
