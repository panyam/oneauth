package apiauth_test

// Revocation and introspection, issue 88's "Token Security" walk: a client
// may revoke only its own tokens, an unverified token never touches the
// blacklist, and introspection reports refresh tokens and the RFC 6749 §7.1
// token type.
//
// References:
//   - RFC 7009 §2.1, §2.2.1 (https://www.rfc-editor.org/rfc/rfc7009#section-2.1)
//   - RFC 7662 §2.2 (https://www.rfc-editor.org/rfc/rfc7662#section-2.2)
//   - CWE-639 (https://cwe.mitre.org/data/definitions/639.html)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"encoding/json"
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
)

const ownershipSigningKey = "ownership-test-signing-key-32-by"

type ownershipFixture struct {
	revoke, introspect http.Handler
	fx                 *apiAuthFixture
}

func setupOwnership(t *testing.T) *ownershipFixture {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	for _, c := range []string{"client-a", "client-b"} {
		_, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: c, Key: []byte(c + "-secret"), Algorithm: "HS256"}})
		require.NoError(t, err)
	}
	fx := newAPIAuthFixture(apiauth.OneAuthConfig{
		KeyStore:     ks,
		SigningKey:   []byte(ownershipSigningKey),
		SigningAlg:   "HS256",
		Issuer:       "test-issuer",
		Blacklist:    core.NewInMemoryBlacklist(),
		RefreshStore: newInMemoryRefreshStore(),
	}, nil)
	return &ownershipFixture{revoke: fx.OneAuth.RevocationHTTPHandler(), introspect: fx.OneAuth.IntrospectionHTTPHandler(), fx: fx}
}

func (o *ownershipFixture) accessToken(t *testing.T, clientID string) string {
	t.Helper()
	resp, err := o.fx.Issuer().CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "alice", ClientID: clientID, Scopes: []string{"read"}})
	require.NoError(t, err)
	return resp.Token
}

func (o *ownershipFixture) introspection(t *testing.T, token string) map[string]any {
	t.Helper()
	rr := postIntrospect(t, o.introspect, token, "client-a", "client-a-secret")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	return body
}

func oauthError(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), rr.Body.String())
	return body["error"]
}

// Client B holding client A's access token can't revoke it, and is told so.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
func TestRevocation_AccessTokenOfAnotherClientIsRefused(t *testing.T) {
	o := setupOwnership(t)
	tok := o.accessToken(t, "client-a")

	rr := postRevoke(t, o.revoke, tok, "access_token", "client-b", "client-b-secret")
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_request", oauthError(t, rr))
	assert.Equal(t, true, o.introspection(t, tok)["active"], "client A's token must survive client B's request")

	rr = postRevoke(t, o.revoke, tok, "access_token", "client-a", "client-a-secret")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, false, o.introspection(t, tok)["active"], "client A revokes its own token")
}

// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
func TestRevocation_RefreshTokenOfAnotherClientIsRefused(t *testing.T) {
	o := setupOwnership(t)
	created, err := o.fx.RefreshTokenStore().CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{Subject: "alice", ClientID: "client-a", Scopes: []string{"read"}})
	require.NoError(t, err)
	rt := created.Token.Token

	for _, hint := range []string{"refresh_token", ""} {
		rr := postRevoke(t, o.revoke, rt, hint, "client-b", "client-b-secret")
		assert.Equal(t, http.StatusBadRequest, rr.Code, "hint %q", hint)
		got, err := o.fx.RefreshTokenStore().GetRefreshToken(context.Background(), &core.GetRefreshTokenRequest{Token: rt})
		require.NoError(t, err)
		assert.False(t, got.Token.Revoked, "hint %q: client B revoked client A's refresh token", hint)
	}
}

// Anyone could put a victim's jti into an unsigned token. Only a token that
// verifies may reach the blacklist.
//
// See: https://cwe.mitre.org/data/definitions/347.html
func TestRevocation_UnverifiedTokenNeverReachesTheBlacklist(t *testing.T) {
	o := setupOwnership(t)
	victim := o.accessToken(t, "client-a")
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(victim, claims)
	require.NoError(t, err)

	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"jti": claims["jti"], "client_id": "client-b", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("attacker-key-attacker-key-attack"))
	require.NoError(t, err)

	rr := postRevoke(t, o.revoke, forged, "access_token", "client-b", "client-b-secret")
	assert.Equal(t, http.StatusOK, rr.Code, "an invalid token gets 200 (RFC 7009 §2.2)")
	assert.Equal(t, true, o.introspection(t, victim)["active"], "the victim's token must survive a forged jti")
}

// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
func TestRevocation_MissingTokenIsInvalidRequest(t *testing.T) {
	o := setupOwnership(t)
	rr := postRevoke(t, o.revoke, "", "", "client-a", "client-a-secret")
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_request", oauthError(t, rr))
}

// token_type is the RFC 6749 §7.1 access-token type, as in the token
// response, not the literal "access_token".
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
func TestIntrospection_TokenTypeIsTheAccessTokenType(t *testing.T) {
	o := setupOwnership(t)
	assert.Equal(t, "Bearer", o.introspection(t, o.accessToken(t, "client-a"))["token_type"])
}

// RFC 7662 §2.1 lets the caller introspect refresh tokens, and a revoked or
// expired one is inactive.
//
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.1
func TestIntrospection_RefreshTokens(t *testing.T) {
	o := setupOwnership(t)
	created, err := o.fx.RefreshTokenStore().CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{Subject: "alice", ClientID: "client-a", Scopes: []string{"read", "write"}})
	require.NoError(t, err)
	rt := created.Token.Token

	got := o.introspection(t, rt)
	assert.Equal(t, true, got["active"])
	assert.Equal(t, "alice", got["sub"])
	assert.Equal(t, "client-a", got["client_id"])
	assert.Equal(t, "read write", got["scope"])
	assert.NotContains(t, got, "token_type", "token_type names an access-token type")
	assert.NotZero(t, got["exp"])

	rr := postRevoke(t, o.revoke, rt, "refresh_token", "client-a", "client-a-secret")
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, false, o.introspection(t, rt)["active"])

	// token_type_hint is a hint: a refresh token with the access hint still resolves.
	created, err = o.fx.RefreshTokenStore().CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{Subject: "bob", ClientID: "client-a"})
	require.NoError(t, err)
	form := url.Values{"token": {created.Token.Token}, "token_type_hint": {"access_token"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("client-a", "client-a-secret")
	rec := httptest.NewRecorder()
	o.introspect.ServeHTTP(rec, req)
	assert.Contains(t, rec.Body.String(), `"active":true`)
}

// The AS's own token for a client that also has a key in the KeyStore is
// verified with the AS's key. Resolving it by its client_id claim checked it
// against the client's key, and it never verified.
func TestValidation_ASTokenNamingARegisteredClientVerifies(t *testing.T) {
	o := setupOwnership(t)
	got := o.introspection(t, o.accessToken(t, "client-a"))
	assert.Equal(t, true, got["active"])
	assert.Equal(t, "client-a", got["client_id"])
}
