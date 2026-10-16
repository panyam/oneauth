package keycloak_test

// Keycloak signs its ID tokens with the same RS256 key as its access
// tokens, with the same header typ ("JWT") and, for a confidential client,
// the same aud. Only the typ claim tells them apart ("ID" versus
// "Bearer"). A resource server validating through Keycloak's JWKS must
// still refuse an ID token presented as an access token.
//
// References:
//   - RFC 8725 §3.11 (https://www.rfc-editor.org/rfc/rfc8725#section-3.11)
//   - RFC 9068 §4 (https://www.rfc-editor.org/rfc/rfc9068#section-4)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/testutil"
)

// See: https://www.rfc-editor.org/rfc/rfc8725#section-3.11
func TestKeycloak_OnlyTheAccessTokenIsAnAccessToken(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	cfg := discoverOIDC(t)
	tok := testutil.PostTokenEndpoint(t, cfg.TokenEndpoint, url.Values{
		"grant_type": {"password"}, "scope": {"openid"},
		"client_id": {confidentialClientID}, "client_secret": {confidentialClientSecret},
		"username": {testUsername}, "password": {testPassword},
	})
	require.NotEmpty(t, tok.IDToken, "Keycloak returns an ID token for scope=openid")
	require.Equal(t, "ID", parseJWTClaims(t, tok.IDToken)["typ"])
	require.Equal(t, parseJWTHeader(t, tok.AccessToken)["alg"], parseJWTHeader(t, tok.IDToken)["alg"], "same signing key family as the access token")

	ks := keys.NewJWKSKeyStore(cfg.JWKSURI, keys.WithMinRefreshGap(0))
	require.NoError(t, ks.Start())
	defer ks.Stop()

	mw := &apiauth.APIMiddleware{KeyStore: ks}
	status := func(token string) int {
		req := httptest.NewRequest(http.MethodGet, "/api", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(rr, req)
		return rr.Code
	}
	v := apiauth.NewJWTValidator(apiauth.JWTValidatorConfig{KeyLookup: ks})
	validate := func(token string) error {
		_, err := v.ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: token})
		return err
	}

	assert.Equal(t, http.StatusOK, status(tok.AccessToken), "access token at the middleware")
	assert.NoError(t, validate(tok.AccessToken), "access token at the validator")

	assert.Equal(t, http.StatusUnauthorized, status(tok.IDToken), "ID token at the middleware")
	assert.Error(t, validate(tok.IDToken), "ID token at the validator")

	// Keycloak's refresh token is HS512 under a realm secret, so it can't
	// verify against the JWKS at all.
	assert.Equal(t, http.StatusUnauthorized, status(tok.RefreshToken), "refresh token at the middleware")
}
