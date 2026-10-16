package apiauth_test

// Refresh-token rotation turned off (OneAuthConfig.DisableRefreshTokenRotation).
// FAPI 2.0 §5.3.2.1 has the AS not rotate refresh tokens, so a client whose
// refresh response is lost can retry with the token it holds instead of
// tripping reuse detection and losing the session.
//
// References:
//   - FAPI 2.0 Security Profile §5.3.2.1 (https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1)
//   - RFC 6749 §6 (https://www.rfc-editor.org/rfc/rfc6749#section-6)
//   - RFC 9700 §4.14 (https://www.rfc-editor.org/rfc/rfc9700#section-4.14)
//   - See: https://github.com/panyam/oneauth/issues/395

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

func newNoRotationFixture(t *testing.T, disable bool) *refreshAuthFixture {
	t.Helper()
	store := newInMemoryRefreshStore()
	fx := newAPIAuthFixture(apiauth.OneAuthConfig{
		SigningKey:                  []byte("server-jwt-secret-key-32chars!!"),
		SigningAlg:                  "HS256",
		Issuer:                      "rotation-issuer",
		RefreshStore:                store,
		DisableRefreshTokenRotation: disable,
	}, nil)
	return &refreshAuthFixture{apiAuthFixture: fx, refreshStore: store}
}

func TestRefreshRotationOff_SameTokenRedeemsAgain(t *testing.T) {
	fx := newNoRotationFixture(t, true)
	token := fx.issue(t, "app")
	owner := url.Values{"client_id": {"app"}}

	for i := 0; i < 3; i++ {
		code, body := fx.refresh(t, token, owner)
		require.Equal(t, http.StatusOK, code, "refresh %d: %v", i+1, body)
		assert.NotEmpty(t, body["access_token"])
		assert.Nil(t, body["refresh_token"], "no new refresh token: the client keeps the one it has")
	}

	got, err := fx.refreshStore.GetRefreshToken(context.Background(), &core.GetRefreshTokenRequest{Token: token})
	require.NoError(t, err)
	assert.False(t, got.Token.Revoked, "the token is still live")
}

// A revoked token (logout, RFC 7009) is refused even with rotation off.
func TestRefreshRotationOff_RevokedTokenRefused(t *testing.T) {
	fx := newNoRotationFixture(t, true)
	token := fx.issue(t, "app")
	_, err := fx.refreshStore.RevokeRefreshToken(context.Background(), &core.RevokeRefreshTokenRequest{Token: token})
	require.NoError(t, err)

	code, body := fx.refresh(t, token, url.Values{"client_id": {"app"}})

	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_grant", body["error"])
}

// The client check still applies with rotation off.
func TestRefreshRotationOff_ClientStillChecked(t *testing.T) {
	fx := newNoRotationFixture(t, true)
	token := fx.issue(t, "app")

	_, body := fx.refresh(t, token, url.Values{"client_id": {"someone-else"}})

	assert.Equal(t, "invalid_grant", body["error"])
}

// The default still rotates, and the old token is spent.
func TestRefreshRotationDefault_StillRotates(t *testing.T) {
	fx := newNoRotationFixture(t, false)
	token := fx.issue(t, "app")
	owner := url.Values{"client_id": {"app"}}

	code, body := fx.refresh(t, token, owner)
	require.Equal(t, http.StatusOK, code)
	assert.NotEmpty(t, body["refresh_token"])
	assert.NotEqual(t, token, body["refresh_token"])

	_, body = fx.refresh(t, token, owner)
	assert.Equal(t, "invalid_grant", body["error"])
}
