package apiauth_test

// Error codes and statuses on the refresh grant, matched against what
// Keycloak answers for the same requests (tests/keycloak covers the
// comparison). RFC 6749 §5.2 sends every error with 400 except
// invalid_client, which may be 401, and names invalid_client for "no client
// authentication included".
//
// References:
//   - RFC 6749 §5.2 (https://www.rfc-editor.org/rfc/rfc6749#section-5.2)
//   - OAuth 2.1 §4.3.1 (https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13#section-4.3.1)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/core"
)

// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2
func TestRefreshErrors_InvalidGrantIs400(t *testing.T) {
	fx := newRefreshAuthFixture(t, nil)

	t.Run("token issued to another client", func(t *testing.T) {
		code, body := fx.refresh(t, fx.issue(t, "public-client"), url.Values{"client_id": {"other-client"}})
		assert.Equal(t, "invalid_grant", body["error"])
		assert.Equal(t, http.StatusBadRequest, code)
	})
	t.Run("unknown token", func(t *testing.T) {
		code, body := fx.refresh(t, "no-such-token", url.Values{"client_id": {"public-client"}})
		assert.Equal(t, "invalid_grant", body["error"])
		assert.Equal(t, http.StatusBadRequest, code)
	})
	t.Run("rotated-out token", func(t *testing.T) {
		token := fx.issue(t, "public-client")
		owner := url.Values{"client_id": {"public-client"}}
		first, _ := fx.refresh(t, token, owner)
		require.Equal(t, http.StatusOK, first)
		code, body := fx.refresh(t, token, owner)
		assert.Equal(t, "invalid_grant", body["error"])
		assert.Equal(t, http.StatusBadRequest, code)
	})
}

// A request that doesn't say which client it comes from, for a token that
// belongs to one, has included no client authentication at all.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2 (invalid_client)
func TestRefreshErrors_NoClientIdentificationIsInvalidClient(t *testing.T) {
	fx := newRefreshAuthFixture(t, nil)
	token := fx.issue(t, "public-client")

	code, body := fx.refresh(t, token, nil)

	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Equal(t, "invalid_client", body["error"])
	assert.Nil(t, body["access_token"])
	fx.assertStillRedeemable(t, token, url.Values{"client_id": {"public-client"}})
}

// A token stored with no client still needs no client identification.
func TestRefreshErrors_ClientlessTokenNeedsNoClient(t *testing.T) {
	fx := newRefreshAuthFixture(t, nil)
	created, err := fx.refreshStore.CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{Subject: "u", Scopes: []string{"read"}})
	require.NoError(t, err)

	code, body := fx.refresh(t, created.Token.Token, nil)
	require.Equal(t, http.StatusOK, code, body)
}

// A request naming a different client than the token's owner is refused as
// invalid_grant, without first asking it to authenticate as the owner. It
// can't succeed either way, and the code then says the token isn't theirs.
// Keycloak answers the same.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2 (invalid_grant)
func TestRefreshErrors_ConfidentialTokenUnderAnotherClient(t *testing.T) {
	fx := newRefreshAuthFixture(t, nil)
	token := fx.issue(t, "conf-client")

	code, body := fx.refresh(t, token, url.Values{"client_id": {"public-client"}})

	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_grant", body["error"])
	fx.assertStillRedeemable(t, token, confForm("conf-client"))
}
