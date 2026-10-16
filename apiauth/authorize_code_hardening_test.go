package apiauth_test

// Authorization-code redemption, issue 88's "Token Security" walk: the
// access token says which client it was issued to, and a code redeemed by
// two requests at once gives tokens to only one of them.
//
// References:
//   - RFC 6749 §4.1.2, §10.5 (https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2)
//   - RFC 9068 §2.2 client_id (https://www.rfc-editor.org/rfc/rfc9068#section-2.2)
//   - CWE-367 (https://cwe.mitre.org/data/definitions/367.html)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

// The token's client_id is what revocation ownership and the resource
// server's tenant checks go by.
//
// See: https://www.rfc-editor.org/rfc/rfc9068#section-2.2
func TestAuthCodeHardening_AccessTokenNamesTheClient(t *testing.T) {
	auth, store := setupAuthCode(t)
	seedAuthCode(t, store, "code-1")

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenRedeemForm(t, nil))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))

	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(body["access_token"].(string), claims)
	require.NoError(t, err)
	assert.Equal(t, authcodeTestClientID, claims["client_id"])
}

// staleCodeStore answers GetAuthorizationCode from a snapshot, the way a
// second request sees the code when it reads before the first one deletes.
type staleCodeStore struct {
	core.AuthorizationCodeStore
	snapshot *core.AuthorizationCode
}

func (s *staleCodeStore) GetAuthorizationCode(_ context.Context, _ *core.GetAuthorizationCodeRequest) (*core.GetAuthorizationCodeResponse, error) {
	c := *s.snapshot
	return &core.GetAuthorizationCodeResponse{Code: &c}, nil
}

// Two redemptions racing on one code: the loser reaches the delete after
// the winner and must get invalid_grant, the same answer as a late replay.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2
// See: https://cwe.mitre.org/data/definitions/367.html
func TestAuthCodeHardening_RacingRedemptionIsInvalidGrant(t *testing.T) {
	inner := core.NewInMemoryAuthorizationCodeStore()
	seedAuthCode(t, inner, "code-1")
	got, err := inner.GetAuthorizationCode(context.Background(), &core.GetAuthorizationCodeRequest{Code: "code-1"})
	require.NoError(t, err)

	fx := newAPIAuthFixture(apiauth.OneAuthConfig{
		SigningKey:             []byte("authcode-test-secret-32chars-min!"),
		SigningAlg:             "HS256",
		Issuer:                 "test-issuer",
		AuthorizationCodeStore: &staleCodeStore{AuthorizationCodeStore: inner, snapshot: got.Code},
	}, nil)

	first := httptest.NewRecorder()
	fx.ServeHTTP(first, tokenRedeemForm(t, nil))
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())

	second := httptest.NewRecorder()
	fx.ServeHTTP(second, tokenRedeemForm(t, nil))
	assert.Equal(t, http.StatusBadRequest, second.Code, second.Body.String())
	assert.Contains(t, second.Body.String(), `"invalid_grant"`)
	assert.NotContains(t, second.Body.String(), "access_token")
}
