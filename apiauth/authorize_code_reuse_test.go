package apiauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/stores/fs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupCodeReuse(t *testing.T, codes core.AuthorizationCodeStore) *apiAuthFixture {
	t.Helper()
	return newAPIAuthFixture(apiauth.OneAuthConfig{
		SigningKey:             []byte("authcode-test-secret-32chars-min!"),
		SigningAlg:             "HS256",
		Issuer:                 "test-issuer",
		Blacklist:              core.NewInMemoryBlacklist(),
		RefreshStore:           fs.NewFSRefreshTokenStore(t.TempDir()),
		AuthorizationCodeStore: codes,
	}, nil)
}

func redeemCode(t *testing.T, fx *apiAuthFixture) (int, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	fx.ServeHTTP(rr, tokenRedeemForm(t, nil))
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), rr.Body.String())
	return rr.Code, body
}

// assertTokensRevoked checks both tokens from a redemption: the access
// token no longer validates and the refresh token no longer redeems.
func assertTokensRevoked(t *testing.T, fx *apiAuthFixture, tokens map[string]any) {
	t.Helper()
	_, err := fx.OneAuth.Validator.ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: tokens["access_token"].(string)})
	assert.Error(t, err, "the access token from the first redemption MUST be revoked")

	rr := httptest.NewRecorder()
	fx.ServeHTTP(rr, tokenRedeemForm(t, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens["refresh_token"].(string)},
		"code":          nil, "code_verifier": nil, "redirect_uri": nil,
	}))
	assert.Equal(t, http.StatusBadRequest, rr.Code, "the refresh token from the first redemption MUST be revoked: %s", rr.Body.String())
	assert.Contains(t, rr.Body.String(), `"invalid_grant"`)
}

// A code presented a second time is refused, and the tokens the first
// redemption produced are revoked: the second presentation means the
// code leaked, so whoever holds those tokens may not be the client.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.5
func TestAuthCodeReuse_RevokesFirstRedemptionsTokens(t *testing.T) {
	codes := core.NewInMemoryAuthorizationCodeStore()
	fx := setupCodeReuse(t, codes)
	seedAuthCode(t, codes, "code-1")

	status, first := redeemCode(t, fx)
	require.Equal(t, http.StatusOK, status, first)
	require.NotEmpty(t, first["refresh_token"])
	_, err := fx.OneAuth.Validator.ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: first["access_token"].(string)})
	require.NoError(t, err, "the token is valid before the reuse")

	status, second := redeemCode(t, fx)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", second["error"])
	assert.Nil(t, second["access_token"])

	assertTokensRevoked(t, fx, first)
}

// A reuse after the code's own lifetime still revokes, because the used
// record is kept until the access token it produced expires.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2
func TestAuthCodeReuse_AfterCodeExpiryStillRevokes(t *testing.T) {
	codes := core.NewInMemoryAuthorizationCodeStore()
	fx := setupCodeReuse(t, codes)
	seedAuthCode(t, codes, "code-1")

	status, first := redeemCode(t, fx)
	require.Equal(t, http.StatusOK, status, first)

	expireCode(t, codes, "code-1")
	_, err := codes.CleanupExpired(context.Background(), &core.CleanupExpiredAuthorizationCodesRequest{})
	require.NoError(t, err)

	status, second := redeemCode(t, fx)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", second["error"])

	assertTokensRevoked(t, fx, first)
}

// Two redemptions racing: the second one consumes after the first but
// before the first has recorded its tokens, so it has nothing to revoke.
// The first must notice the reuse when it records, and refuse.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2
// See: https://cwe.mitre.org/data/definitions/367.html
func TestAuthCodeReuse_RaceRefusesTheFirstRedemption(t *testing.T) {
	inner := core.NewInMemoryAuthorizationCodeStore()
	seedAuthCode(t, inner, "code-1")
	fx := setupCodeReuse(t, &reuseBeforeRecordStore{AuthorizationCodeStore: inner})

	status, body := redeemCode(t, fx)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Nil(t, body["access_token"], "a redemption that raced a reuse MUST NOT hand out tokens")
}

// reuseBeforeRecordStore presents the code a second time between the
// redemption's consume and its record, the window the race test needs.
type reuseBeforeRecordStore struct {
	core.AuthorizationCodeStore
}

func (s *reuseBeforeRecordStore) RecordAuthorizationCodeTokens(ctx context.Context, req *core.RecordAuthorizationCodeTokensRequest) (*core.RecordAuthorizationCodeTokensResponse, error) {
	_, _ = s.AuthorizationCodeStore.ConsumeAuthorizationCode(ctx, &core.ConsumeAuthorizationCodeRequest{Code: req.Code})
	return s.AuthorizationCodeStore.RecordAuthorizationCodeTokens(ctx, req)
}

// expireCode moves a stored code's own expiry into the past.
func expireCode(t *testing.T, codes core.AuthorizationCodeStore, code string) {
	t.Helper()
	got, err := codes.GetAuthorizationCode(context.Background(), &core.GetAuthorizationCodeRequest{Code: code})
	require.NoError(t, err)
	c := got.Code
	c.ExpiresAt = c.IssuedAt
	_, err = codes.DeleteAuthorizationCode(context.Background(), &core.DeleteAuthorizationCodeRequest{Code: code})
	require.NoError(t, err)
	_, err = codes.CreateAuthorizationCode(context.Background(), &core.CreateAuthorizationCodeRequest{Code: c})
	require.NoError(t, err)
}
