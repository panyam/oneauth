package apiauth_test

// Revoking a refresh token takes the access tokens issued from the same
// grant with it: the one issued at login, and every one minted by
// refreshing since, whichever refresh token of the family was presented.
// Reuse detection does the same to a stolen family.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2
// See: https://github.com/panyam/oneauth/issues/436

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/localauth"
	"github.com/panyam/oneauth/stores/fs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupFamilyRevocation(t *testing.T, disableRotation bool) *apiAuthFixture {
	t.Helper()
	dir := t.TempDir()
	users := fs.NewFSUserStore(dir)
	identities := fs.NewFSIdentityStore(dir)
	channels := fs.NewFSChannelStore(dir)
	email := "family@example.com"
	_, err := localauth.NewCreateUserFunc(users, identities, channels)(&localauth.Credentials{
		Username: "family", Email: &email, Password: "password123",
	})
	require.NoError(t, err)

	return newAPIAuthFixture(apiauth.OneAuthConfig{
		SigningKey:                  []byte("family-revocation-secret-32chars!"),
		Issuer:                      "test-issuer",
		RefreshStore:                fs.NewFSRefreshTokenStore(dir),
		Blacklist:                   core.NewInMemoryBlacklist(),
		ValidateCredentials:         localauth.NewCredentialsValidator(identities, channels, users),
		DisableRefreshTokenRotation: disableRotation,
	}, nil)
}

func passwordLogin(t *testing.T, fx *apiAuthFixture) *core.TokenPair {
	t.Helper()
	rr := postTokenRequest(t, fx, `{"grant_type":"password","username":"family@example.com","password":"password123"}`)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var pair core.TokenPair
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &pair))
	require.NotEmpty(t, pair.RefreshToken)
	return &pair
}

func refresh(t *testing.T, fx *apiAuthFixture, rt string) *core.TokenPair {
	t.Helper()
	resp, err := fx.OneAuth.Issuer.RefreshGrant(context.Background(), &apiauth.RefreshGrantRequest{RefreshToken: rt})
	require.NoError(t, err)
	return resp.Tokens
}

func accessTokenValid(fx *apiAuthFixture, token string) bool {
	_, err := fx.Validator().ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: token})
	return err == nil
}

func revoke(t *testing.T, fx *apiAuthFixture, token string) {
	t.Helper()
	_, err := fx.OneAuth.Revoker.Revoke(context.Background(), &apiauth.RevokeRequest{Token: token, TokenTypeHint: "refresh_token"})
	require.NoError(t, err)
}

func TestRevokeRefreshToken_BlacklistsTheLoginAccessToken(t *testing.T) {
	fx := setupFamilyRevocation(t, false)
	login := passwordLogin(t, fx)
	require.True(t, accessTokenValid(fx, login.AccessToken))

	revoke(t, fx, login.RefreshToken)

	assert.False(t, accessTokenValid(fx, login.AccessToken), "access token issued with the revoked refresh token")
}

func TestRevokeRefreshToken_BlacklistsEveryGeneration(t *testing.T) {
	fx := setupFamilyRevocation(t, false)
	login := passwordLogin(t, fx)
	first := refresh(t, fx, login.RefreshToken)
	second := refresh(t, fx, first.RefreshToken)

	revoke(t, fx, second.RefreshToken)

	assert.False(t, accessTokenValid(fx, login.AccessToken), "login access token")
	assert.False(t, accessTokenValid(fx, first.AccessToken), "first refresh")
	assert.False(t, accessTokenValid(fx, second.AccessToken), "second refresh")
}

// With rotation off (FAPI 2.0 §5.3.2.1) one refresh token mints every
// access token of the session.
func TestRevokeRefreshToken_WithoutRotation(t *testing.T) {
	fx := setupFamilyRevocation(t, true)
	login := passwordLogin(t, fx)
	first := refresh(t, fx, login.RefreshToken)
	second := refresh(t, fx, login.RefreshToken)
	require.Empty(t, first.RefreshToken, "rotation off")

	revoke(t, fx, login.RefreshToken)

	assert.False(t, accessTokenValid(fx, login.AccessToken))
	assert.False(t, accessTokenValid(fx, first.AccessToken))
	assert.False(t, accessTokenValid(fx, second.AccessToken))
}

func TestRevokeRefreshToken_LeavesOtherSessionsAlone(t *testing.T) {
	fx := setupFamilyRevocation(t, false)
	mine := passwordLogin(t, fx)
	other := passwordLogin(t, fx)

	revoke(t, fx, mine.RefreshToken)

	assert.True(t, accessTokenValid(fx, other.AccessToken))
	_, err := fx.OneAuth.Issuer.RefreshGrant(context.Background(), &apiauth.RefreshGrantRequest{RefreshToken: other.RefreshToken})
	assert.NoError(t, err)
}

// A rotated-away refresh token presented again means the family leaked;
// the access token the thief or the client holds goes with it.
func TestRefreshReuse_BlacklistsTheFamilyAccessTokens(t *testing.T) {
	fx := setupFamilyRevocation(t, false)
	login := passwordLogin(t, fx)
	current := refresh(t, fx, login.RefreshToken)

	_, err := fx.OneAuth.Issuer.RefreshGrant(context.Background(), &apiauth.RefreshGrantRequest{RefreshToken: login.RefreshToken})
	require.Error(t, err)
	require.Contains(t, err.Error(), "token reuse")

	assert.False(t, accessTokenValid(fx, login.AccessToken))
	assert.False(t, accessTokenValid(fx, current.AccessToken))
}

// revokingStore revokes the family just before the issuer records its new
// access token, which is what a revocation racing a refresh looks like
// from inside the store.
type revokingStore struct {
	core.RefreshTokenStore
}

func (s revokingStore) RecordAccessToken(ctx context.Context, req *core.RecordAccessTokenRequest) (*core.RecordAccessTokenResponse, error) {
	got, err := s.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: req.Token})
	if err != nil {
		return nil, err
	}
	if _, err := s.RevokeTokenFamily(ctx, &core.RevokeTokenFamilyRequest{Family: got.Token.Family}); err != nil {
		return nil, err
	}
	return s.RefreshTokenStore.RecordAccessToken(ctx, req)
}

type recordingBlacklist struct {
	core.TokenBlacklist
	revoked []string
}

func (b *recordingBlacklist) Revoke(jti string, exp time.Time) error {
	b.revoked = append(b.revoked, jti)
	return b.TokenBlacklist.Revoke(jti, exp)
}

func TestRefresh_RevokedWhileMintingIsRefused(t *testing.T) {
	ctx := context.Background()
	store := fs.NewFSRefreshTokenStore(t.TempDir())
	bl := &recordingBlacklist{TokenBlacklist: core.NewInMemoryBlacklist()}
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		SigningKey:                  []byte("family-revocation-secret-32chars!"),
		SigningAlg:                  "HS256",
		Issuer:                      "test-issuer",
		RefreshStore:                revokingStore{store},
		Blacklist:                   bl,
		DisableRefreshTokenRotation: true,
	})
	created, err := store.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{Subject: "alice"})
	require.NoError(t, err)

	_, err = oa.Issuer.RefreshGrant(ctx, &apiauth.RefreshGrantRequest{RefreshToken: created.Token.Token})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")
	assert.Len(t, bl.revoked, 1, "the access token minted for the refused refresh is blacklisted")
}

// Reusing an authorization code revokes the family it produced (issue
// 429), and that now includes access tokens minted by refreshing it, not
// only the one the code redemption returned.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2
func TestAuthCodeReuse_RevokesAccessTokensFromRefreshing(t *testing.T) {
	codes := core.NewInMemoryAuthorizationCodeStore()
	fx := setupCodeReuse(t, codes)
	seedAuthCode(t, codes, "code-1")

	status, first := redeemCode(t, fx)
	require.Equal(t, http.StatusOK, status, first)

	rr := httptest.NewRecorder()
	fx.ServeHTTP(rr, tokenRedeemForm(t, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first["refresh_token"].(string)},
		"code":          nil, "code_verifier": nil, "redirect_uri": nil,
	}))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var refreshed map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &refreshed))
	require.True(t, accessTokenValid(fx, refreshed["access_token"].(string)))

	status, _ = redeemCode(t, fx)
	require.Equal(t, http.StatusBadRequest, status)

	assert.False(t, accessTokenValid(fx, refreshed["access_token"].(string)), "access token minted by refreshing the reused code's family")
}

// See: https://www.rfc-editor.org/rfc/rfc8628#section-3.5
func TestRevokeRefreshToken_BlacklistsTheDeviceGrantAccessToken(t *testing.T) {
	store := core.NewInMemoryDeviceAuthorizationStore()
	fx := newAPIAuthFixture(apiauth.OneAuthConfig{
		SigningKey:      []byte("device-test-secret-32chars-min!!"),
		Issuer:          "test-issuer",
		RefreshStore:    fs.NewFSRefreshTokenStore(t.TempDir()),
		Blacklist:       core.NewInMemoryBlacklist(),
		DeviceAuthStore: store,
	}, nil)
	deviceCode, userCode := runDeviceAuthorize(t, &apiauth.DeviceAuthorizationHandler{
		Store: store, VerificationURI: "https://auth.example/device",
	}, "client-x")
	require.NoError(t, fx.ApproveDeviceAuthorization(httptest.NewRequest(http.MethodPost, "/", nil), userCode, "alice", nil))

	rr := httptest.NewRecorder()
	fx.ServeHTTP(rr, tokenForm(t, url.Values{
		"grant_type":  {apiauth.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {"client-x"},
	}))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var out map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))

	revoke(t, fx, out["refresh_token"].(string))

	assert.False(t, accessTokenValid(fx, out["access_token"].(string)))
}
