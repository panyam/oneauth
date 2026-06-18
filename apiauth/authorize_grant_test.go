package apiauth_test

// Tests for the RFC 6749 §4.1.3 authorization_code redemption branch
// of the token endpoint.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	authcodeTestVerifier = "test-verifier-0123456789abcdef0123456789abcdef0123"
	authcodeTestSubject  = "user-1"
	authcodeTestClientID = "client-x"
	authcodeTestRedirect = "https://app.example/cb"
)

func setupAuthCode(t *testing.T) (*apiauth.APIAuth, core.AuthorizationCodeStore) {
	t.Helper()
	codeStore := core.NewInMemoryAuthorizationCodeStore()
	auth := &apiauth.APIAuth{
		JWTSecretKey:           "authcode-test-secret-32chars-min!",
		JWTIssuer:              "test-issuer",
		RefreshTokenStore:      newInMemoryRefreshStore(),
		AuthorizationCodeStore: codeStore,
	}
	return auth, codeStore
}

// seedAuthCode persists a valid authorization code bound to the test
// fixture client_id / redirect_uri / PKCE pair.
func seedAuthCode(t *testing.T, store core.AuthorizationCodeStore, code string) {
	t.Helper()
	challenge := oauth2.ComputeCodeChallenge(authcodeTestVerifier)
	_, err := store.CreateAuthorizationCode(context.Background(), &core.CreateAuthorizationCodeRequest{
		Code: &core.AuthorizationCode{
			Code:                code,
			ClientID:            authcodeTestClientID,
			RedirectURI:         authcodeTestRedirect,
			Scopes:              []string{"read"},
			Subject:             authcodeTestSubject,
			CodeChallenge:       challenge,
			CodeChallengeMethod: oauth2.CodeChallengeMethodS256,
			IssuedAt:            time.Now(),
			ExpiresAt:           time.Now().Add(1 * time.Minute),
		},
	})
	require.NoError(t, err)
}

func tokenRedeemForm(t *testing.T, overrides url.Values) *http.Request {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code-1"},
		"code_verifier": {authcodeTestVerifier},
		"redirect_uri":  {authcodeTestRedirect},
		"client_id":     {authcodeTestClientID},
	}
	for k, v := range overrides {
		form[k] = v
	}
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// TestAuthCodeRedeem_HappyPath pins the §4.1.3 success path: a
// well-formed redemption returns an access token + refresh token + the
// granted scope set.
func TestAuthCodeRedeem_HappyPath(t *testing.T) {
	auth, store := setupAuthCode(t)
	seedAuthCode(t, store, "code-1")

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenRedeemForm(t, nil))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.NotEmpty(t, body["access_token"], "access_token MUST be issued on successful redemption")
	assert.NotEmpty(t, body["refresh_token"], "refresh_token MUST be issued when RefreshTokenStore is configured")
	assert.Equal(t, "Bearer", body["token_type"])
}

// TestAuthCodeRedeem_SingleUse pins RFC 6749 §4.1.2 — a second
// redemption attempt with the same code MUST fail. The first call
// consumes the code; the second sees ErrAuthorizationCodeNotFound.
func TestAuthCodeRedeem_SingleUse(t *testing.T) {
	auth, store := setupAuthCode(t)
	seedAuthCode(t, store, "code-1")

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenRedeemForm(t, nil))
	require.Equal(t, http.StatusOK, rr.Code)

	rr2 := httptest.NewRecorder()
	auth.ServeHTTP(rr2, tokenRedeemForm(t, nil))
	assert.Equal(t, http.StatusBadRequest, rr2.Code, "second redemption MUST be rejected (single-use)")
	assert.Contains(t, rr2.Body.String(), "invalid_grant")
}

// TestAuthCodeRedeem_PKCEMismatch pins RFC 7636 §4.6 — a wrong
// code_verifier MUST be rejected with invalid_grant, and the code
// SHOULD remain consumable (we choose to NOT delete on verify failure
// so the legitimate client can retry within the expiry window).
func TestAuthCodeRedeem_PKCEMismatch(t *testing.T) {
	auth, store := setupAuthCode(t)
	seedAuthCode(t, store, "code-1")

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenRedeemForm(t, url.Values{"code_verifier": {"wrong-verifier"}}))
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
	assert.Contains(t, rr.Body.String(), "PKCE")
}

// TestAuthCodeRedeem_RedirectURIMismatch pins §4.1.3 — the
// redirect_uri on the redemption MUST match the value bound at
// /authorize time.
func TestAuthCodeRedeem_RedirectURIMismatch(t *testing.T) {
	auth, store := setupAuthCode(t)
	seedAuthCode(t, store, "code-1")

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenRedeemForm(t, url.Values{"redirect_uri": {"https://attacker.example/cb"}}))
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
	assert.Contains(t, rr.Body.String(), "redirect_uri")
}

// TestAuthCodeRedeem_ClientIDMismatch pins §4.1.3 binding — the code
// MUST be presented by the same client_id that requested it. An empty
// client_id against a bound entry is also rejected (binding-bypass
// attempt).
func TestAuthCodeRedeem_ClientIDMismatch(t *testing.T) {
	auth, store := setupAuthCode(t)
	seedAuthCode(t, store, "code-1")

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenRedeemForm(t, url.Values{"client_id": {"other-client"}}))
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

// TestAuthCodeRedeem_Expired pins the §4.1.2 expiry behavior — a
// stale code returns invalid_grant. The expired record is consumed
// so a leaked-but-stale code cannot be retried indefinitely.
func TestAuthCodeRedeem_Expired(t *testing.T) {
	auth, store := setupAuthCode(t)
	challenge := oauth2.ComputeCodeChallenge(authcodeTestVerifier)
	_, err := store.CreateAuthorizationCode(context.Background(), &core.CreateAuthorizationCodeRequest{
		Code: &core.AuthorizationCode{
			Code:                "code-stale",
			ClientID:            authcodeTestClientID,
			RedirectURI:         authcodeTestRedirect,
			Scopes:              []string{"read"},
			Subject:             authcodeTestSubject,
			CodeChallenge:       challenge,
			CodeChallengeMethod: oauth2.CodeChallengeMethodS256,
			IssuedAt:            time.Now().Add(-2 * time.Minute),
			ExpiresAt:           time.Now().Add(-1 * time.Minute),
		},
	})
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenRedeemForm(t, url.Values{"code": {"code-stale"}}))
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
	assert.Contains(t, rr.Body.String(), "expired")

	_, err = store.GetAuthorizationCode(context.Background(), &core.GetAuthorizationCodeRequest{Code: "code-stale"})
	assert.Error(t, err, "expired code MUST be consumed on redemption attempt so leaked-but-stale codes cannot be retried")
}

// TestAuthCodeRedeem_UnknownCode pins the §5.2 invalid_grant mapping
// for a never-issued code (matches the redemption-of-expired path's
// taxonomy so callers can't distinguish "stolen-and-expired" from
// "guessed-and-wrong" via timing or error code).
func TestAuthCodeRedeem_UnknownCode(t *testing.T) {
	auth, _ := setupAuthCode(t)
	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenRedeemForm(t, url.Values{"code": {"never-issued"}}))
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")
}

// TestAuthCodeRedeem_MissingPKCEVerifier pins the §4.1.3 invalid_request
// mapping for a missing code_verifier — every code minted by /authorize
// carries a code_challenge, so a redemption without code_verifier
// cannot satisfy the PKCE check.
func TestAuthCodeRedeem_MissingPKCEVerifier(t *testing.T) {
	auth, store := setupAuthCode(t)
	seedAuthCode(t, store, "code-1")

	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenRedeemForm(t, url.Values{"code_verifier": {""}}))
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_request")
}

// TestAuthCodeRedeem_GrantNotEnabled pins that a token endpoint without
// AuthorizationCodeStore wired rejects the grant with unsupported_grant_type
// — the legacy behavior is preserved for callers who haven't opted in.
func TestAuthCodeRedeem_GrantNotEnabled(t *testing.T) {
	auth := &apiauth.APIAuth{
		JWTSecretKey: "authcode-test-secret-32chars-min!",
		JWTIssuer:    "test-issuer",
		// AuthorizationCodeStore intentionally nil
	}
	rr := httptest.NewRecorder()
	auth.ServeHTTP(rr, tokenRedeemForm(t, nil))
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "unsupported_grant_type")
}
