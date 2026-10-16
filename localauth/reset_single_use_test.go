package localauth_test

// A password-reset link works once, applies the same password policy as
// signup, and ends the account's other sessions.
//
// See: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
// See: https://cwe.mitre.org/data/definitions/367.html (check-then-use race)
// See: https://cwe.mitre.org/data/definitions/613.html (insufficient session expiration)
// See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/localauth"
	"github.com/panyam/oneauth/stores/fs"
)

func newResetToken(t *testing.T, service *testAuthService) string {
	t.Helper()
	resp, err := service.TokenStore.CreateToken(context.Background(), &localauth.CreateVerificationTokenRequest{
		Email: "reset@example.com", Type: localauth.VerificationTypePasswordReset, ExpiryDuration: localauth.VerificationExpiryPasswordReset,
	})
	require.NoError(t, err)
	return resp.Token.Token
}

func postReset(auth *localauth.LocalAuth, token, password string) *httptest.ResponseRecorder {
	form := url.Values{"token": {token}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	auth.HandleResetPassword(rr, req)
	return rr
}

// The token is consumed before the password changes, so a second request
// racing the first can't use it too. The second request here arrives while
// the first is still inside UpdatePassword.
//
// See: https://cwe.mitre.org/data/definitions/367.html
func TestReset_TokenIsSingleUseEvenUnderARace(t *testing.T) {
	auth, service, _, tmpDir := setupPasswordResetAuth(t)
	defer cleanup(t, tmpDir)
	token := newResetToken(t, service)

	var racer *httptest.ResponseRecorder
	raced := false
	update := auth.UpdatePassword
	auth.UpdatePassword = func(email, password string) error {
		if !raced {
			raced = true
			racer = postReset(auth, token, "attacker-password-1")
		}
		return update(email, password)
	}

	first := postReset(auth, token, "owner-password-123")
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	require.NotNil(t, racer)
	assert.NotEqual(t, http.StatusOK, racer.Code, "a reset link must work once: %s", racer.Body.String())
}

func TestReset_AppliesTheSignupPasswordPolicy(t *testing.T) {
	auth, service, _, tmpDir := setupPasswordResetAuth(t)
	defer cleanup(t, tmpDir)
	policy := localauth.PolicyEmailOnly
	policy.MinPasswordLength = 14
	auth.SignupPolicy = &policy

	rr := postReset(auth, newResetToken(t, service), "only-12-char")
	assert.NotEqual(t, http.StatusOK, rr.Code, "a password signup would refuse must not be set by a reset")
}

// See: https://cwe.mitre.org/data/definitions/613.html
func TestReset_EndsOtherSessions(t *testing.T) {
	auth, service, _, tmpDir := setupPasswordResetAuth(t)
	defer cleanup(t, tmpDir)
	var revokedFor string
	auth.AfterPasswordReset = func(ctx context.Context, email string) error {
		revokedFor = email
		return nil
	}

	rr := postReset(auth, newResetToken(t, service), "brand-new-password-1")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "reset@example.com", revokedFor)
}

// NewRevokeSessionsOnReset finds the account by email and revokes its
// refresh tokens.
func TestReset_RevokeSessionsOnResetRevokesRefreshTokens(t *testing.T) {
	_, service, _, tmpDir := setupPasswordResetAuth(t)
	defer cleanup(t, tmpDir)
	refresh := fs.NewFSRefreshTokenStore(tmpDir)
	ident, err := service.IdentityStore.GetIdentity(context.Background(), &accounts.GetIdentityRequest{IdentityType: "email", IdentityValue: "reset@example.com"})
	require.NoError(t, err)
	created, err := refresh.CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{Subject: ident.Identity.UserID, Scopes: []string{"read"}})
	require.NoError(t, err)

	hook := localauth.NewRevokeSessionsOnReset(service.IdentityStore, refresh)
	require.NoError(t, hook(context.Background(), "reset@example.com"))

	got, err := refresh.GetRefreshToken(context.Background(), &core.GetRefreshTokenRequest{Token: created.Token.Token})
	require.NoError(t, err)
	assert.True(t, got.Token.Revoked)
}
