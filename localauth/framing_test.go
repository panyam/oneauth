package localauth_test

// The built-in forgot-password and reset-password forms refuse to be framed
// (clickjacking, CWE-1021).
//
// See: https://cwe.mitre.org/data/definitions/1021.html
// See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/localauth"
)

func TestFraming_PasswordForms(t *testing.T) {
	localAuth, service, _, tmpDir := setupPasswordResetAuth(t)
	defer cleanup(t, tmpDir)

	forgot := httptest.NewRecorder()
	localAuth.HandleForgotPasswordForm(forgot, httptest.NewRequest(http.MethodGet, "/auth/forgot-password", nil))
	assert.Equal(t, "DENY", forgot.Header().Get("X-Frame-Options"), "forgot-password form")
	assert.Contains(t, forgot.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")

	tokenResp, err := service.TokenStore.CreateToken(context.Background(), &localauth.CreateVerificationTokenRequest{
		Email: "reset@example.com", Type: localauth.VerificationTypePasswordReset, ExpiryDuration: localauth.VerificationExpiryPasswordReset,
	})
	require.NoError(t, err)
	reset := httptest.NewRecorder()
	localAuth.HandleResetPasswordForm(reset, httptest.NewRequest(http.MethodGet, "/auth/reset-password?token="+tokenResp.Token.Token, nil))
	require.Equal(t, http.StatusOK, reset.Code)
	assert.Equal(t, "DENY", reset.Header().Get("X-Frame-Options"), "reset-password form")
	assert.Contains(t, reset.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
}
