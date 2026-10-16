package localauth_test

// The reset-password form and its redirect carry the reset token, a
// credential, so neither may be cached.
//
// See: https://cwe.mitre.org/data/definitions/525.html
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

func TestResetPasswordForm_IsNoStore(t *testing.T) {
	for name, redirectURL := range map[string]string{"rendered form": "", "redirect to the app": "/reset-password"} {
		t.Run(name, func(t *testing.T) {
			localAuth, service, _, tmpDir := setupPasswordResetAuth(t)
			defer cleanup(t, tmpDir)
			localAuth.ResetPasswordURL = redirectURL
			tokenResp, err := service.TokenStore.CreateToken(context.Background(), &localauth.CreateVerificationTokenRequest{
				Email: "reset@example.com", Type: localauth.VerificationTypePasswordReset, ExpiryDuration: localauth.VerificationExpiryPasswordReset,
			})
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			localAuth.HandleResetPasswordForm(rr, httptest.NewRequest(http.MethodGet, "/auth/reset-password?token="+tokenResp.Token.Token, nil))

			assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
			assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
		})
	}
}
