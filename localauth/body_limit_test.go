package localauth_test

// Login, signup and reset forms are bounded, so a client can't make the
// server read megabytes of form or spool them to disk (CWE-770).
//
// See: https://cwe.mitre.org/data/definitions/770.html
// See: https://github.com/panyam/oneauth/issues/88

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBodyLimit_ForgotPasswordRefusesAnOversizedForm(t *testing.T) {
	auth, _, _, tmpDir := setupPasswordResetAuth(t)
	defer cleanup(t, tmpDir)

	send := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		auth.HandleForgotPassword(rr, req)
		return rr.Code
	}
	ok := send("email=reset@example.com")
	assert.Less(t, ok, 300, "a normal request succeeds")
	assert.GreaterOrEqual(t, send("email=reset@example.com&pad="+strings.Repeat("a", 200<<10)), 400, "the same request with 200 KiB of padding is refused")
}
