package localauth_test

// Signup doesn't reveal which emails already have accounts, issue 408 /
// 88: with email verification on, signing up with a taken email gets the
// same answer as a fresh one, and the existing owner is told by email.
//
// See: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-and-error-messages
// See: https://cwe.mitre.org/data/definitions/204.html
// See: https://github.com/panyam/oneauth/issues/408

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// existsNotifyingSender also implements localauth.AccountExistsEmailSender.
type existsNotifyingSender struct {
	trackingEmailSender
	existsEmails []sentEmail
}

func (s *existsNotifyingSender) SendAccountExistsEmail(to, link string) error {
	s.existsEmails = append(s.existsEmails, sentEmail{to, link})
	return nil
}

func TestSignup_TakenEmailLooksLikeAFreshOne(t *testing.T) {
	auth, _, _, tmpDir := setupPasswordResetAuth(t) // reset@example.com already exists
	defer cleanup(t, tmpDir)
	sender := &existsNotifyingSender{}
	auth.EmailSender = sender
	auth.RequireEmailVerification = true

	signup := func(email string) (int, string) {
		form := url.Values{"username": {strings.Split(email, "@")[0]}, "email": {email}, "password": {"a-good-password-123"}}
		req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		auth.HandleSignup(rr, req)
		return rr.Code, rr.Body.String()
	}

	freshCode, freshBody := signup("newcomer@example.com")
	takenCode, takenBody := signup("reset@example.com")
	assert.Equal(t, freshCode, takenCode, "same status")
	assert.Equal(t, freshBody, takenBody, "same body")
	assert.NotContains(t, freshBody, "user_id", "an id in the response would tell the two apart")

	if assert.Len(t, sender.existsEmails, 1, "the existing owner hears about it") {
		assert.Equal(t, "reset@example.com", sender.existsEmails[0].to)
	}
	for _, e := range sender.verificationEmails {
		assert.NotEqual(t, "reset@example.com", e.to, "no verification email for an account that exists")
	}
}
