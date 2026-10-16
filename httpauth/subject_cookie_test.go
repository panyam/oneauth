package httpauth_test

// The loggedInSubject cookie is HttpOnly like the token cookie: nothing
// reads it from script, and a script that could would learn who is
// signed in.
//
// See: https://cwe.mitre.org/data/definitions/1004.html

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSession_SubjectCookieIsHttpOnly(t *testing.T) {
	a := newSessionAuth(t)
	sub := cookieNamed(login(t, a, "user-1", nil), "loggedInSubject")
	require.NotNil(t, sub)
	assert.True(t, sub.HttpOnly)

	var cleared bool
	for _, c := range login(t, a, "", nil) {
		if c.Name == "loggedInSubject" {
			cleared = true
			assert.True(t, c.HttpOnly, "the delete cookie too")
		}
	}
	assert.True(t, cleared, "logout deletes loggedInSubject")
}
