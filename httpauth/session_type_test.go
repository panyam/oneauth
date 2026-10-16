package httpauth_test

// The httpauth session verifier accepts session JWTs only: an access token
// signed with the same secret is not a login (RFC 8725 §3.11).
//
// See: https://www.rfc-editor.org/rfc/rfc8725#section-3.11
// See: https://github.com/panyam/oneauth/issues/88

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSession_VerifierRefusesAccessTokens(t *testing.T) {
	a := newSessionAuth(t)
	for typ, ok := range map[string]bool{"access": false, "session": true} {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "alice", "type": typ, "exp": time.Now().Add(time.Hour).Unix()})
		s, err := tok.SignedString([]byte(sessionTestSecret))
		require.NoError(t, err)
		sub, _, err := a.Middleware.VerifyToken(s)
		if ok {
			assert.NoError(t, err)
			assert.Equal(t, "alice", sub)
		} else {
			assert.Error(t, err, "an access token must not verify as a session")
		}
	}
}
