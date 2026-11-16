package apiauth_test

// SetAuthErrorHeaders and WriteAuthError, the two halves of the default
// refusal, so an OnAuthError that writes its own body still sends the
// RFC 6750 challenge.
//
// See: https://www.rfc-editor.org/rfc/rfc6750#section-3.1
// See: https://github.com/panyam/oneauth/issues/463

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetAuthErrorHeaders_StatusAndChallengeWithoutWriting(t *testing.T) {
	mw := &apiauth.APIMiddleware{}
	cases := []struct {
		name      string
		err       error
		status    int
		challenge string
	}{
		{"no credentials", &apiauth.AuthError{Err: errors.New("missing authorization header")}, http.StatusUnauthorized, `Bearer realm="api"`},
		{"invalid token", &apiauth.AuthError{Scheme: "Bearer", Code: "invalid_token", Description: "expired"}, http.StatusUnauthorized, `Bearer realm="api", error="invalid_token", error_description="expired"`},
		{"insufficient scope", &apiauth.AuthError{Scheme: "Bearer", Code: "insufficient_scope", Description: "requires scope echo"}, http.StatusForbidden, `Bearer realm="api", error="insufficient_scope", error_description="requires scope echo"`},
		{"plain error", errors.New("missing authorization_details type"), http.StatusUnauthorized, `Bearer realm="api"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			status := mw.SetAuthErrorHeaders(rec, tc.err)

			assert.Equal(t, tc.status, status)
			assert.Equal(t, tc.challenge, rec.Header().Get("WWW-Authenticate"))
			assert.False(t, rec.Flushed)
			assert.Empty(t, rec.Header().Get("Content-Type"), "headers only; the body is the caller's")
			assert.Zero(t, rec.Body.Len())
		})
	}
}

func TestWriteAuthError_MatchesDefaultRefusal(t *testing.T) {
	mw := &apiauth.APIMiddleware{JWTSecretKey: "auth-error-headers-test-secret-32b!"}
	h := mw.RequireScopes("echo")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")

	viaDefault := httptest.NewRecorder()
	h.ServeHTTP(viaDefault, req)

	var seen error
	mw.OnAuthError = func(w http.ResponseWriter, r *http.Request, err error) {
		seen = err
		mw.WriteAuthError(w, r, err)
	}
	viaHook := httptest.NewRecorder()
	h.ServeHTTP(viaHook, req)

	require.Error(t, seen)
	assert.Equal(t, viaDefault.Code, viaHook.Code)
	assert.Equal(t, http.StatusUnauthorized, viaHook.Code)
	assert.Equal(t, viaDefault.Header(), viaHook.Header())
	assert.Equal(t, viaDefault.Body.String(), viaHook.Body.String())
	var body map[string]string
	require.NoError(t, json.Unmarshal(viaHook.Body.Bytes(), &body))
	assert.Equal(t, "unauthorized", body["error"])
}
