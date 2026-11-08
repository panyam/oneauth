package apiauth_test

// ValidateBearer checks a token that arrived without an HTTP request around
// it, such as a fresh token sent over an open WebSocket. It runs the same
// token checks as ValidateToken and reports failures as *AuthError carrying
// the RFC 6750 error code. A DPoP-bound token has no proof to check here, so
// it passes only when the caller supplies ConfirmBinding.
//
// See: https://www.rfc-editor.org/rfc/rfc6750#section-3.1
// See: https://www.rfc-editor.org/rfc/rfc9449#section-7.2
// See: https://github.com/panyam/oneauth/issues/456

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

func bearerMiddleware(opts ...func(*apiauth.APIMiddleware)) *apiauth.APIMiddleware {
	mw := &apiauth.APIMiddleware{JWTSecretKey: rsSecret, JWTIssuer: rsIssuer}
	for _, opt := range opts {
		opt(mw)
	}
	return mw
}

func withDPoP(m *apiauth.APIMiddleware) {
	m.DPoP = apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{BaseURL: rsBaseURL})
}

func requireAuthError(t *testing.T, err error, code string) *apiauth.AuthError {
	t.Helper()
	require.Error(t, err)
	var ae *apiauth.AuthError
	require.True(t, errors.As(err, &ae), "want *AuthError, got %T: %v", err, err)
	assert.Equal(t, code, ae.Code)
	return ae
}

func boundToken(t *testing.T, jkt string) string {
	claims := timesClaims()
	claims["cnf"] = map[string]any{"jkt": jkt}
	return signTimesToken(t, claims)
}

func TestValidateBearer_MatchesRequestPath(t *testing.T) {
	mw := bearerMiddleware()
	tok := signTimesToken(t, timesClaims())

	resp, err := mw.ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{Token: tok})

	require.NoError(t, err)
	assert.Equal(t, infoFromHandler(t, mw, tok), resp.Info)
	assert.Equal(t, "alice", resp.Info.Subject)
	assertTimes(t, resp.Info)
}

func TestValidateBearer_RefusedTokensAreInvalidToken(t *testing.T) {
	expired := timesClaims()
	expired["exp"] = time.Now().Add(-time.Hour).Unix()
	otherIssuer := timesClaims()
	otherIssuer["iss"] = "someone-else"
	badSig, err := jwt.NewWithClaims(jwt.SigningMethodHS256, timesClaims()).SignedString([]byte("another-secret-of-32-bytes-long!"))
	require.NoError(t, err)

	blacklist := core.NewInMemoryBlacklist()
	require.NoError(t, blacklist.Revoke("tok-1", timesExp))

	cases := map[string]struct {
		token string
		mw    *apiauth.APIMiddleware
	}{
		"expired":       {signTimesToken(t, expired), bearerMiddleware()},
		"wrong issuer":  {signTimesToken(t, otherIssuer), bearerMiddleware()},
		"bad signature": {badSig, bearerMiddleware()},
		"revoked":       {signTimesToken(t, timesClaims()), bearerMiddleware(func(m *apiauth.APIMiddleware) { m.Blacklist = blacklist })},
		"not a jwt":     {"garbage", bearerMiddleware()},
		"empty":         {"", bearerMiddleware()},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			resp, err := tc.mw.ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{Token: tc.token})

			assert.Nil(t, resp)
			ae := requireAuthError(t, err, "invalid_token")
			assert.Equal(t, apiauth.TokenTypeBearer, ae.Scheme)
		})
	}
}

// With no ConfirmBinding there is nothing to check a key binding against, so
// a bound token is refused. Accepting it would let a stolen bound token work
// as a bearer token, the downgrade RFC 9449 §7.2 closes. Unlike the request
// path, this holds even with no DPoP validator wired.
func TestValidateBearer_RefusesBoundTokenWithoutConfirmBinding(t *testing.T) {
	for name, mw := range map[string]*apiauth.APIMiddleware{
		"dpop wired":     bearerMiddleware(withDPoP),
		"dpop not wired": bearerMiddleware(),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := mw.ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{Token: boundToken(t, "jkt-1")})

			ae := requireAuthError(t, err, "invalid_token")
			assert.Equal(t, apiauth.TokenTypeDPoP, ae.Scheme)
		})
	}
}

func TestValidateBearer_ConfirmBindingAccepts(t *testing.T) {
	var seen *core.Confirmation
	resp, err := bearerMiddleware(withDPoP).ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{
		Token: boundToken(t, "jkt-1"),
		ConfirmBinding: func(_ context.Context, cnf *core.Confirmation) error {
			seen = cnf
			return nil
		},
	})

	require.NoError(t, err)
	require.NotNil(t, seen)
	assert.Equal(t, "jkt-1", seen.JKT)
	assert.Equal(t, "jkt-1", resp.Info.Confirmation.JKT)
}

func TestValidateBearer_ConfirmBindingRefusalIsInvalidToken(t *testing.T) {
	mismatch := errors.New("key mismatch")

	_, err := bearerMiddleware(withDPoP).ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{
		Token:          boundToken(t, "jkt-1"),
		ConfirmBinding: func(context.Context, *core.Confirmation) error { return mismatch },
	})

	ae := requireAuthError(t, err, "invalid_token")
	assert.Equal(t, apiauth.TokenTypeDPoP, ae.Scheme)
	assert.ErrorIs(t, err, mismatch)
}

// A host that checks its own proofs picks the error code, such as
// invalid_dpop_proof for a bad proof.
func TestValidateBearer_ConfirmBindingAuthErrorPassesThrough(t *testing.T) {
	_, err := bearerMiddleware(withDPoP).ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{
		Token: boundToken(t, "jkt-1"),
		ConfirmBinding: func(context.Context, *core.Confirmation) error {
			return &apiauth.AuthError{Scheme: apiauth.TokenTypeDPoP, Code: "invalid_dpop_proof", Description: "bad proof"}
		},
	})

	ae := requireAuthError(t, err, "invalid_dpop_proof")
	assert.Equal(t, "bad proof", ae.Description)
}

func TestValidateBearer_UnboundTokenSkipsConfirmBinding(t *testing.T) {
	called := false
	resp, err := bearerMiddleware(withDPoP).ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{
		Token:          signTimesToken(t, timesClaims()),
		ConfirmBinding: func(context.Context, *core.Confirmation) error { called = true; return nil },
	})

	require.NoError(t, err)
	assert.False(t, called)
	assert.Nil(t, resp.Info.Confirmation)
}

func TestValidateBearer_RequireDPoPRefusesUnboundToken(t *testing.T) {
	mw := bearerMiddleware(withDPoP, func(m *apiauth.APIMiddleware) { m.RequireDPoP = true })

	_, err := mw.ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{
		Token:          signTimesToken(t, timesClaims()),
		ConfirmBinding: func(context.Context, *core.Confirmation) error { return nil },
	})

	ae := requireAuthError(t, err, "invalid_token")
	assert.Equal(t, apiauth.TokenTypeDPoP, ae.Scheme)
}

func TestValidateBearer_RequireDPoPAcceptsConfirmedBoundToken(t *testing.T) {
	mw := bearerMiddleware(withDPoP, func(m *apiauth.APIMiddleware) { m.RequireDPoP = true })

	_, err := mw.ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{
		Token:          boundToken(t, "jkt-1"),
		ConfirmBinding: func(context.Context, *core.Confirmation) error { return nil },
	})

	require.NoError(t, err)
}

func TestValidateBearer_APIKey(t *testing.T) {
	store := newAPIKeyStore(t)
	created, err := store.CreateAPIKey(context.Background(), &core.CreateAPIKeyRequest{Subject: "bob", Name: "k"})
	require.NoError(t, err)

	resp, err := bearerMiddleware(func(m *apiauth.APIMiddleware) { m.APIKeyStore = store }).
		ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{Token: created.FullKey})

	require.NoError(t, err)
	assert.Equal(t, "bob", resp.Info.Subject)
	assert.Equal(t, "api_key", resp.Info.AuthType)
}

func TestValidateBearer_NilRequest(t *testing.T) {
	_, err := bearerMiddleware().ValidateBearer(context.Background(), nil)

	requireAuthError(t, err, "invalid_token")
}

// OnAuthError receives the same exported type, so a custom error writer can
// read the code without parsing the message.
func TestValidateBearer_OnAuthErrorSeesAuthError(t *testing.T) {
	var got *apiauth.AuthError
	mw := bearerMiddleware(func(m *apiauth.APIMiddleware) {
		m.OnAuthError = func(w http.ResponseWriter, r *http.Request, err error) {
			errors.As(err, &got)
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	h := mw.ValidateToken(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer garbage")

	h.ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, got)
	assert.Equal(t, "invalid_token", got.Code)
	assert.Equal(t, apiauth.TokenTypeBearer, got.Scheme)
}
