package apiauth_test

// TokenInfo carries the verified token's exp, iat, client_id and jti on every
// validation path, so a caller ending a session at exp never re-parses the
// token unverified.
//
// See: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
// See: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
// See: https://github.com/panyam/oneauth/issues/456

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/stores/fs"
)

var (
	timesIat = time.Now().Add(-time.Minute).Truncate(time.Second)
	timesExp = time.Now().Add(time.Hour).Truncate(time.Second)
)

func signTimesToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(rsSecret))
	require.NoError(t, err)
	return tok
}

func timesClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub":       "alice",
		"iss":       rsIssuer,
		"exp":       timesExp.Unix(),
		"iat":       timesIat.Unix(),
		"jti":       "tok-1",
		"client_id": "app-1",
	}
}

func assertTimes(t *testing.T, info *apiauth.TokenInfo) {
	t.Helper()
	require.NotNil(t, info)
	assert.True(t, info.ExpiresAt.Equal(timesExp), "ExpiresAt = %v, want %v", info.ExpiresAt, timesExp)
	assert.True(t, info.IssuedAt.Equal(timesIat), "IssuedAt = %v, want %v", info.IssuedAt, timesIat)
	assert.Equal(t, "app-1", info.ClientID)
	assert.Equal(t, "tok-1", info.TokenID)
}

// infoFromHandler runs one request through ValidateToken and returns the
// TokenInfo the downstream handler sees in its context.
func infoFromHandler(t *testing.T, mw *apiauth.APIMiddleware, token string) *apiauth.TokenInfo {
	t.Helper()
	var got *apiauth.TokenInfo
	h := mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = apiauth.GetTokenInfoFromAPIContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	return got
}

func TestTokenInfoTimes_Validator(t *testing.T) {
	mw := &apiauth.APIMiddleware{
		Validator: apiauth.NewJWTValidator(apiauth.JWTValidatorConfig{
			KeyLookup:  keys.NewInMemoryKeyStore(),
			SigningKey: []byte(rsSecret), SigningAlg: "HS256", Issuer: rsIssuer,
		}),
	}
	assertTimes(t, infoFromHandler(t, mw, signTimesToken(t, timesClaims())))
}

func TestTokenInfoTimes_InlineJWT(t *testing.T) {
	mw := &apiauth.APIMiddleware{JWTSecretKey: rsSecret, JWTIssuer: rsIssuer}
	assertTimes(t, infoFromHandler(t, mw, signTimesToken(t, timesClaims())))
}

func TestTokenInfoTimes_ZeroWhenIatAbsent(t *testing.T) {
	claims := timesClaims()
	delete(claims, "iat")
	delete(claims, "jti")
	delete(claims, "client_id")
	mw := &apiauth.APIMiddleware{JWTSecretKey: rsSecret, JWTIssuer: rsIssuer}

	info := infoFromHandler(t, mw, signTimesToken(t, claims))

	assert.True(t, info.IssuedAt.IsZero())
	assert.Empty(t, info.ClientID)
	assert.Empty(t, info.TokenID)
	assert.True(t, info.ExpiresAt.Equal(timesExp))
}

func TestTokenInfoTimes_Introspection(t *testing.T) {
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active":    true,
			"sub":       "alice",
			"exp":       timesExp.Unix(),
			"iat":       timesIat.Unix(),
			"jti":       "tok-1",
			"client_id": "app-1",
		})
	}))
	defer as.Close()
	mw := &apiauth.APIMiddleware{
		Introspection: &apiauth.IntrospectionValidator{
			IntrospectionURL: as.URL, ClientID: "rs", ClientSecret: "rs-secret",
		},
	}
	assertTimes(t, infoFromHandler(t, mw, "opaque-token"))
}

func TestTokenInfoTimes_APIKeyExpiry(t *testing.T) {
	store := newAPIKeyStore(t)
	created, err := store.CreateAPIKey(context.Background(), &core.CreateAPIKeyRequest{
		Subject: "alice", Name: "k", ExpiresAt: &timesExp,
	})
	require.NoError(t, err)
	mw := &apiauth.APIMiddleware{APIKeyStore: store}

	info := infoFromHandler(t, mw, created.FullKey)

	assert.Equal(t, "api_key", info.AuthType)
	assert.True(t, info.ExpiresAt.Equal(timesExp), "ExpiresAt = %v", info.ExpiresAt)
	assert.True(t, info.IssuedAt.IsZero())
}

// lastUsedKeyStore is an FS API key store whose cleanup waits for the
// middleware's background last-used write, which otherwise races
// t.TempDir's removal of the directory.
type lastUsedKeyStore struct {
	core.APIKeyStore
	written chan struct{}
}

func newAPIKeyStore(t *testing.T) *lastUsedKeyStore {
	t.Helper()
	s := &lastUsedKeyStore{APIKeyStore: fs.NewFSAPIKeyStore(t.TempDir()), written: make(chan struct{}, 16)}
	t.Cleanup(func() {
		select {
		case <-s.written:
		case <-time.After(2 * time.Second):
		}
	})
	return s
}

func (s *lastUsedKeyStore) UpdateAPIKeyLastUsed(ctx context.Context, req *core.UpdateAPIKeyLastUsedRequest) (*core.UpdateAPIKeyLastUsedResponse, error) {
	defer func() { s.written <- struct{}{} }()
	return s.APIKeyStore.UpdateAPIKeyLastUsed(ctx, req)
}

func TestTokenInfoTimes_NoContextOutsideMiddleware(t *testing.T) {
	assert.Nil(t, apiauth.GetTokenInfoFromAPIContext(context.Background()))
}
