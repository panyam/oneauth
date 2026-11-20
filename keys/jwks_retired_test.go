package keys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/panyam/oneauth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listOnly is a KidLister that isn't a *KidStore, standing in for the FS,
// GORM and GAE kid stores.
type listOnly struct{ inner *KidStore }

func (l listOnly) ListKids(ctx context.Context, req *ListKidsRequest) (*ListKidsResponse, error) {
	return l.inner.ListKids(ctx, req)
}

func jwksKids(t *testing.T, h *JWKSHandler) []string {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	require.Equal(t, http.StatusOK, rr.Code)
	var set utils.JWKSet
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &set))
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.Kid)
	}
	return kids
}

// A key retired with a grace period stays in the JWKS until the grace
// period ends, from any kid store, so a resource server validating
// through the JWKS accepts tokens signed just before a rotation. Symmetric
// and expired entries are never published.
// See: https://github.com/panyam/oneauth/issues/421
func TestJWKSHandler_PublishesRetiredKeys(t *testing.T) {
	ctx := context.Background()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pem, err := utils.EncodePublicKeyPEM(&priv.PublicKey)
	require.NoError(t, err)
	kids := NewKidStore()
	_, _ = kids.Add(ctx, &AddKidRequest{Kid: "retired-rsa", Key: pem, Algorithm: "RS256", ClientID: "oneauth-issuer", ExpiresAt: time.Now().Add(time.Hour)})
	_, _ = kids.Add(ctx, &AddKidRequest{Kid: "retired-hmac", Key: []byte("secret"), Algorithm: "HS256", ClientID: "c", ExpiresAt: time.Now().Add(time.Hour)})
	_, _ = kids.Add(ctx, &AddKidRequest{Kid: "expired-rsa", Key: pem, Algorithm: "RS256", ClientID: "c", ExpiresAt: time.Now().Add(-time.Minute)})

	for name, h := range map[string]*JWKSHandler{
		"KidStore field":    {KeyStore: NewInMemoryKeyStore(), KidStore: kids},
		"RetiredKeys field": {KeyStore: NewInMemoryKeyStore(), RetiredKeys: listOnly{kids}},
	} {
		assert.Equal(t, []string{"retired-rsa"}, jwksKids(t, h), name)
	}
}
