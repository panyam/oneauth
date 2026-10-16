package apiauth_test

// A rotation's grace period, issue 88's "Key Management" walk: a token a
// tenant signed with its old key keeps verifying while the old key sits in
// the KidStore, and stops when it expires.
//
// See: https://github.com/panyam/oneauth/issues/88
// See: https://www.rfc-editor.org/rfc/rfc7517#section-4.5

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

func TestKeyRotation_RetiredKeyVerifiesDuringItsGracePeriod(t *testing.T) {
	ctx := context.Background()
	oldKey := []byte("tenant-old-secret-that-is-32-byt")
	newKey := []byte("tenant-new-secret-that-is-32-byt")
	oldKid, err := utils.ComputeKid(oldKey, "HS256")
	require.NoError(t, err)

	ks := keys.NewInMemoryKeyStore()
	_, err = ks.PutKey(ctx, &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app", Key: oldKey, Algorithm: "HS256"}})
	require.NoError(t, err)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "alice", "client_id": "app", "iss": "as", "type": "access", "jti": "j",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = oldKid
	signed, err := tok.SignedString(oldKey)
	require.NoError(t, err)

	// Rotate: the new key replaces the old in KeyStore, the old one moves
	// to the KidStore for its grace period.
	_, err = ks.PutKey(ctx, &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "app", Key: newKey, Algorithm: "HS256"}})
	require.NoError(t, err)
	kids := keys.NewKidStore()
	_, err = kids.Add(ctx, &keys.AddKidRequest{Kid: oldKid, Key: oldKey, Algorithm: "HS256", ClientID: "app", ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)

	validate := func(kidStore keys.KidStorage) error {
		oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{KeyStore: ks, KidStore: kidStore, SigningKey: []byte("as-own-signing-key-that-is-32-by"), SigningAlg: "HS256", Issuer: "as"})
		_, err := oa.Validator.ValidateToken(ctx, &apiauth.ValidateTokenRequest{Token: signed})
		return err
	}
	assert.NoError(t, validate(kids), "old key inside its grace period")
	assert.Error(t, validate(nil), "no KidStore: the rotated key is gone")

	_, err = kids.Add(ctx, &keys.AddKidRequest{Kid: oldKid, Key: oldKey, Algorithm: "HS256", ClientID: "app", ExpiresAt: time.Now().Add(-time.Second)})
	require.NoError(t, err)
	assert.Error(t, validate(kids), "grace period over")
}
