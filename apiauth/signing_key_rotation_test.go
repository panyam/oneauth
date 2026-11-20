package apiauth_test

// Rotating the AS's own signing key at runtime (issue 507, OIDC Core
// §10.1.1). New tokens carry the new key's kid. Tokens signed with the
// retired key keep verifying while its kid-store grace entry lasts, and
// stop when it goes. Every key the AS registered under OwnKeyClientID is
// its own, so its tokens skip the tenant check whichever key signed them.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
// See: https://github.com/panyam/oneauth/issues/507

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

const ownKeyClient = "oneauth-issuer"

func TestRotatingSigningKey_RotateChecksTheKeyFitsTheAlg(t *testing.T) {
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	src, err := apiauth.NewRotatingSigningKey(k1, "ES256")
	require.NoError(t, err)
	key, alg := src.CurrentSigningKey()
	assert.Equal(t, k1, key)
	assert.Equal(t, "ES256", alg)

	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	assert.Error(t, src.Rotate(rk), "an RSA key can't sign ES256")
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.Error(t, src.Rotate(p384), "ES256 needs P-256")
	assert.Error(t, src.Rotate(&k1.PublicKey), "a public key can't sign")

	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, src.Rotate(k2))
	key, _ = src.CurrentSigningKey()
	assert.Equal(t, k2, key)

	_, err = apiauth.NewRotatingSigningKey(rk, "ES256")
	assert.Error(t, err)
}

type rotationFixture struct {
	oa      *apiauth.OneAuth
	src     *apiauth.RotatingSigningKey
	keys    *keys.InMemoryKeyStore
	kids    *keys.KidStore
	current *ecdsa.PrivateKey
}

// publish registers key's public half as the AS's own key, as the
// reference server does at startup and on rotation.
func (fx *rotationFixture) publish(t *testing.T, key *ecdsa.PrivateKey) {
	t.Helper()
	pem, err := utils.EncodePublicKeyPEM(&key.PublicKey)
	require.NoError(t, err)
	_, err = fx.keys.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: ownKeyClient, Key: pem, Algorithm: "ES256"}})
	require.NoError(t, err)
}

// rotate makes next the signing key and keeps the old public key in the
// kid store for an hour, as AppRegistrar.RotateSecret does.
func (fx *rotationFixture) rotate(t *testing.T, next *ecdsa.PrivateKey) string {
	t.Helper()
	oldKid, err := utils.ComputeKid(&fx.current.PublicKey, "ES256")
	require.NoError(t, err)
	pem, err := utils.EncodePublicKeyPEM(&fx.current.PublicKey)
	require.NoError(t, err)
	_, err = fx.kids.Add(context.Background(), &keys.AddKidRequest{Kid: oldKid, Key: pem, Algorithm: "ES256", ClientID: ownKeyClient, ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	fx.publish(t, next)
	require.NoError(t, fx.src.Rotate(next))
	fx.current = next
	return oldKid
}

func newRotationFixture(t *testing.T) *rotationFixture {
	t.Helper()
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	src, err := apiauth.NewRotatingSigningKey(k1, "ES256")
	require.NoError(t, err)
	fx := &rotationFixture{src: src, keys: keys.NewInMemoryKeyStore(), kids: keys.NewKidStore(), current: k1}
	fx.publish(t, k1)
	fx.oa = apiauth.NewOneAuth(apiauth.OneAuthConfig{
		SigningKeySource: src,
		OwnKeyClientID:   ownKeyClient,
		KeyStore:         fx.keys,
		KidStore:         fx.kids,
		Issuer:           "https://as.example",
		Blacklist:        core.NewInMemoryBlacklist(),
	})
	return fx
}

func (fx *rotationFixture) mint(t *testing.T) (token, kid string) {
	t.Helper()
	resp, err := fx.oa.Issuer.CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "alice", Scopes: []string{"read"}, ClientID: "some-app"})
	require.NoError(t, err)
	parsed, _, err := jwt.NewParser().ParseUnverified(resp.Token, jwt.MapClaims{})
	require.NoError(t, err)
	kid, _ = parsed.Header["kid"].(string)
	return resp.Token, kid
}

func (fx *rotationFixture) valid(token string) error {
	_, err := fx.oa.Validator.ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: token})
	return err
}

func TestSigningKeyRotation_OldTokensLastTheGracePeriod(t *testing.T) {
	fx := newRotationFixture(t)
	before, kidBefore := fx.mint(t)
	require.NoError(t, fx.valid(before))

	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	oldKid := fx.rotate(t, k2)
	assert.Equal(t, kidBefore, oldKid)

	after, kidAfter := fx.mint(t)
	assert.NotEqual(t, kidBefore, kidAfter, "new tokens carry the new key's kid")
	assert.NoError(t, fx.valid(after), "the AS's new key is its own: no tenant check against client_id some-app")
	assert.NoError(t, fx.valid(before), "a token signed before the rotation verifies during the grace period")

	_, err := fx.kids.Remove(context.Background(), &keys.RemoveKidRequest{Kid: oldKid})
	require.NoError(t, err)
	assert.Error(t, fx.valid(before), "once the grace entry is gone, the retired key verifies nothing")
}

// A key registered to an ordinary client still signs only for that
// client, so OwnKeyClientID doesn't widen the tenant check.
func TestSigningKeyRotation_TenantKeysStillBoundToTheirClient(t *testing.T) {
	fx := newRotationFixture(t)
	tenant, _ := rsa.GenerateKey(rand.Reader, 2048)
	pem, err := utils.EncodePublicKeyPEM(&tenant.PublicKey)
	require.NoError(t, err)
	_, err = fx.keys.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "tenant-a", Key: pem, Algorithm: "RS256"}})
	require.NoError(t, err)
	kid, err := utils.ComputeKid(&tenant.PublicKey, "RS256")
	require.NoError(t, err)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "alice", "client_id": "tenant-b", "iss": "https://as.example", "exp": time.Now().Add(time.Minute).Unix(), "typ": "Bearer"})
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(tenant)
	require.NoError(t, err)
	assert.Error(t, fx.valid(signed))
}

// ID tokens follow the rotation too, so a relying party fetching the JWKS
// finds the kid each one names.
func TestSigningKeyRotation_IDTokensUseTheCurrentKey(t *testing.T) {
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	src, err := apiauth.NewRotatingSigningKey(k1, "ES256")
	require.NoError(t, err)
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{SigningKeySource: src, Issuer: "https://as.example", OIDC: &apiauth.OIDCConfig{}})
	kidOf := func() string {
		resp, err := oa.IDTokenIssuer.CreateIDToken(context.Background(), &apiauth.CreateIDTokenRequest{Subject: "alice", ClientID: "app"})
		require.NoError(t, err)
		parsed, _, err := jwt.NewParser().ParseUnverified(resp.Token, jwt.MapClaims{})
		require.NoError(t, err)
		return parsed.Header["kid"].(string)
	}
	want1, _ := utils.ComputeKid(&k1.PublicKey, "ES256")
	assert.Equal(t, want1, kidOf())
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, src.Rotate(k2))
	want2, _ := utils.ComputeKid(&k2.PublicKey, "ES256")
	assert.Equal(t, want2, kidOf())
}
