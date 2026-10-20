package client

// VerifyIDToken against the client-side checks OIDC Core §3.1.3.7 lists:
// signature by the AS's published key, iss, aud/azp, exp, iat, nonce and
// at_hash, plus the token-kind markers that keep an access token from
// passing as an ID token.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
// See: https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
// See: https://github.com/panyam/oneauth/issues/453

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/keys"
)

const (
	idtIssuer = "https://as.example"
	idtClient = "client-1"
	idtNonce  = "n-453"
	idtAccess = "access-token-453"
)

// staticKeys is a KeyLookup over a fixed kid → record map.
type staticKeys map[string]*keys.KeyRecord

func (s staticKeys) GetKey(context.Context, *keys.GetKeyRequest) (*keys.GetKeyResponse, error) {
	return nil, keys.ErrKeyNotFound
}

func (s staticKeys) GetKeyByKid(_ context.Context, req *keys.GetKeyByKidRequest) (*keys.GetKeyByKidResponse, error) {
	rec, ok := s[req.Kid]
	if !ok {
		return nil, keys.ErrKidNotFound
	}
	return &keys.GetKeyByKidResponse{Record: rec}, nil
}

type idtFixture struct {
	ec    *ecdsa.PrivateKey
	rsa   *rsa.PrivateKey
	ed    ed25519.PrivateKey
	rsaPE []byte // PEM of the RSA public key
	keys  staticKeys
}

func newIDTFixture(t *testing.T) *idtFixture {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	require.NoError(t, err)
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return &idtFixture{
		ec: ec, rsa: rk, ed: ed, rsaPE: rsaPEM,
		keys: staticKeys{
			"ec":  {Key: &ec.PublicKey, Algorithm: "ES256"},
			"rsa": {Key: rsaPEM}, // PEM-stored, no algorithm, as the in-memory stores keep it
			"ed":  {Key: ed.Public(), Algorithm: "EdDSA"},
			"enc": {Key: &rk.PublicKey, Algorithm: "RSA-OAEP"},
		},
	}
}

func atHashSHA256(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func idtClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":       idtIssuer,
		"sub":       "user-1",
		"aud":       idtClient,
		"iat":       now.Unix(),
		"exp":       now.Add(5 * time.Minute).Unix(),
		"auth_time": now.Add(-time.Minute).Unix(),
		"nonce":     idtNonce,
		"at_hash":   atHashSHA256(idtAccess),
		"typ":       "ID",
		"email":     "ada@example.com",

		"email_verified": true,
	}
}

func (f *idtFixture) sign(t *testing.T, method jwt.SigningMethod, kid string, key any, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}

func (f *idtFixture) es256(t *testing.T, claims jwt.MapClaims) string {
	return f.sign(t, jwt.SigningMethodES256, "ec", f.ec, claims)
}

func (f *idtFixture) verify(token string) (*IDTokenClaims, error) {
	return VerifyIDToken(context.Background(), &VerifyIDTokenRequest{
		IDToken: token, Issuer: idtIssuer, ClientID: idtClient, Keys: f.keys,
		Nonce: idtNonce, AccessToken: idtAccess,
	})
}

func TestVerifyIDToken_AcceptsAValidToken(t *testing.T) {
	f := newIDTFixture(t)
	c := idtClaims()
	got, err := f.verify(f.es256(t, c))
	require.NoError(t, err)

	assert.Equal(t, idtIssuer, got.Issuer)
	assert.Equal(t, "user-1", got.Subject)
	assert.Equal(t, []string{idtClient}, got.Audience)
	assert.Equal(t, idtNonce, got.Nonce)
	assert.Equal(t, c["auth_time"], got.AuthTime.Unix())
	assert.Equal(t, c["exp"], got.ExpiresAt.Unix())
	assert.Equal(t, "ada@example.com", got.Email)
	assert.True(t, got.EmailVerified)
	assert.Equal(t, "ID", got.Claims["typ"])
}

// at_hash uses the hash of the ID token's own algorithm: SHA-256 for
// RS256, SHA-512 for EdDSA (Ed25519).
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
func TestVerifyIDToken_AtHashFollowsTheAlgorithm(t *testing.T) {
	f := newIDTFixture(t)

	_, err := f.verify(f.sign(t, jwt.SigningMethodRS256, "rsa", f.rsa, idtClaims()))
	require.NoError(t, err, "RS256 with a PEM-stored key and a SHA-256 at_hash")

	c := idtClaims()
	sum := sha512.Sum512([]byte(idtAccess))
	c["at_hash"] = base64.RawURLEncoding.EncodeToString(sum[:32])
	_, err = f.verify(f.sign(t, jwt.SigningMethodEdDSA, "ed", f.ed, c))
	require.NoError(t, err, "EdDSA hashes with SHA-512")

	c["at_hash"] = atHashSHA256(idtAccess)
	_, err = f.verify(f.sign(t, jwt.SigningMethodEdDSA, "ed", f.ed, c))
	require.ErrorIs(t, err, ErrInvalidIDToken, "a SHA-256 at_hash on an EdDSA token is wrong")
}

func TestVerifyIDToken_AtHashAndNonceAreOptionalWhenNotAskedFor(t *testing.T) {
	f := newIDTFixture(t)
	c := idtClaims()
	delete(c, "at_hash")
	delete(c, "nonce")
	_, err := VerifyIDToken(context.Background(), &VerifyIDTokenRequest{
		IDToken: f.es256(t, c), Issuer: idtIssuer, ClientID: idtClient, Keys: f.keys,
		AccessToken: idtAccess,
	})
	require.NoError(t, err, "code flow makes at_hash optional, and no nonce was sent")
}

// Each case changes one thing about an otherwise valid token, and each
// must fail with ErrInvalidIDToken.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
// See: https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
// See: https://openid.net/specs/openid-connect-core-1_0.html#Symmetric (§10.1)
// See: https://cwe.mitre.org/data/definitions/347.html
// See: https://www.rfc-editor.org/rfc/rfc8725#section-3.1 (algorithm verification)
func TestVerifyIDToken_Refuses(t *testing.T) {
	f := newIDTFixture(t)
	with := func(k string, v any) jwt.MapClaims {
		c := idtClaims()
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	past := time.Now().Add(-10 * time.Minute).Unix()

	cases := map[string]string{
		"another audience":                f.es256(t, with("aud", "client-2")),
		"another issuer":                  f.es256(t, with("iss", "https://evil.example")),
		"a different nonce":               f.es256(t, with("nonce", "n-other")),
		"no nonce when one was sent":      f.es256(t, with("nonce", nil)),
		"an at_hash for another token":    f.es256(t, with("at_hash", atHashSHA256("other-access"))),
		"an expired token":                f.es256(t, with("exp", past)),
		"no exp":                          f.es256(t, with("exp", nil)),
		"no iat":                          f.es256(t, with("iat", nil)),
		"an iat in the future":            f.es256(t, with("iat", time.Now().Add(10*time.Minute).Unix())),
		"no sub":                          f.es256(t, with("sub", nil)),
		"Keycloak's access-token typ":     f.es256(t, with("typ", "Bearer")),
		"oneauth's access-token type":     f.es256(t, with("type", "access")),
		"several audiences, no azp":       f.es256(t, with("aud", []string{idtClient, "api"})),
		"an azp naming another client":    f.es256(t, with("azp", "client-2")),
		"no kid":                          f.sign(t, jwt.SigningMethodES256, "", f.ec, idtClaims()),
		"an unknown kid":                  f.sign(t, jwt.SigningMethodES256, "nope", f.ec, idtClaims()),
		"a key published for another alg": f.sign(t, jwt.SigningMethodRS256, "enc", f.rsa, idtClaims()),
		"a signature by another key": func() string {
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			return f.sign(t, jwt.SigningMethodES256, "ec", other, idtClaims())
		}(),
		// HS256 keyed with the RSA public key's PEM: the alg-confusion
		// forgery, since that PEM is public.
		"HS256 keyed with the public key": f.sign(t, jwt.SigningMethodHS256, "rsa", f.rsaPE, idtClaims()),
		"alg none":                        f.sign(t, jwt.SigningMethodNone, "ec", jwt.UnsafeAllowNoneSignatureType, idtClaims()),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := f.verify(token)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidIDToken), "error should wrap ErrInvalidIDToken: %v", err)
		})
	}
}

func TestVerifyIDToken_AzpEqualToTheClientPasses(t *testing.T) {
	f := newIDTFixture(t)
	c := idtClaims()
	c["aud"] = []string{idtClient, "api"}
	c["azp"] = idtClient
	_, err := f.verify(f.es256(t, c))
	require.NoError(t, err)
}

func TestVerifyIDToken_RequiresIssuerClientAndKeys(t *testing.T) {
	f := newIDTFixture(t)
	token := f.es256(t, idtClaims())
	for name, req := range map[string]*VerifyIDTokenRequest{
		"nil":       nil,
		"no token":  {Issuer: idtIssuer, ClientID: idtClient, Keys: f.keys},
		"no issuer": {IDToken: token, ClientID: idtClient, Keys: f.keys},
		"no client": {IDToken: token, Issuer: idtIssuer, Keys: f.keys},
		"no keys":   {IDToken: token, Issuer: idtIssuer, ClientID: idtClient},
	} {
		_, err := VerifyIDToken(context.Background(), req)
		assert.ErrorIs(t, err, ErrInvalidIDToken, name)
	}
}
