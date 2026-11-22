package apiauth_test

// PS256 as the AS signing algorithm (issue 330). An RSA key with
// SigningAlg "PS256" signs access tokens, ID tokens and JARM responses
// with RSASSA-PSS, and the JWKS lists the key as PS256, so a verifier that
// binds a key to its alg accepts them. FAPI 2.0 §5.4 allows PS256 and
// ES256, not RS256.
//
// See: https://www.rfc-editor.org/rfc/rfc7518#section-3.5
// See: https://github.com/panyam/oneauth/issues/330

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

const ps256Issuer = "https://as.example"

// ps256Key is an RSA key, and a key lookup that publishes it as PS256 the
// way the JWKS does.
func ps256Key(t *testing.T) (any, any, keys.KeyLookup) {
	t.Helper()
	privPEM, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	require.NoError(t, err)
	priv, err := utils.ParsePrivateKeyPEM(privPEM)
	require.NoError(t, err)
	pub, err := utils.ParsePublicKeyPEM(pubPEM)
	require.NoError(t, err)
	store := keys.NewInMemoryKeyStore()
	_, err = store.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "issuer", Key: pubPEM, Algorithm: "PS256"}})
	require.NoError(t, err)
	return priv, pub, store
}

func headerAlg(t *testing.T, token string) string {
	t.Helper()
	tok, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	require.NoError(t, err)
	alg, _ := tok.Header["alg"].(string)
	return alg
}

func TestPS256_AccessTokens(t *testing.T) {
	priv, pub, _ := ps256Key(t)
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{SigningAlg: "PS256", SigningKey: priv, VerifyKey: pub, Issuer: ps256Issuer})
	resp, err := oa.Issuer.CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "u1", Scopes: []string{"read"}})
	require.NoError(t, err)
	assert.Equal(t, "PS256", headerAlg(t, resp.Token))

	v, err := oa.Validator.ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: resp.Token})
	require.NoError(t, err)
	assert.Equal(t, "u1", v.Info.Subject)
}

// at_hash for PS256 uses SHA-256, as for RS256 (OIDC Core §3.1.3.6).
func TestPS256_IDTokens(t *testing.T) {
	priv, _, lookup := ps256Key(t)
	issuer, err := apiauth.NewJWTIDTokenIssuer(apiauth.JWTIDTokenIssuerConfig{SigningKey: priv, SigningAlg: "PS256", Issuer: ps256Issuer})
	require.NoError(t, err)
	resp, err := issuer.CreateIDToken(context.Background(), &apiauth.CreateIDTokenRequest{Subject: "u1", ClientID: "c1", Nonce: "n1", AccessToken: "at-1"})
	require.NoError(t, err)
	assert.Equal(t, "PS256", headerAlg(t, resp.Token))

	claims, err := client.VerifyIDToken(context.Background(), &client.VerifyIDTokenRequest{
		IDToken: resp.Token, Issuer: ps256Issuer, ClientID: "c1", Keys: lookup, Nonce: "n1", AccessToken: "at-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "u1", claims.Subject)
}

// The JWKS lists the key as PS256, so the SDK's alg check accepts a PS256
// response. With the key listed as RS256 it would refuse it.
func TestPS256_JARMResponses(t *testing.T) {
	priv, _, lookup := ps256Key(t)
	signer, err := apiauth.NewJWTAuthorizationResponseSigner(apiauth.JWTAuthorizationResponseSignerConfig{SigningKey: priv, SigningAlg: "PS256", Issuer: ps256Issuer})
	require.NoError(t, err)
	assert.Equal(t, []string{"PS256"}, signer.AuthorizationSigningAlgs())
	out, err := signer.SignAuthorizationResponse(context.Background(), &apiauth.SignAuthorizationResponseRequest{
		ClientID: "c1", Params: url.Values{"code": {"code-1"}, "state": {"s1"}},
	})
	require.NoError(t, err)
	assert.Equal(t, "PS256", headerAlg(t, out.Response))

	params, err := client.VerifyAuthorizationResponse(context.Background(), &client.VerifyAuthorizationResponseRequest{
		Response: out.Response, Issuer: ps256Issuer, ClientID: "c1", Keys: lookup,
	})
	require.NoError(t, err)
	assert.Equal(t, "code-1", params.Get("code"))
}

// A client whose key is registered as PS256 authenticates with a PS256
// private_key_jwt assertion (FAPI 2.0 §5.4.1, issue 330's client half).
func TestPS256_PrivateKeyJWTClient(t *testing.T) {
	privPEM, pubPEM, err := utils.GenerateRSAKeyPair(2048)
	require.NoError(t, err)
	priv, err := utils.ParsePrivateKeyPEM(privPEM)
	require.NoError(t, err)
	ks := keys.NewInMemoryKeyStore()
	_, err = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: "ps-client", Key: pubPEM, Algorithm: "PS256"}})
	require.NoError(t, err)
	f := &pkjwtFixture{t: t, clientID: "ps-client", tokenURL: "https://oneauth.example.com/api/token",
		auth: newAPIAuthFixture(apiauth.OneAuthConfig{
			KeyStore: ks, SigningKey: []byte("server-jwt-secret-key-32chars!!"), SigningAlg: "HS256", Issuer: "test-issuer",
			Authenticator: apiauth.NewClientAuthenticator(ks), AcceptedAudiences: []string{"https://oneauth.example.com/api/token"},
		}, nil)}

	tok := jwt.NewWithClaims(jwt.SigningMethodPS256, jwt.MapClaims{
		"iss": f.clientID, "sub": f.clientID, "aud": f.tokenURL, "jti": "ps-jti-1",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
	})
	assertion, err := tok.SignedString(priv)
	require.NoError(t, err)
	rr := f.postTokenForm(map[string]string{
		"grant_type": "client_credentials", "client_id": f.clientID,
		"client_assertion_type": apiauth.ClientAssertionTypeJWTBearer, "client_assertion": assertion,
	})
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}
