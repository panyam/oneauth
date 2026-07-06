// Auth-method binding: a registered confidential client MUST authenticate with
// the method family it registered as (token_endpoint_auth_method). Presenting a
// different family — e.g. a private_key_jwt client authenticating with a shared
// secret, or the reverse — is an auth-method downgrade and is rejected
// invalid_client (issue 360).
//
// Binding activates only when the authenticator is wired with an AppStore
// (NewClientAuthenticatorWithAppStore); without one there is no registered
// method to bind to and behavior is unchanged. client_secret_basic and
// client_secret_post are one family: the authenticator classifies both as
// "client_secret" and does not learn which channel carried the secret.
//
// See:
//   - RFC 7521 §4.2 / RFC 7523 §2.2 (private_key_jwt / client_secret_jwt)
//   - OIDC Core §9 (token_endpoint_auth_method registration)
//   - oneauth issue 360 (this); 356 (confidential-client auth gate)
package apiauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type bindingEnv struct {
	apps     core.AppRegistrationStore
	ks       *keys.InMemoryKeyStore
	authn    apiauth.ClientAuthenticator
	audience string
}

// newBindingEnv wires an authenticator with an AppStore so the issue-360
// binding is live. Callers register clients via registerSecretClient /
// registerPKJWTClient before authenticating.
func newBindingEnv(t *testing.T) *bindingEnv {
	t.Helper()
	apps := core.NewInMemoryAppStore()
	ks := keys.NewInMemoryKeyStore()
	return &bindingEnv{
		apps:     apps,
		ks:       ks,
		authn:    apiauth.NewClientAuthenticatorWithAppStore(ks, apps),
		audience: "https://oneauth-test/api/token",
	}
}

// registerSecretClient registers a client with the given
// token_endpoint_auth_method and stores a matching HMAC secret in the KeyStore,
// so the raw-secret path can authenticate it.
func (e *bindingEnv) registerSecretClient(t *testing.T, clientID, method, secret string) {
	t.Helper()
	_, err := e.apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID:                clientID,
		TokenEndpointAuthMethod: method,
		SigningAlg:              "HS256",
	}})
	require.NoError(t, err)
	_, err = e.ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID:  clientID,
		Key:       []byte(secret),
		Algorithm: "HS256",
	}})
	require.NoError(t, err)
}

// registerPKJWTClient registers a private_key_jwt client and stores its RSA
// public key (PEM, RS256), returning the private half for signing assertions.
func (e *bindingEnv) registerPKJWTClient(t *testing.T, clientID string) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubPEM, err := utils.EncodePublicKeyPEM(&priv.PublicKey)
	require.NoError(t, err)
	_, err = e.apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID:                clientID,
		TokenEndpointAuthMethod: "private_key_jwt",
		SigningAlg:              "RS256",
	}})
	require.NoError(t, err)
	_, err = e.ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID:  clientID,
		Key:       pubPEM,
		Algorithm: "RS256",
	}})
	require.NoError(t, err)
	return priv
}

func (e *bindingEnv) signAssertion(t *testing.T, priv *rsa.PrivateKey, clientID string) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": e.audience,
		"exp": now.Add(2 * time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": clientID + "-jti-" + now.Format("150405.000000000"),
	})
	signed, err := tok.SignedString(priv)
	require.NoError(t, err)
	return signed
}

func (e *bindingEnv) authSecret(clientID, secret string) (*apiauth.AuthenticateClientResponse, error) {
	return e.authn.AuthenticateClient(context.Background(), &apiauth.AuthenticateClientRequest{
		ClientID:     clientID,
		ClientSecret: secret,
	})
}

func (e *bindingEnv) authAssertion(assertion string) (*apiauth.AuthenticateClientResponse, error) {
	return e.authn.AuthenticateClient(context.Background(), &apiauth.AuthenticateClientRequest{
		ClientAssertionType: apiauth.ClientAssertionTypeJWTBearer,
		ClientAssertion:     assertion,
		Audiences:           []string{e.audience},
	})
}

// --- downgrade blocked -----------------------------------------------------

func TestBinding_PrivateKeyJWTClient_PresentsSecret_Rejected(t *testing.T) {
	e := newBindingEnv(t)
	// A private_key_jwt client that also happens to have a shared secret on
	// file must not be able to authenticate with it.
	priv := e.registerPKJWTClient(t, "pkjwt-client")
	_, err := e.ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID: "pkjwt-client", Key: []byte("leaked-secret"), Algorithm: "HS256",
	}})
	require.NoError(t, err)
	_ = priv

	_, err = e.authSecret("pkjwt-client", "leaked-secret")
	require.Error(t, err, "private_key_jwt client MUST NOT authenticate with a shared secret")
	assert.Contains(t, err.Error(), "invalid_client")
}

func TestBinding_ClientSecretJWTClient_PresentsSecret_Rejected(t *testing.T) {
	e := newBindingEnv(t)
	// client_secret_jwt: proves possession of the secret via a signed JWT,
	// never by transmitting it. Sending the raw secret is a downgrade.
	e.registerSecretClient(t, "csjwt-client", "client_secret_jwt", "shared-secret")

	_, err := e.authSecret("csjwt-client", "shared-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_client")
}

func TestBinding_SecretClient_PresentsAssertion_Rejected(t *testing.T) {
	e := newBindingEnv(t)
	// A client registered client_secret_basic must not authenticate via a
	// private_key_jwt assertion even if a public key is on file for it.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubPEM, err := utils.EncodePublicKeyPEM(&priv.PublicKey)
	require.NoError(t, err)
	_, err = e.apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID: "basic-client", TokenEndpointAuthMethod: "client_secret_basic", SigningAlg: "RS256",
	}})
	require.NoError(t, err)
	_, err = e.ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID: "basic-client", Key: pubPEM, Algorithm: "RS256",
	}})
	require.NoError(t, err)

	_, err = e.authAssertion(e.signAssertion(t, priv, "basic-client"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_client")
}

// --- matching method accepted ----------------------------------------------

func TestBinding_SecretClient_PresentsSecret_Accepted(t *testing.T) {
	e := newBindingEnv(t)
	// Registered client_secret_post, presented secret → "client_secret"
	// family matches. This also guards the client_secret_basic case, since
	// both collapse to the same family (issue 362 sends basic for a
	// post-registered client).
	e.registerSecretClient(t, "secret-client", "client_secret_post", "the-secret")

	resp, err := e.authSecret("secret-client", "the-secret")
	require.NoError(t, err)
	assert.Equal(t, "secret-client", resp.ClientID)
}

func TestBinding_PrivateKeyJWTClient_PresentsAssertion_Accepted(t *testing.T) {
	e := newBindingEnv(t)
	priv := e.registerPKJWTClient(t, "pkjwt-ok")

	resp, err := e.authAssertion(e.signAssertion(t, priv, "pkjwt-ok"))
	require.NoError(t, err)
	assert.Equal(t, "pkjwt-ok", resp.ClientID)
	assert.Equal(t, "private_key_jwt", resp.Method)
}

// --- binding inert without AppStore ----------------------------------------

// --- HTTP integration: binding reaches client_credentials over the wire ----

// TestBinding_ClientCredentials_HTTP_PrivateKeyJWTClient_PresentsSecret_Rejected
// proves the binding is live through the full token-endpoint HTTP path for the
// client_credentials grant, which bypasses the confidential-client gate and
// authenticates directly. It pins that NewOneAuth threads its AppStore into the
// default authenticator (oneauth.go) so the downgrade is caught end-to-end, not
// only in a direct authenticator unit test.
func TestBinding_ClientCredentials_HTTP_PrivateKeyJWTClient_PresentsSecret_Rejected(t *testing.T) {
	e := newConfClientEnv(t)
	// Register a private_key_jwt client that also has a shared secret on file.
	_, err := e.apiAuth.OneAuth.AppStore.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID: "pkjwt-http", TokenEndpointAuthMethod: "private_key_jwt", SigningAlg: "HS256",
	}})
	require.NoError(t, err)
	_, err = e.apiAuth.OneAuth.KeyStore.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID: "pkjwt-http", Key: []byte("leaked"), Algorithm: "HS256",
	}})
	require.NoError(t, err)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "pkjwt-http")
	form.Set("client_secret", "leaked")

	status, body := postForm(t, e.apiAuth, form)
	assert.Equal(t, http.StatusUnauthorized, status, "private_key_jwt client using a shared secret must be rejected over HTTP")
	assert.Equal(t, "invalid_client", body["error"])
}

func TestBinding_NoAppStore_MismatchAllowed(t *testing.T) {
	// Without an AppStore the authenticator has no registered method to bind
	// to, so a secret authenticates regardless of any (absent) registration.
	// Backward-compatibility guard for NewClientAuthenticator.
	ks := keys.NewInMemoryKeyStore()
	_, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID: "unbound", Key: []byte("s3cret"), Algorithm: "HS256",
	}})
	require.NoError(t, err)
	authn := apiauth.NewClientAuthenticator(ks)

	resp, err := authn.AuthenticateClient(context.Background(), &apiauth.AuthenticateClientRequest{
		ClientID: "unbound", ClientSecret: "s3cret",
	})
	require.NoError(t, err)
	assert.Equal(t, "unbound", resp.ClientID)
}
