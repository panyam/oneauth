// Tests for confidential-client authentication on the jwt-bearer (RFC 7523)
// and token-exchange (RFC 8693 / ID-JAG) grants — issue 356.
//
// A registered confidential client MUST authenticate on these grants; a
// public / unregistered client keeps the RFC 7523 §3 assertion-only path.
// For ID-JAG redemption the presenter must additionally authenticate as the
// client the ID-JAG names (its client_id claim), binding a single-use ID-JAG
// to a specific client so a stolen one can't be redeemed as a public client.
//
// See:
//   - RFC 7523 §3:  https://www.rfc-editor.org/rfc/rfc7523#section-3
//   - draft-ietf-oauth-identity-assertion-authz-grant-04
//   - oneauth issue 356 (this); 266 (device_code precedent)
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type confClientEnv struct {
	apiAuth      *apiAuthFixture
	idpKey       *rsa.PrivateKey
	idpIssuer    string
	asAudience   string
	confClientID string
	confSecret   string
}

// newConfClientEnv builds an AS that trusts one IdP for assertions AND
// registers one confidential client (client_secret_post) whose secret lives
// in the KeyStore, so the lazy ClientAuthenticator can validate it.
func newConfClientEnv(t *testing.T) *confClientEnv {
	t.Helper()
	idpKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	e := &confClientEnv{
		idpKey:       idpKey,
		idpIssuer:    "https://corp-idp.example.com",
		asAudience:   "https://oneauth-test/api/token",
		confClientID: "mcp-client-conf",
		confSecret:   "conf-secret-value",
	}

	apps := core.NewInMemoryAppStore()
	_, err = apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID:                e.confClientID,
		TokenEndpointAuthMethod: "client_secret_post",
		SigningAlg:              "HS256",
	}})
	require.NoError(t, err)

	ks := keys.NewInMemoryKeyStore()
	_, err = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID:  e.confClientID,
		Key:       []byte(e.confSecret),
		Algorithm: "HS256",
	}})
	require.NoError(t, err)

	e.apiAuth = newAPIAuthFixture(apiauth.OneAuthConfig{
		KeyStore:   ks,
		SigningKey: []byte("test-secret-key-for-testing-only-32b"),
		SigningAlg: "HS256",
		Issuer:     "oneauth-test",
		Audience:   e.asAudience,
		AppStore:   apps,
		TrustedAssertionIssuers: []apiauth.TrustedAssertionIssuer{{
			Issuer:             e.idpIssuer,
			PublicKey:          &idpKey.PublicKey,
			Audiences:          []string{e.asAudience},
			AcceptedAlgorithms: []string{"RS256"},
		}},
	}, nil)
	return e
}

// mint signs an assertion with the IdP key. typ="" is a plain jwt-bearer
// assertion; typ=IDJAGTypeHeader with a client_id override is an ID-JAG.
func (e *confClientEnv) mint(t *testing.T, typ string, overrides jwt.MapClaims) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": e.idpIssuer,
		"sub": "alice@corp.example.com",
		"aud": e.asAudience,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"nbf": now.Add(-1 * time.Second).Unix(),
	}
	for k, v := range overrides {
		claims[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if typ != "" {
		tok.Header["typ"] = typ
	}
	signed, err := tok.SignedString(e.idpKey)
	require.NoError(t, err)
	return signed
}

func (e *confClientEnv) mintIDJAG(t *testing.T, clientID, jti string) string {
	return e.mint(t, apiauth.IDJAGTypeHeader, jwt.MapClaims{"client_id": clientID, "jti": jti})
}

// --- plain jwt-bearer ------------------------------------------------------

func TestJwtBearer_ConfidentialClient_CorrectSecret_Succeeds(t *testing.T) {
	e := newConfClientEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", e.mint(t, "", nil))
	form.Set("client_id", e.confClientID)
	form.Set("client_secret", e.confSecret)

	status, body := postForm(t, e.apiAuth, form)
	assert.Equal(t, http.StatusOK, status)
	assert.NotEmpty(t, body["access_token"])
}

func TestJwtBearer_ConfidentialClient_WrongSecret_InvalidClient(t *testing.T) {
	e := newConfClientEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", e.mint(t, "", nil))
	form.Set("client_id", e.confClientID)
	form.Set("client_secret", "WRONG")

	status, body := postForm(t, e.apiAuth, form)
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", body["error"])
}

func TestJwtBearer_ConfidentialClient_MissingSecret_InvalidClient(t *testing.T) {
	e := newConfClientEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", e.mint(t, "", nil))
	form.Set("client_id", e.confClientID)
	// client_secret intentionally absent.

	status, body := postForm(t, e.apiAuth, form)
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", body["error"])
}

func TestJwtBearer_PublicClient_AssertionOnly_Succeeds(t *testing.T) {
	e := newConfClientEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", e.mint(t, "", nil))
	form.Set("client_id", "unregistered-public-client") // not in AppStore
	// no client_secret — RFC 7523 §3 public path.

	status, body := postForm(t, e.apiAuth, form)
	assert.Equal(t, http.StatusOK, status, "unregistered client_id keeps the assertion-only path")
	assert.NotEmpty(t, body["access_token"])
}

// --- ID-JAG redemption -----------------------------------------------------

func TestIDJAG_Redeem_ConfidentialNamedClient_CorrectSecret_Succeeds(t *testing.T) {
	e := newConfClientEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", e.mintIDJAG(t, e.confClientID, "jti-ok-1"))
	form.Set("client_id", e.confClientID)
	form.Set("client_secret", e.confSecret)

	status, body := postForm(t, e.apiAuth, form)
	require.Equal(t, http.StatusOK, status)
	accessToken, _ := body["access_token"].(string)
	require.NotEmpty(t, accessToken)
	_, claims := parseUnverified(t, accessToken)
	assert.Equal(t, e.confClientID, claims["client_id"], "issued token binds the ID-JAG client_id")
}

func TestIDJAG_Redeem_ConfidentialNamedClient_NoCreds_InvalidClient(t *testing.T) {
	e := newConfClientEnv(t)
	// A holder of the ID-JAG tries to redeem it without authenticating as
	// the named confidential client (the stolen-ID-JAG case).
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", e.mintIDJAG(t, e.confClientID, "jti-theft-1"))
	// no client_id / client_secret.

	status, body := postForm(t, e.apiAuth, form)
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", body["error"])
}

func TestIDJAG_Redeem_ClientIDMismatch_InvalidGrant(t *testing.T) {
	e := newConfClientEnv(t)
	// Register a SECOND confidential client and authenticate as it, while
	// the ID-JAG names the first — authenticated client_id != ID-JAG claim.
	other := "other-conf-client"
	otherSecret := "other-secret"
	// Reuse the AS's stores via a fresh confidential registration.
	registerConfidentialClient(t, e, other, otherSecret)

	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", e.mintIDJAG(t, e.confClientID, "jti-mismatch-1")) // names confClientID
	form.Set("client_id", other)
	form.Set("client_secret", otherSecret)

	status, body := postForm(t, e.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
}

func TestIDJAG_Redeem_PublicNamedClient_AssertionOnly_Succeeds(t *testing.T) {
	e := newConfClientEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", e.mintIDJAG(t, "unregistered-client", "jti-pub-1")) // named client not registered
	form.Set("client_id", "unregistered-client")

	status, body := postForm(t, e.apiAuth, form)
	assert.Equal(t, http.StatusOK, status, "ID-JAG naming an unregistered client keeps assertion-only path")
	assert.NotEmpty(t, body["access_token"])
}

// TestIDJAG_Redeem_FailedAuth_DoesNotBurnJTI — a rejected redemption
// (invalid_client) must NOT consume the single-use jti, so a subsequent
// correctly-authenticated redemption of the SAME ID-JAG still succeeds.
func TestIDJAG_Redeem_FailedAuth_DoesNotBurnJTI(t *testing.T) {
	e := newConfClientEnv(t)
	idjag := e.mintIDJAG(t, e.confClientID, "jti-retry-1")

	bad := url.Values{}
	bad.Set("grant_type", apiauth.JwtBearerGrantType)
	bad.Set("assertion", idjag)
	bad.Set("client_id", e.confClientID)
	bad.Set("client_secret", "WRONG")
	status1, _ := postForm(t, e.apiAuth, bad)
	require.Equal(t, http.StatusUnauthorized, status1)

	good := url.Values{}
	good.Set("grant_type", apiauth.JwtBearerGrantType)
	good.Set("assertion", idjag)
	good.Set("client_id", e.confClientID)
	good.Set("client_secret", e.confSecret)
	status2, body2 := postForm(t, e.apiAuth, good)
	assert.Equal(t, http.StatusOK, status2, "failed auth must not consume the single-use jti")
	assert.NotEmpty(t, body2["access_token"])
}

// --- token-exchange --------------------------------------------------------

func TestTokenExchange_ConfidentialClient_WrongSecret_InvalidClient(t *testing.T) {
	e := newConfClientEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", e.mint(t, "", nil))
	form.Set("subject_token_type", apiauth.TokenTypeJWT)
	form.Set("client_id", e.confClientID)
	form.Set("client_secret", "WRONG")

	status, body := postForm(t, e.apiAuth, form)
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", body["error"])
}

func TestTokenExchange_PublicClient_Succeeds(t *testing.T) {
	e := newConfClientEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", e.mint(t, "", nil))
	form.Set("subject_token_type", apiauth.TokenTypeJWT)
	// no client credentials — public exchange.

	status, body := postForm(t, e.apiAuth, form)
	assert.Equal(t, http.StatusOK, status)
	assert.NotEmpty(t, body["access_token"])
}

// registerConfidentialClient adds another confidential client to the AS's
// AppStore + KeyStore mid-test. Mutates through the OneAuth-exposed stores.
func registerConfidentialClient(t *testing.T, e *confClientEnv, clientID, secret string) {
	t.Helper()
	_, err := e.apiAuth.OneAuth.AppStore.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID:                clientID,
		TokenEndpointAuthMethod: "client_secret_post",
		SigningAlg:              "HS256",
	}})
	require.NoError(t, err)
	_, err = e.apiAuth.OneAuth.KeyStore.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID:  clientID,
		Key:       []byte(secret),
		Algorithm: "HS256",
	}})
	require.NoError(t, err)
}
