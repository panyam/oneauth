package apiauth_test

// private_key_jwt for a client registered with jwks_uri (issue 507): the
// authenticator fetches the client's key set, picks the key by the
// assertion's kid, refetches once on an unknown kid so the client can
// rotate keys, and never lets the assertion choose an algorithm the key
// can't have.
//
// References:
//   - RFC 7523 §3 (https://www.rfc-editor.org/rfc/rfc7523#section-3)
//   - RFC 7591 §2 jwks_uri (https://www.rfc-editor.org/rfc/rfc7591#section-2)
//   - OIDC Core §9 and §10.1.1 key rotation (https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys)
//   - CVE-2016-10555 alg confusion; CWE-918 SSRF
//   - See: https://github.com/panyam/oneauth/issues/507

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

const jwksTokenURL = "https://as.example/api/token"

// jwksHost serves a JWK set it can change, and counts fetches.
type jwksHost struct {
	mu      sync.Mutex
	keys    []utils.JWK
	fetches atomic.Int32
	srv     *httptest.Server
}

func newJWKSHost(t *testing.T) *jwksHost {
	h := &jwksHost{}
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h.fetches.Add(1)
		h.mu.Lock()
		defer h.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"keys": h.keys})
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *jwksHost) publish(t *testing.T, kid string, pub crypto.PublicKey) {
	t.Helper()
	jwk, err := utils.PublicKeyToJWK(kid, "", pub)
	require.NoError(t, err)
	h.mu.Lock()
	h.keys = append(h.keys, jwk)
	h.mu.Unlock()
}

type jwksClientFixture struct {
	host *jwksHost
	auth apiauth.ClientAuthenticator
}

// newJWKSClient registers "jwks-client" with the host's jwks_uri and pinned
// alg (empty for none), using a fetcher that trusts the test server.
func newJWKSClient(t *testing.T, pinnedAlg string, tune func(*apiauth.ClientJWKSFetcher)) *jwksClientFixture {
	host := newJWKSHost(t)
	apps := core.NewInMemoryAppStore()
	_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID: "jwks-client", TokenEndpointAuthMethod: "private_key_jwt", SigningAlg: "RS256",
		JWKSURI: host.srv.URL + "/jwks.json", TokenEndpointAuthSigningAlg: pinnedAlg,
	}})
	require.NoError(t, err)
	f := &apiauth.ClientJWKSFetcher{HTTPClient: host.srv.Client(), MinRefreshInterval: time.Nanosecond}
	if tune != nil {
		tune(f)
	}
	auth := apiauth.NewClientAuthenticatorWithOptions(keys.NewInMemoryKeyStore(), apiauth.ClientAuthenticatorOptions{AppStore: apps, JWKSFetcher: f})
	return &jwksClientFixture{host: host, auth: auth}
}

func assertionFor(t *testing.T, method jwt.SigningMethod, kid string, key any) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(method, jwt.MapClaims{
		"iss": "jwks-client", "sub": "jwks-client", "aud": jwksTokenURL,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": rand.Text(),
	})
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}

func (fx *jwksClientFixture) authenticate(assertion string) (*apiauth.AuthenticateClientResponse, error) {
	return fx.auth.AuthenticateClient(context.Background(), &apiauth.AuthenticateClientRequest{
		ClientAssertionType: apiauth.ClientAssertionTypeJWTBearer, ClientAssertion: assertion, Audiences: []string{jwksTokenURL},
	})
}

func TestClientJWKSURI_AuthenticatesWithThePublishedKey(t *testing.T) {
	fx := newJWKSClient(t, "", nil)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fx.host.publish(t, "k1", &k.PublicKey)

	resp, err := fx.authenticate(assertionFor(t, jwt.SigningMethodES256, "k1", k))
	require.NoError(t, err)
	assert.Equal(t, "jwks-client", resp.ClientID)
	assert.Equal(t, "private_key_jwt", resp.Method)

	_, err = fx.authenticate(assertionFor(t, jwt.SigningMethodES256, "k1", k))
	require.NoError(t, err)
	assert.EqualValues(t, 1, fx.host.fetches.Load(), "a known kid is served from the cache")
}

// See: https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
func TestClientJWKSURI_RotatedKeyIsFetchedOnUnknownKid(t *testing.T) {
	fx := newJWKSClient(t, "", nil)
	old, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fx.host.publish(t, "old", &old.PublicKey)
	_, err := fx.authenticate(assertionFor(t, jwt.SigningMethodES256, "old", old))
	require.NoError(t, err)

	rotated, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fx.host.publish(t, "new", &rotated.PublicKey)
	_, err = fx.authenticate(assertionFor(t, jwt.SigningMethodES256, "new", rotated))
	require.NoError(t, err)
	assert.EqualValues(t, 2, fx.host.fetches.Load())
}

func TestClientJWKSURI_UnknownKidIsRefused(t *testing.T) {
	fx := newJWKSClient(t, "", nil)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fx.host.publish(t, "k1", &k.PublicKey)
	_, err := fx.authenticate(assertionFor(t, jwt.SigningMethodES256, "nope", k))
	assert.Error(t, err)
}

// A refetch on an unknown kid is rate-limited, so a client sending made-up
// kids can't make the AS hammer its jwks_uri (or someone else's).
func TestClientJWKSURI_RefetchIsRateLimited(t *testing.T) {
	fx := newJWKSClient(t, "", func(f *apiauth.ClientJWKSFetcher) { f.MinRefreshInterval = time.Hour })
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fx.host.publish(t, "k1", &k.PublicKey)
	for i := 0; i < 5; i++ {
		_, _ = fx.authenticate(assertionFor(t, jwt.SigningMethodES256, "made-up", k))
	}
	assert.EqualValues(t, 1, fx.host.fetches.Load())
}

// The key decides the algorithm family. An RSA key can't verify an HS256
// assertion whose "secret" is the public key, nor an ES256 one.
// See: CVE-2016-10555
func TestClientJWKSURI_AlgorithmMustFitTheKey(t *testing.T) {
	fx := newJWKSClient(t, "", nil)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	fx.host.publish(t, "rsa", &rk.PublicKey)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	pubPEM, err := utils.EncodePublicKeyPEM(&rk.PublicKey)
	require.NoError(t, err)
	_, err = fx.authenticate(assertionFor(t, jwt.SigningMethodHS256, "rsa", pubPEM))
	assert.Error(t, err, "HS256 keyed with the public key")
	_, err = fx.authenticate(assertionFor(t, jwt.SigningMethodES256, "rsa", ek))
	assert.Error(t, err, "ES256 against an RSA key")
	_, err = fx.authenticate(assertionFor(t, jwt.SigningMethodPS256, "rsa", rk))
	assert.NoError(t, err, "PS256 is an RSA algorithm too")
}

// A client that registered token_endpoint_auth_signing_alg gets only that.
func TestClientJWKSURI_PinnedAlgorithm(t *testing.T) {
	fx := newJWKSClient(t, "PS256", nil)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	fx.host.publish(t, "rsa", &rk.PublicKey)
	_, err := fx.authenticate(assertionFor(t, jwt.SigningMethodRS256, "rsa", rk))
	assert.Error(t, err)
	_, err = fx.authenticate(assertionFor(t, jwt.SigningMethodPS256, "rsa", rk))
	assert.NoError(t, err)
}

// With one signing key published, an assertion without a kid uses it.
// With two, it must say which.
func TestClientJWKSURI_NoKid(t *testing.T) {
	one := newJWKSClient(t, "", nil)
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	one.host.publish(t, "k1", &k1.PublicKey)
	_, err := one.authenticate(assertionFor(t, jwt.SigningMethodES256, "", k1))
	require.NoError(t, err)

	two := newJWKSClient(t, "", nil)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	two.host.publish(t, "k1", &k1.PublicKey)
	two.host.publish(t, "k2", &k2.PublicKey)
	_, err = two.authenticate(assertionFor(t, jwt.SigningMethodES256, "", k1))
	assert.Error(t, err)
}

// The default fetcher refuses private and loopback addresses at dial time,
// doesn't follow redirects, and caps the body.
// See: https://cwe.mitre.org/data/definitions/918.html
func TestClientJWKSFetcher_Guards(t *testing.T) {
	ctx := context.Background()
	local := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"keys":[]}`)) }))
	defer local.Close()
	_, err := (&apiauth.ClientJWKSFetcher{}).Keys(ctx, local.URL, false)
	assert.ErrorContains(t, err, "private", "the default fetcher dials no loopback address")

	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer redirect.Close()
	_, err = (&apiauth.ClientJWKSFetcher{AllowPrivateHosts: true, HTTPClient: redirect.Client()}).Keys(ctx, redirect.URL, false)
	assert.ErrorContains(t, err, "status 302", "a redirect isn't followed")

	big := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"keys":[],"pad":"` + strings.Repeat("x", 200<<10) + `"}`))
	}))
	defer big.Close()
	_, err = (&apiauth.ClientJWKSFetcher{AllowPrivateHosts: true, HTTPClient: big.Client()}).Keys(ctx, big.URL, false)
	assert.ErrorContains(t, err, "over 65536 bytes", "an oversized body is refused")

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"keys":[]}`)) }))
	defer plain.Close()
	_, err = (&apiauth.ClientJWKSFetcher{AllowPrivateHosts: true}).Keys(ctx, plain.URL, false)
	assert.Error(t, err, "http is refused")
}

// RootCAs trusts a private CA while the dial guard and redirect rule stay
// in force, which a custom HTTPClient would replace.
func TestClientJWKSFetcher_RootCAs(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"keys":[{"kty":"EC","kid":"k"}]}`)) }))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	set, err := (&apiauth.ClientJWKSFetcher{AllowPrivateHosts: true, RootCAs: pool}).Keys(context.Background(), srv.URL, false)
	require.NoError(t, err)
	assert.Equal(t, "k", set.Keys[0].Kid)

	_, err = (&apiauth.ClientJWKSFetcher{AllowPrivateHosts: true}).Keys(context.Background(), srv.URL, false)
	assert.Error(t, err, "without RootCAs the test server's certificate isn't trusted")
	_, err = (&apiauth.ClientJWKSFetcher{RootCAs: pool}).Keys(context.Background(), srv.URL, false)
	assert.ErrorContains(t, err, "private", "RootCAs doesn't lift the dial guard")
}

// A key that declares its alg allows only that one, even where the key
// type would verify another (RFC 7517 §4.4).
func TestClientJWKSURI_KeyAlgIsBinding(t *testing.T) {
	fx := newJWKSClient(t, "", nil)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk, err := utils.PublicKeyToJWK("rsa", "RS256", &rk.PublicKey)
	require.NoError(t, err)
	fx.host.mu.Lock()
	fx.host.keys = append(fx.host.keys, jwk)
	fx.host.mu.Unlock()
	_, err = fx.authenticate(assertionFor(t, jwt.SigningMethodPS256, "rsa", rk))
	assert.Error(t, err)
	_, err = fx.authenticate(assertionFor(t, jwt.SigningMethodRS256, "rsa", rk))
	assert.NoError(t, err)
}

// An encryption key (use "enc") never verifies an assertion, even when it
// is the only key and the assertion names no kid (RFC 7517 §4.2).
func TestClientJWKSURI_EncryptionKeyNeverVerifies(t *testing.T) {
	fx := newJWKSClient(t, "", nil)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, err := utils.PublicKeyToJWK("k1", "", &k.PublicKey)
	require.NoError(t, err)
	jwk.Use = "enc"
	fx.host.mu.Lock()
	fx.host.keys = append(fx.host.keys, jwk)
	fx.host.mu.Unlock()
	_, err = fx.authenticate(assertionFor(t, jwt.SigningMethodES256, "", k))
	assert.Error(t, err, "no kid")
	_, err = fx.authenticate(assertionFor(t, jwt.SigningMethodES256, "k1", k))
	assert.Error(t, err, "kid of the enc key")
}

// A sector_identifier_uri is fetched through the same guards as a jwks_uri,
// and must hold a JSON array of strings (OIDC Registration §5).
func TestClientJWKSFetcher_SectorRedirectURIs(t *testing.T) {
	ctx := context.Background()
	doc := `["https://a.example/cb","https://b.example/cb"]`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(doc)) }))
	defer srv.Close()
	f := &apiauth.ClientJWKSFetcher{AllowPrivateHosts: true, HTTPClient: srv.Client()}
	got, err := f.SectorRedirectURIs(ctx, srv.URL)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://a.example/cb", "https://b.example/cb"}, got)

	doc = `{"redirect_uris":["https://a.example/cb"]}`
	_, err = f.SectorRedirectURIs(ctx, srv.URL)
	assert.Error(t, err, "not an array")
	_, err = (&apiauth.ClientJWKSFetcher{}).SectorRedirectURIs(ctx, srv.URL)
	assert.ErrorContains(t, err, "private", "the dial guard applies")
}
