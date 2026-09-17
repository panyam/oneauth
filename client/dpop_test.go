package client_test

// Client-side DPoP tests (RFC 9449): the proofs this SDK mints, and the way
// it presents bound tokens. The round-trip cases run against the real
// apiauth validator rather than a hand-written parser, so a disagreement
// between the two halves of the library fails here.
//
// References:
//   - RFC 9449 §4.2 (https://www.rfc-editor.org/rfc/rfc9449#section-4.2) — proof syntax
//   - RFC 9449 §7.1 (https://www.rfc-editor.org/rfc/rfc9449#section-7.1) — presenting a bound token
//   - See: https://github.com/panyam/oneauth/issues/377

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/keys"
)

const (
	dpopClientID     = "dpop-sdk-client"
	dpopClientSecret = "dpop-sdk-secret"
	dpopJWTSecret    = "dpop-sdk-jwt-secret-32-chars!!!!"
	dpopIssuer       = "dpop-sdk-issuer"
)

// memStore is a minimal CredentialStore. The package's own mock lives in an
// internal test file, which this external test package cannot reach.
type memStore struct {
	creds map[string]*client.ServerCredential
}

func newMemStore() *memStore { return &memStore{creds: map[string]*client.ServerCredential{}} }

func (s *memStore) GetCredential(serverURL string) (*client.ServerCredential, error) {
	return s.creds[serverURL], nil
}
func (s *memStore) SetCredential(serverURL string, cred *client.ServerCredential) error {
	s.creds[serverURL] = cred
	return nil
}
func (s *memStore) RemoveCredential(serverURL string) error {
	delete(s.creds, serverURL)
	return nil
}
func (s *memStore) Save() error { return nil }
func (s *memStore) ListServers() ([]string, error) {
	servers := make([]string, 0, len(s.creds))
	for url := range s.creds {
		servers = append(servers, url)
	}
	return servers, nil
}

func newKey(t *testing.T) *client.DPoPKey {
	t.Helper()
	key, err := client.NewDPoPKey()
	require.NoError(t, err)
	return key
}

// claimsOf decodes a proof without verifying it. The signature is checked by
// the apiauth validator in the round-trip tests; here the question is which
// claims we emit.
func claimsOf(t *testing.T, proof string) (header, payload map[string]any) {
	t.Helper()
	parts := strings.Split(proof, ".")
	require.Len(t, parts, 3)
	decode := func(seg string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(seg)
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(raw, &m))
		return m
	}
	return decode(parts[0]), decode(parts[1])
}

func TestDPoPKey_ProofShape(t *testing.T) {
	key := newKey(t)

	proof, err := key.Proof(http.MethodPost, "https://as.example.com/api/token", "")
	require.NoError(t, err)

	header, payload := claimsOf(t, proof)
	assert.Equal(t, "dpop+jwt", header["typ"])
	assert.Equal(t, "ES256", header["alg"])
	jwk, ok := header["jwk"].(map[string]any)
	require.True(t, ok, "proof must carry the public key")
	assert.Equal(t, "EC", jwk["kty"])
	assert.Equal(t, "P-256", jwk["crv"])
	assert.Equal(t, http.MethodPost, payload["htm"])
	assert.Equal(t, "https://as.example.com/api/token", payload["htu"])
	assert.NotEmpty(t, payload["jti"])
	assert.NotEmpty(t, payload["iat"])
	assert.NotContains(t, payload, "ath", "a token-endpoint proof has no access token to bind to")
}

// A proof carrying private key material would hand the server the client's
// key, which is the opposite of proving possession of it.
func TestDPoPKey_ProofNeverCarriesPrivateMaterial(t *testing.T) {
	key := newKey(t)

	proof, err := key.Proof(http.MethodGet, "https://rs.example.com/data", "token")
	require.NoError(t, err)

	header, _ := claimsOf(t, proof)
	jwk := header["jwk"].(map[string]any)
	for _, private := range []string{"d", "k", "p", "q", "dp", "dq", "qi"} {
		assert.NotContains(t, jwk, private)
	}
}

func TestDPoPKey_ProofBindsToTheAccessToken(t *testing.T) {
	key := newKey(t)
	const token = "an-access-token"
	sum := sha256.Sum256([]byte(token))

	proof, err := key.Proof(http.MethodGet, "https://rs.example.com/data", token)
	require.NoError(t, err)

	_, payload := claimsOf(t, proof)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), payload["ath"])
}

// Each proof is good for one request. Repeating a jti is a replay and every
// conforming server rejects the second use.
func TestDPoPKey_EveryProofHasAFreshJTI(t *testing.T) {
	key := newKey(t)
	seen := map[string]bool{}

	for range 50 {
		proof, err := key.Proof(http.MethodGet, "https://rs.example.com/data", "")
		require.NoError(t, err)
		_, payload := claimsOf(t, proof)
		jti := payload["jti"].(string)
		require.False(t, seen[jti], "jti %q was reused", jti)
		seen[jti] = true
	}
}

// Query and fragment are excluded from the htu comparison (§4.3), and
// sending them would leak request parameters into a JWT that intermediaries
// can read.
func TestDPoPKey_HTUDropsQueryAndFragment(t *testing.T) {
	key := newKey(t)

	proof, err := key.Proof(http.MethodGet, "https://rs.example.com/data?token=secret#frag", "")
	require.NoError(t, err)

	_, payload := claimsOf(t, proof)
	assert.Equal(t, "https://rs.example.com/data", payload["htu"])
}

func TestDPoPKey_ThumbprintIsStableAndMatchesTheServer(t *testing.T) {
	key := newKey(t)

	first, second := key.Thumbprint(), key.Thumbprint()

	assert.Equal(t, first, second)
	assert.NotEmpty(t, first)
	// 256-bit base64url, no padding.
	assert.Len(t, first, 43)
}

func TestDPoPKey_RejectsNonP256Curves(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	_, err = client.NewDPoPKeyFromECDSA(p384)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "P-256")
}

// Checking the advertised algorithms up front turns "every request fails"
// into one legible configuration error.
func TestDPoPKey_SupportedBy(t *testing.T) {
	key := newKey(t)

	assert.NoError(t, key.SupportedBy(nil), "a server advertising nothing is not a refusal")
	assert.NoError(t, key.SupportedBy([]string{"RS256", "ES256"}))
	require.Error(t, key.SupportedBy([]string{"RS256", "PS256"}))
}

// --- round trip against the real server-side validator ---

// newDPoPServer builds an AS that issues bound tokens plus a resource
// endpoint that enforces the binding, both on one listener.
func newDPoPServer(t *testing.T) *httptest.Server {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	_, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID: dpopClientID, Key: []byte(dpopClientSecret), Algorithm: "HS256",
	}})
	require.NoError(t, err)

	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	base := "http://" + server.Listener.Addr().String()

	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:   ks,
		SigningKey: []byte(dpopJWTSecret),
		SigningAlg: "HS256",
		Issuer:     dpopIssuer,
		DPoP:       apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: base + "/api/token"}),
	})
	mw := &apiauth.APIMiddleware{
		JWTSecretKey: dpopJWTSecret,
		JWTIssuer:    dpopIssuer,
		DPoP:         apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{BaseURL: base}),
	}

	mux.Handle("POST /api/token", apiauth.NewTokenEndpointHandler(oa))
	mux.Handle("GET /data", mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"subject": apiauth.GetSubjectFromAPIContext(r.Context())})
	})))

	server.Start()
	t.Cleanup(server.Close)
	return server
}

// newDPoPClient points an AuthClient at the fixture's token endpoint. The
// client defaults to /auth/cli/token, which this server does not mount.
func newDPoPClient(t *testing.T, server *httptest.Server, store client.CredentialStore, opts ...client.ClientOption) *client.AuthClient {
	t.Helper()
	opts = append(opts, client.WithASMetadata(&client.ASMetadata{
		Issuer:        dpopIssuer,
		TokenEndpoint: server.URL + "/api/token",
	}))
	return client.NewAuthClient(server.URL, store, opts...)
}

// The proofs this SDK mints have to satisfy the validator the library ships.
// Testing them against a hand-written parser would only prove the tests agree
// with themselves.
func TestDPoPClient_TokenRequestGetsABoundToken(t *testing.T) {
	server := newDPoPServer(t)
	key := newKey(t)
	c := newDPoPClient(t, server, nil, client.WithDPoPKey(key))

	cred, err := c.ClientCredentialsToken(dpopClientID, dpopClientSecret, []string{"read"})

	require.NoError(t, err)
	require.NotEmpty(t, cred.AccessToken)
	_, payload := claimsOf(t, cred.AccessToken)
	cnf, ok := payload["cnf"].(map[string]any)
	require.True(t, ok, "issued token must be bound")
	assert.Equal(t, key.Thumbprint(), cnf["jkt"])
}

// Without a key the client keeps getting plain bearer tokens, which is what
// every existing caller does.
func TestDPoPClient_WithoutAKeyNothingChanges(t *testing.T) {
	server := newDPoPServer(t)
	c := newDPoPClient(t, server, nil)

	cred, err := c.ClientCredentialsToken(dpopClientID, dpopClientSecret, []string{"read"})

	require.NoError(t, err)
	_, payload := claimsOf(t, cred.AccessToken)
	assert.NotContains(t, payload, "cnf")
}

// The end-to-end point of the feature: a token obtained with a key is spent
// at a resource server that enforces the binding.
func TestDPoPClient_SpendsTheBoundTokenAtAResourceServer(t *testing.T) {
	server := newDPoPServer(t)
	key := newKey(t)
	store := newMemStore()
	c := newDPoPClient(t, server, store, client.WithDPoPKey(key))

	cred, err := c.ClientCredentialsToken(dpopClientID, dpopClientSecret, []string{"read"})
	require.NoError(t, err)
	// Assert the binding before spending it. Without this the test would
	// also pass against a client that silently obtained a plain bearer
	// token, since the resource server accepts those too.
	_, payload := claimsOf(t, cred.AccessToken)
	require.Contains(t, payload, "cnf")
	require.NoError(t, store.SetCredential(server.URL, cred))

	resp, err := c.HTTPClient().Get(server.URL + "/data")

	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// A bound token presented as Bearer is refused by the resource server
// (§7.2), so the client has to switch schemes on its own. This is the test
// that fails if `authorize` forgets the DPoP branch.
func TestDPoPClient_PresentsTheTokenUnderTheDPoPScheme(t *testing.T) {
	var scheme, proof string
	captured := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, _, _ = strings.Cut(r.Header.Get("Authorization"), " ")
		proof = r.Header.Get("DPoP")
	}))
	defer captured.Close()

	key := newKey(t)
	store := newMemStore()
	c := client.NewAuthClient(captured.URL, store, client.WithDPoPKey(key))
	require.NoError(t, store.SetCredential(captured.URL, &client.ServerCredential{
		AccessToken: "bound-token",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))

	resp, err := c.HTTPClient().Get(captured.URL + "/data")
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, "DPoP", scheme)
	require.NotEmpty(t, proof, "a DPoP-scheme request must carry a proof")
	_, payload := claimsOf(t, proof)
	sum := sha256.Sum256([]byte("bound-token"))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), payload["ath"],
		"the proof must be bound to the token it accompanies")
}
