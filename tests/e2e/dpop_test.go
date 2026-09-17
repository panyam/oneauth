package e2e_test

// End-to-end RFC 9449 (DPoP) issuance test against an in-process oneauth AS.
// Drives a real HTTP client that mints its own proof per request, so the
// header value, the form encoding and the `htu` the server derives are all
// exercised the way a deployed client would exercise them:
//
//	POST /api/token   grant_type=client_credentials + DPoP header
//	POST /api/token   grant_type=refresh_token      + DPoP header
//	GET  /.well-known/openid-configuration          — dpop_signing_alg_values_supported
//
//	GET  /protected                                 — DPoP-bound token at the resource server
//
// The resource-server leg closes the loop: the same in-process AS issues a
// bound token and the middleware then accepts it only when the client proves
// the key again, and refuses the Bearer downgrade.
//
// Why a hand-rolled fixture instead of TestEnv: DPoP's htu check needs the
// server's external URL at construction time, so the AS is built around
// httptest.NewUnstartedServer — read server.URL, wire the validator, then
// Start. Same pattern as device_flow_test.go.
//
// References:
//   - RFC 9449 §5 (https://www.rfc-editor.org/rfc/rfc9449#section-5)
//   - See: https://github.com/panyam/oneauth/issues/336

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/stores/fs"
	"github.com/panyam/oneauth/utils"
)

const (
	dpopE2EJWTSecret   = "dpop-e2e-jwt-secret-32chars!!!!!"
	dpopE2EIssuer      = "oneauth-dpop-e2e"
	dpopE2EClientID    = "dpop-e2e-client"
	dpopE2EClientToken = "dpop-e2e-client-secret"
)

// dpopE2EEnv is one in-process AS plus the client-side key that stands in
// for a public client's per-installation DPoP key.
type dpopE2EEnv struct {
	t            *testing.T
	server       *httptest.Server
	oa           *apiauth.OneAuth
	clientKey    *ecdsa.PrivateKey
	refreshStore core.RefreshTokenStore
}

func newDPoPE2EEnv(t *testing.T) *dpopE2EEnv {
	t.Helper()

	keyStore := keys.NewInMemoryKeyStore()
	_, err := keyStore.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID:  dpopE2EClientID,
		Key:       []byte(dpopE2EClientToken),
		Algorithm: "HS256",
	}})
	require.NoError(t, err)

	refreshStore := fs.NewFSRefreshTokenStore(t.TempDir())

	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)

	// The proof's htu names the URL the client posts to, which does not
	// exist until httptest allocates a port — hence Unstarted.
	tokenEndpointURL := "http://" + server.Listener.Addr().String() + "/api/token"
	validator := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: tokenEndpointURL})

	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:     keyStore,
		SigningKey:   []byte(dpopE2EJWTSecret),
		SigningAlg:   "HS256",
		Issuer:       dpopE2EIssuer,
		RefreshStore: refreshStore,
		DPoP:         validator,
	})

	mux.Handle("POST /api/token", apiauth.NewTokenEndpointHandler(oa))

	// The resource server shares this process, so its base URL is the same
	// listener the token endpoint answers on.
	resourceMW := &apiauth.APIMiddleware{
		JWTSecretKey: dpopE2EJWTSecret,
		JWTIssuer:    dpopE2EIssuer,
		DPoP: apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{
			BaseURL: "http://" + server.Listener.Addr().String(),
		}),
	}
	mux.Handle("GET /protected", resourceMW.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"subject": apiauth.GetSubjectFromAPIContext(r.Context())})
	})))
	apiauth.MountASMetadata(mux, &apiauth.ASServerMetadata{
		Issuer:                        dpopE2EIssuer,
		TokenEndpoint:                 tokenEndpointURL,
		DPoPSigningAlgValuesSupported: validator.SigningAlgValuesSupported(),
	})

	server.Start()
	t.Cleanup(server.Close)

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &dpopE2EEnv{t: t, server: server, oa: oa, clientKey: clientKey, refreshStore: refreshStore}
}

// proof mints a fresh proof for one request, the way a client library would:
// new jti every call, htm/htu naming this exact request.
func (e *dpopE2EEnv) proof(method, targetURL string) string {
	return e.proofWithATH(method, targetURL, "")
}

// proofWithATH is proof plus the RFC 9449 §4.2 `ath` binding it to one
// access token, which resource-server requests require and token requests
// have no token for.
func (e *dpopE2EEnv) proofWithATH(method, targetURL, accessToken string) string {
	e.t.Helper()
	jti := make([]byte, 16)
	_, err := rand.Read(jti)
	require.NoError(e.t, err)

	claims := jwt.MapClaims{
		"jti": base64.RawURLEncoding.EncodeToString(jti),
		"htm": method,
		"htu": targetURL,
		"iat": time.Now().Unix(),
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkHeaderFor(e.t, &e.clientKey.PublicKey)
	signed, err := token.SignedString(e.clientKey)
	require.NoError(e.t, err)
	return signed
}

// jwkHeaderFor renders a public key as the proof's `jwk` header. It goes
// through utils rather than reading X/Y directly: those coordinates are
// big.Ints, so Bytes() drops a leading zero byte and produces a short — and
// therefore invalid — JWK coordinate roughly one key in 256.
func jwkHeaderFor(t *testing.T, pub *ecdsa.PublicKey) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(utils.ECDSAPublicKeyToJWK("", "ES256", pub))
	require.NoError(t, err)
	var members map[string]any
	require.NoError(t, json.Unmarshal(encoded, &members))
	return members
}

// postToken sends a form-encoded token request, attaching a proof when
// withProof is set.
func (e *dpopE2EEnv) postToken(form url.Values, withProof bool) (int, map[string]any) {
	e.t.Helper()
	target := e.server.URL + "/api/token"
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	require.NoError(e.t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if withProof {
		req.Header.Set("DPoP", e.proof(http.MethodPost, target))
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(e.t, err)
	var body map[string]any
	require.NoError(e.t, json.Unmarshal(raw, &body), string(raw))
	return resp.StatusCode, body
}

func dpopClaims(t *testing.T, accessToken string) map[string]any {
	t.Helper()
	parts := strings.Split(accessToken, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

// TestDPoP_E2E_ClientCredentialsIssuesBoundToken drives the arc a client
// library drives: mint a proof, post it, read the bound token back.
func TestDPoP_E2E_ClientCredentialsIssuesBoundToken(t *testing.T) {
	env := newDPoPE2EEnv(t)

	status, body := env.postToken(url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {dpopE2EClientID},
		"client_secret": {dpopE2EClientToken},
		"scope":         {"read"},
	}, true)

	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "DPoP", body["token_type"])
	cnf, ok := dpopClaims(t, body["access_token"].(string))["cnf"].(map[string]any)
	require.True(t, ok, "issued token must carry cnf")
	assert.NotEmpty(t, cnf["jkt"])
}

// The same AS keeps serving clients that send no proof, which is what makes
// DPoP adoptable one client at a time.
func TestDPoP_E2E_BearerClientsAreUnaffected(t *testing.T) {
	env := newDPoPE2EEnv(t)

	status, body := env.postToken(url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {dpopE2EClientID},
		"client_secret": {dpopE2EClientToken},
	}, false)

	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "Bearer", body["token_type"])
	assert.NotContains(t, dpopClaims(t, body["access_token"].(string)), "cnf")
}

// The refresh token persists through a real store (FS, not a test double),
// so this covers the binding surviving serialization and rotation.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-5
func TestDPoP_E2E_RefreshTokenBindingSurvivesTheStore(t *testing.T) {
	env := newDPoPE2EEnv(t)
	jkt := requireJKT(t, env)

	created, err := env.refreshStore.CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{
		Subject:      "e2e-user",
		ClientID:     dpopE2EClientID,
		Scopes:       []string{"read"},
		Confirmation: &core.Confirmation{JKT: jkt},
	})
	require.NoError(t, err)

	status, body := env.postToken(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {created.Token.Token},
	}, true)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "DPoP", body["token_type"])

	rotated, err := env.refreshStore.GetRefreshToken(context.Background(), &core.GetRefreshTokenRequest{
		Token: body["refresh_token"].(string),
	})
	require.NoError(t, err)
	require.NotNil(t, rotated.Token.Confirmation)
	assert.Equal(t, jkt, rotated.Token.Confirmation.JKT, "rotation must carry the binding forward")

	// Same refresh token, no proof: the binding is what makes a stolen
	// refresh token worthless on its own.
	status, body = env.postToken(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rotated.Token.Token},
	}, false)
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_grant", body["error"])
}

// A client discovers DPoP support from AS metadata, so the advertised
// algorithms have to match what the validator actually accepts.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-5.1
func TestDPoP_E2E_MetadataAdvertisesSigningAlgs(t *testing.T) {
	env := newDPoPE2EEnv(t)

	resp, err := http.Get(env.server.URL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()
	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	algs, ok := meta["dpop_signing_alg_values_supported"].([]any)
	require.True(t, ok, "metadata must advertise dpop_signing_alg_values_supported")
	assert.Contains(t, algs, "ES256")
}

// requireJKT asks the AS for a bound token and reads the thumbprint back out
// of it, which is how a test learns the client key's jkt without
// reimplementing RFC 7638.
func requireJKT(t *testing.T, env *dpopE2EEnv) string {
	t.Helper()
	status, body := env.postToken(url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {dpopE2EClientID},
		"client_secret": {dpopE2EClientToken},
	}, true)
	require.Equal(t, http.StatusOK, status, body)
	cnf := dpopClaims(t, body["access_token"].(string))["cnf"].(map[string]any)
	return cnf["jkt"].(string)
}

// getProtected calls the resource server with the given scheme, attaching a
// proof for this exact request when withProof is set.
func (e *dpopE2EEnv) getProtected(scheme, token string, withProof bool) (int, string) {
	e.t.Helper()
	target := e.server.URL + "/protected"
	req, err := http.NewRequest(http.MethodGet, target, nil)
	require.NoError(e.t, err)
	req.Header.Set("Authorization", scheme+" "+token)
	if withProof {
		req.Header.Set("DPoP", e.proofWithATH(http.MethodGet, target, token))
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(e.t, err)
	return resp.StatusCode, string(body)
}

// TestDPoP_E2E_BoundTokenRoundTrip drives the arc both halves of #336 exist
// for: get a bound token from the AS, spend it at the resource server, and
// watch the same token fail when the proof is dropped.
func TestDPoP_E2E_BoundTokenRoundTrip(t *testing.T) {
	env := newDPoPE2EEnv(t)

	status, body := env.postToken(url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {dpopE2EClientID},
		"client_secret": {dpopE2EClientToken},
		"scope":         {"read"},
	}, true)
	require.Equal(t, http.StatusOK, status, body)
	require.Equal(t, "DPoP", body["token_type"])
	token := body["access_token"].(string)

	status, page := env.getProtected("DPoP", token, true)
	require.Equal(t, http.StatusOK, status, page)
	assert.Contains(t, page, dpopE2EClientID)

	// Same token, no proof, Bearer scheme: the downgrade RFC 9449 §7.2
	// closes. Without this the binding would protect nothing.
	status, _ = env.getProtected("Bearer", token, false)
	assert.Equal(t, http.StatusUnauthorized, status)

	// Same token under the right scheme but with no proof at all.
	status, _ = env.getProtected("DPoP", token, false)
	assert.Equal(t, http.StatusUnauthorized, status)
}

// An unbound token keeps working as a bearer token against the same resource
// server, which is what lets a fleet adopt DPoP one client at a time.
func TestDPoP_E2E_BearerTokenStillReachesTheResource(t *testing.T) {
	env := newDPoPE2EEnv(t)

	status, body := env.postToken(url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {dpopE2EClientID},
		"client_secret": {dpopE2EClientToken},
	}, false)
	require.Equal(t, http.StatusOK, status, body)

	status, page := env.getProtected("Bearer", body["access_token"].(string), false)

	require.Equal(t, http.StatusOK, status, page)
}
