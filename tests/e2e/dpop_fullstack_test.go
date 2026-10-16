package e2e_test

// End-to-end coverage for the issue 88 DPoP slice and the refresh-grant
// client check from issue 395, against one in-process AS that wires every
// piece together: DCR into an AppStore, PAR and /authorize through
// MountAuthorize sharing the token endpoint's DPoP validator, a refresh
// store, an optional nonce policy, and a DPoP-protecting resource server.
// The unit tests cover each piece on its own; these cover the wiring, and
// drive the SDK where it has a part to play.
//
// References:
//   - RFC 9449 §5.2, §8, §10.1 (https://www.rfc-editor.org/rfc/rfc9449)
//   - RFC 9126 (https://www.rfc-editor.org/rfc/rfc9126)
//   - RFC 6749 §6 (https://www.rfc-editor.org/rfc/rfc6749#section-6)
//   - See: https://github.com/panyam/oneauth/issues/88
//   - See: https://github.com/panyam/oneauth/issues/395

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/stores/fs"
	"github.com/panyam/oneauth/utils"
)

const (
	fullStackJWTSecret = "fullstack-e2e-jwt-secret-32chars"
	fullStackIssuer    = "oneauth-fullstack-e2e"
	fullStackUser      = "alice@example.com"
	fullStackPassword  = "correct horse"
	fullStackRedirect  = "https://app.example/cb"
	fullStackVerifier  = "fullstack-e2e-verifier-0123456789abcdef0123456789"
)

type fullStackEnv struct {
	*dpopE2EEnv // reused for proof minting; its server is the one below

	tokenURL string
	parURL   string
	browser  *http.Client // does not follow redirects

	// nonceChallenges counts use_dpop_nonce answers from the token endpoint.
	nonceChallenges atomic.Int32
}

type fullStackOpts struct {
	requireNonce bool
}

func newFullStackEnv(t *testing.T, opts fullStackOpts) *fullStackEnv {
	t.Helper()
	keyStore := keys.NewInMemoryKeyStore()
	appStore := core.NewInMemoryAppStore()
	refreshStore := newE2ERefreshStore(t)
	registrar := admin.NewAppRegistrarWithStore(keyStore, admin.NewNoAuth(), appStore)

	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	base := "http://" + server.Listener.Addr().String()

	dpopCfg := apiauth.DPoPConfig{EndpointURL: base + "/api/token"}
	if opts.requireNonce {
		dpopCfg.NonceSource = apiauth.NewNonceSource(apiauth.NonceConfig{})
		dpopCfg.NoncePolicy = func(*http.Request) bool { return true }
	}
	validator := apiauth.NewDPoPProofValidator(dpopCfg)

	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:               keyStore,
		AppStore:               appStore,
		SigningKey:             []byte(fullStackJWTSecret),
		SigningAlg:             "HS256",
		Issuer:                 fullStackIssuer,
		RefreshStore:           refreshStore,
		AuthorizationCodeStore: core.NewInMemoryAuthorizationCodeStore(),
		DPoP:                   validator,
	})
	oa.PasswordGranter = apiauth.NewPasswordGranter(apiauth.PasswordGranterConfig{
		Issuer: oa.Issuer,
		ValidateCredentials: func(username, password, _ string) (accounts.User, error) {
			if username != fullStackUser || password != fullStackPassword {
				return nil, errors.New("invalid credentials")
			}
			return &accounts.BasicUser{ID: "alice"}, nil
		},
	})

	env := &fullStackEnv{tokenURL: base + "/api/token", parURL: base + "/par"}
	tokenHandler := apiauth.NewTokenEndpointHandler(oa)
	mux.Handle("POST /api/token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		tokenHandler.ServeHTTP(rec, r)
		if rec.status == http.StatusBadRequest && w.Header().Get(apiauth.DPoPNonceHeader) != "" {
			env.nonceChallenges.Add(1)
		}
	}))
	mux.Handle("/apps/", registrar.Handler())
	mux.Handle("/apps/dcr", registrar.Handler())
	apiauth.MountAuthorize(mux, apiauth.AuthorizeMountConfig{
		OneAuth:              oa,
		IssuerURL:            fullStackIssuer,
		PushedStore:          core.NewInMemoryPushedAuthorizationRequestStore(),
		SubjectFromRequest:   func(r *http.Request) string { return "" },
		CSRFTokenFromRequest: func(r *http.Request) string { return "" },
		AutoApproveSubject:   "alice",
	})
	resourceMW := &apiauth.APIMiddleware{
		JWTSecretKey: fullStackJWTSecret,
		JWTIssuer:    fullStackIssuer,
		DPoP:         apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{BaseURL: base}),
	}
	mux.Handle("GET /protected", resourceMW.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, apiauth.GetSubjectFromAPIContext(r.Context()))
	})))

	server.Start()
	t.Cleanup(server.Close)

	inner := newDPoPE2EEnvKeyOnly(t)
	inner.server = server
	inner.oa = oa
	inner.refreshStore = refreshStore
	env.dpopE2EEnv = inner
	env.browser = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return env
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (e *fullStackEnv) register(t *testing.T, req client.ClientRegistrationRequest) *client.ClientRegistrationResponse {
	t.Helper()
	if req.ClientName == "" {
		req.ClientName = "fullstack-e2e"
	}
	if req.RedirectURIs == nil {
		req.RedirectURIs = []string{fullStackRedirect}
	}
	resp, err := client.RegisterClient(e.server.URL+"/apps/dcr", req, nil)
	require.NoError(t, err)
	return resp
}

// send posts a form, attaching proof as the DPoP header when non-empty.
func (e *fullStackEnv) send(t *testing.T, target string, form url.Values, proof string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode, decodeBody(t, resp.Body)
}

// codeFor follows /authorize with only client_id + request_uri, as a
// browser carrying a PAR reference would, and returns the code.
func (e *fullStackEnv) codeFor(t *testing.T, clientID, requestURI string) string {
	t.Helper()
	resp, err := e.browser.Get(e.server.URL + "/authorize?" + url.Values{
		"client_id": {clientID}, "request_uri": {requestURI},
	}.Encode())
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code, loc.String())
	return code
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (e *fullStackEnv) jkt(t *testing.T) string {
	t.Helper()
	jkt, err := utils.ComputeKid(&e.clientKey.PublicKey, "ES256")
	require.NoError(t, err)
	return jkt
}

// sdkKey hands the SDK the same key the raw proofs use, so a test can
// compare thumbprints.
func (e *fullStackEnv) sdkKey(t *testing.T) *client.DPoPKey {
	t.Helper()
	k, err := client.NewDPoPKeyFromECDSA(e.clientKey)
	require.NoError(t, err)
	return k
}

// A client that registers dpop_bound_access_tokens through DCR is held to
// it at the token endpoint: no proof, no token. With the SDK holding a key
// it gets a DPoP token, and the resource server accepts it.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-5.2
func TestFullStack_DCRRegisteredDPoPBoundClient(t *testing.T) {
	env := newFullStackEnv(t, fullStackOpts{})
	reg := env.register(t, client.ClientRegistrationRequest{
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
		DPoPBoundAccessTokens:   true,
	})
	require.True(t, reg.DPoPBoundAccessTokens, "the registration response echoes the setting")

	bearer := client.NewAuthClient(env.server.URL, nil, client.WithTokenEndpoint("/api/token"))
	_, err := bearer.ClientCredentials(context.Background(), &client.ClientCredentialsRequest{
		ClientID: reg.ClientID, ClientSecret: reg.ClientSecret,
	})
	var te *client.TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_dpop_proof", te.Code)

	store := &memCredentialStore{creds: map[string]*client.ServerCredential{}}
	bound := client.NewAuthClient(env.server.URL, store, client.WithTokenEndpoint("/api/token"), client.WithDPoPKey(env.sdkKey(t)))
	cred, err := bound.ClientCredentials(context.Background(), &client.ClientCredentialsRequest{
		ClientID: reg.ClientID, ClientSecret: reg.ClientSecret,
	})
	require.NoError(t, err)
	assert.Equal(t, "DPoP", cred.TokenType)
	assertBound(t, cred.AccessToken, env.jkt(t))

	resp, err := bound.HTTPClient().Get(env.server.URL + "/protected")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// /par checks a proof against its own URL, sharing the token endpoint's
// validator through MountAuthorize, and the code it leads to is bound to
// the pushing key.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-10.1
func TestFullStack_PARWithDPoP(t *testing.T) {
	env := newFullStackEnv(t, fullStackOpts{})
	reg := env.register(t, client.ClientRegistrationRequest{
		GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none",
	})
	push := url.Values{
		"client_id": {reg.ClientID}, "response_type": {"code"}, "redirect_uri": {fullStackRedirect},
		"code_challenge": {s256(fullStackVerifier)}, "code_challenge_method": {"S256"}, "scope": {"read"},
	}

	t.Run("a proof made for the token endpoint is refused at /par", func(t *testing.T) {
		code, body := env.send(t, env.parURL, push, env.proof(http.MethodPost, env.tokenURL))
		assert.Equal(t, http.StatusBadRequest, code)
		assert.Equal(t, "invalid_dpop_proof", body["error"])
	})

	redeem := func(code string) url.Values {
		return url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {fullStackVerifier},
			"redirect_uri": {fullStackRedirect}, "client_id": {reg.ClientID},
		}
	}
	pushed := func(t *testing.T) string {
		status, body := env.send(t, env.parURL, push, env.proof(http.MethodPost, env.parURL))
		require.Equal(t, http.StatusCreated, status, body)
		return env.codeFor(t, reg.ClientID, body["request_uri"].(string))
	}

	t.Run("the code needs the pushing key", func(t *testing.T) {
		status, body := env.send(t, env.tokenURL, redeem(pushed(t)), "")
		assert.Equal(t, "invalid_grant", body["error"], status)
	})
	t.Run("redeemed with the key, the token is bound to it", func(t *testing.T) {
		status, body := env.send(t, env.tokenURL, redeem(pushed(t)), env.proof(http.MethodPost, env.tokenURL))
		require.Equal(t, http.StatusOK, status, body)
		assert.Equal(t, "DPoP", body["token_type"])
		assertBound(t, body["access_token"].(string), env.jkt(t))
	})
}

// LoginWithBrowser with a DPoP key sends dpop_jkt on the authorize URL,
// which binds the code, so the code exchange has to carry a proof too.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-10
func TestFullStack_BrowserLoginWithDPoP(t *testing.T) {
	env := newFullStackEnv(t, fullStackOpts{})
	reg := env.register(t, client.ClientRegistrationRequest{
		RedirectURIs: []string{"http://localhost:1/callback"},
		GrantTypes:   []string{"authorization_code"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none",
	})
	c := client.NewAuthClient(env.server.URL, nil, client.WithDPoPKey(env.sdkKey(t)))

	cred, err := c.LoginWithBrowser(context.Background(), &client.BrowserLoginRequest{
		AuthorizationEndpoint: env.server.URL + "/authorize",
		TokenEndpoint:         env.tokenURL,
		ClientID:              reg.ClientID,
		Timeout:               5 * time.Second,
		OpenBrowser:           client.FollowRedirects(nil),
	})
	require.NoError(t, err)
	assertBound(t, cred.AccessToken, env.jkt(t))
}

// A confidential client's refresh token needs the client's credentials, and
// the SDK's RefreshToken sends them.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-6
func TestFullStack_ConfidentialClientRefresh(t *testing.T) {
	env := newFullStackEnv(t, fullStackOpts{})
	reg := env.register(t, client.ClientRegistrationRequest{
		RedirectURIs:            []string{"http://localhost:1/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	c := client.NewAuthClient(env.server.URL, nil, client.WithASMetadata(&client.ASMetadata{TokenEndpoint: env.tokenURL}))
	cred, err := c.LoginWithBrowser(context.Background(), &client.BrowserLoginRequest{
		AuthorizationEndpoint: env.server.URL + "/authorize",
		TokenEndpoint:         env.tokenURL,
		ClientID:              reg.ClientID,
		ClientSecret:          reg.ClientSecret,
		Timeout:               5 * time.Second,
		OpenBrowser:           client.FollowRedirects(nil),
	})
	require.NoError(t, err)
	require.NotEmpty(t, cred.RefreshToken)

	_, err = c.RefreshToken(context.Background(), &client.RefreshTokenRequest{
		ClientID: reg.ClientID, RefreshToken: cred.RefreshToken,
	})
	var te *client.TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_client", te.Code)

	_, err = c.RefreshToken(context.Background(), &client.RefreshTokenRequest{
		ClientID: reg.ClientID, ClientSecret: "not-the-secret", RefreshToken: cred.RefreshToken,
	})
	require.ErrorAs(t, err, &te)
	assert.Equal(t, "invalid_client", te.Code)

	refreshed, err := c.RefreshToken(context.Background(), &client.RefreshTokenRequest{
		ClientID: reg.ClientID, ClientSecret: reg.ClientSecret, RefreshToken: cred.RefreshToken,
	})
	require.NoError(t, err, "the refused attempts must not have burned the token")
	assert.NotEqual(t, cred.RefreshToken, refreshed.RefreshToken)
}

// The SDK's automatic refresh redeems its own bound refresh token, and the
// binding carries forward.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-5
func TestFullStack_SDKAutoRefreshKeepsTheBinding(t *testing.T) {
	env := newFullStackEnv(t, fullStackOpts{})
	store := &memCredentialStore{creds: map[string]*client.ServerCredential{}}
	c := client.NewAuthClient(env.server.URL, store, client.WithTokenEndpoint("/api/token"), client.WithDPoPKey(env.sdkKey(t)))

	cred, err := c.Login(context.Background(), &client.LoginRequest{Username: fullStackUser, Password: fullStackPassword})
	require.NoError(t, err)
	assertBound(t, cred.AccessToken, env.jkt(t))

	cred.ExpiresAt = time.Now().Add(-time.Minute)
	require.NoError(t, store.SetCredential(env.server.URL, cred))

	token, err := c.GetToken()
	require.NoError(t, err)
	require.NotEmpty(t, token)
	assert.NotEqual(t, cred.AccessToken, token)
	assertBound(t, token, env.jkt(t))

	refreshed, err := store.GetCredential(env.server.URL)
	require.NoError(t, err)
	rt, err := env.refreshStore.GetRefreshToken(context.Background(), &core.GetRefreshTokenRequest{Token: refreshed.RefreshToken})
	require.NoError(t, err)
	require.NotNil(t, rt.Token.Confirmation)
	assert.Equal(t, env.jkt(t), rt.Token.Confirmation.JKT)
}

// With an AS that demands nonces, the SDK answers the first challenge and
// then reuses the nonce, so a second request isn't challenged again.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-8
func TestFullStack_SDKFollowsTheNonceProtocol(t *testing.T) {
	env := newFullStackEnv(t, fullStackOpts{requireNonce: true})
	reg := env.register(t, client.ClientRegistrationRequest{
		GrantTypes: []string{"client_credentials"}, TokenEndpointAuthMethod: "client_secret_basic",
	})
	c := client.NewAuthClient(env.server.URL, nil, client.WithTokenEndpoint("/api/token"), client.WithDPoPKey(env.sdkKey(t)))

	for i := 0; i < 2; i++ {
		cred, err := c.ClientCredentials(context.Background(), &client.ClientCredentialsRequest{
			ClientID: reg.ClientID, ClientSecret: reg.ClientSecret,
		})
		require.NoError(t, err, "request %d", i+1)
		assert.Equal(t, "DPoP", cred.TokenType)
	}
	assert.Equal(t, int32(1), env.nonceChallenges.Load(), "only the first request should be challenged")
}

func assertBound(t *testing.T, accessToken, jkt string) {
	t.Helper()
	cnf, ok := dpopClaims(t, accessToken)["cnf"].(map[string]any)
	require.True(t, ok, "access token carries no cnf claim")
	assert.Equal(t, jkt, cnf["jkt"])
}

func newE2ERefreshStore(t *testing.T) core.RefreshTokenStore {
	return fs.NewFSRefreshTokenStore(t.TempDir())
}

// newDPoPE2EEnvKeyOnly gives a dpopE2EEnv just a client key, for its proof
// helpers; the caller fills in the server.
func newDPoPE2EEnvKeyOnly(t *testing.T) *dpopE2EEnv {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &dpopE2EEnv{t: t, clientKey: key}
}

func decodeBody(t *testing.T, r io.Reader) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(r)
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body), string(raw))
	return body
}
