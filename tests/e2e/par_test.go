package e2e_test

// End-to-end RFC 9126 test against an in-process oneauth AS. Drives the
// whole arc a PAR-using client drives, over real HTTP:
//
//	POST /par        — push the authorization request, get a request_uri
//	GET  /authorize  — redirect carrying only client_id + request_uri
//	POST /api/token  — redeem the code
//
// The unit tests exercise the handlers directly; this one proves /par is
// actually mounted and that a browser redirect carrying nothing but a
// reference still produces a working code.
//
// References:
//   - RFC 9126 (https://www.rfc-editor.org/rfc/rfc9126)
//   - See: https://github.com/panyam/oneauth/issues/337

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

const (
	parE2EClientID  = "par-e2e-client"
	parE2ESecret    = "par-e2e-secret"
	parE2EJWTSecret = "par-e2e-jwt-secret-32-chars!!!!!"
	parE2EIssuer    = "oneauth-par-e2e"
	parE2ERedirect  = "https://app.example/cb"
	parE2EVerifier  = "par-e2e-verifier-0123456789abcdef0123456789"
)

type parE2EEnv struct {
	t      *testing.T
	server *httptest.Server
	client *http.Client
}

func newPARE2EEnv(t *testing.T) *parE2EEnv {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	_, err := ks.PutKey(t.Context(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID: parE2EClientID, Key: []byte(parE2ESecret), Algorithm: "HS256",
	}})
	require.NoError(t, err)

	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:               ks,
		SigningKey:             []byte(parE2EJWTSecret),
		SigningAlg:             "HS256",
		Issuer:                 parE2EIssuer,
		AuthorizationCodeStore: core.NewInMemoryAuthorizationCodeStore(),
	})

	mux := http.NewServeMux()
	mux.Handle("POST /api/token", apiauth.NewTokenEndpointHandler(oa))
	apiauth.MountAuthorize(mux, apiauth.AuthorizeMountConfig{
		OneAuth:              oa,
		IssuerURL:            parE2EIssuer,
		PushedStore:          core.NewInMemoryPushedAuthorizationRequestStore(),
		SubjectFromRequest:   func(r *http.Request) string { return "" },
		CSRFTokenFromRequest: func(r *http.Request) string { return "" },
		AutoApproveSubject:   "par-e2e-user",
		RedirectURIValidator: func(ctx context.Context, clientID, redirectURI string) error { return nil },
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &parE2EEnv{
		t:      t,
		server: server,
		// The authorization response is a redirect to an external URL;
		// following it would leave the test asserting against
		// app.example rather than against our Location header.
		client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
}

func (e *parE2EEnv) push(form url.Values) (int, map[string]any) {
	e.t.Helper()
	resp, err := e.client.Post(e.server.URL+"/par", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(e.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(e.t, err)
	var body map[string]any
	require.NoError(e.t, json.Unmarshal(raw, &body), string(raw))
	return resp.StatusCode, body
}

// authorize follows the browser leg and returns the redirect Location.
func (e *parE2EEnv) authorize(query url.Values) (int, string) {
	e.t.Helper()
	resp, err := e.client.Get(e.server.URL + "/authorize?" + query.Encode())
	require.NoError(e.t, err)
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header.Get("Location")
}

func TestPAR_E2E_PushAuthorizeRedeem(t *testing.T) {
	env := newPARE2EEnv(t)

	status, pushed := env.push(url.Values{
		"client_id":             {parE2EClientID},
		"client_secret":         {parE2ESecret},
		"response_type":         {"code"},
		"redirect_uri":          {parE2ERedirect},
		"scope":                 {"read"},
		"code_challenge":        {core.ComputeCodeChallenge(parE2EVerifier)},
		"code_challenge_method": {core.CodeChallengeMethodS256},
		"state":                 {"e2e-state"},
	})
	require.Equal(t, http.StatusCreated, status, pushed)
	requestURI, _ := pushed["request_uri"].(string)
	require.NotEmpty(t, requestURI)

	// The browser leg carries only the reference and the client_id, which
	// is the leak reduction PAR is for: no scope, no redirect_uri, no
	// PKCE challenge in the URL or in browser history.
	status, location := env.authorize(url.Values{
		"client_id":   {parE2EClientID},
		"request_uri": {requestURI},
	})
	require.Equal(t, http.StatusFound, status)
	redirect, err := url.Parse(location)
	require.NoError(t, err)
	code := redirect.Query().Get("code")
	require.NotEmpty(t, code, "authorization response should carry a code, got %s", location)
	assert.Equal(t, "e2e-state", redirect.Query().Get("state"), "state pushed to /par must come back on the redirect")

	resp, err := env.client.PostForm(env.server.URL+"/api/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {parE2EVerifier},
		"redirect_uri":  {parE2ERedirect},
		"client_id":     {parE2EClientID},
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	var tokens map[string]any
	require.NoError(t, json.Unmarshal(raw, &tokens))
	assert.NotEmpty(t, tokens["access_token"])
}

// A reference is good for one code. The second authorization with the same
// request_uri gets nothing, which is what stops a captured redirect URL
// from being replayed.
func TestPAR_E2E_RequestURIIsSpentByTheFirstCode(t *testing.T) {
	env := newPARE2EEnv(t)

	_, pushed := env.push(url.Values{
		"client_id":             {parE2EClientID},
		"client_secret":         {parE2ESecret},
		"response_type":         {"code"},
		"redirect_uri":          {parE2ERedirect},
		"scope":                 {"read"},
		"code_challenge":        {core.ComputeCodeChallenge(parE2EVerifier)},
		"code_challenge_method": {core.CodeChallengeMethodS256},
	})
	requestURI := pushed["request_uri"].(string)
	query := url.Values{"client_id": {parE2EClientID}, "request_uri": {requestURI}}

	status, location := env.authorize(query)
	require.Equal(t, http.StatusFound, status)
	require.Contains(t, location, "code=")

	status, location = env.authorize(query)

	assert.NotEqual(t, http.StatusFound, status,
		"a spent request_uri must not produce a second code, got a redirect to %s", location)
}
