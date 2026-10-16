package apiauth_test

// The token endpoint's input handling, issue 88's "Input Validation" walk:
// a registered client gets only the scopes and RAR types it registered,
// errors carry the RFC 6749 §5.2 status and code without internal detail,
// and request bodies are bounded.
//
// References:
//   - RFC 6749 §3.3, §5.2 (https://www.rfc-editor.org/rfc/rfc6749#section-5.2)
//   - RFC 9396 §5 (https://www.rfc-editor.org/rfc/rfc9396#section-5)
//   - CWE-209 (https://cwe.mitre.org/data/definitions/209.html)
//   - CWE-770 (https://cwe.mitre.org/data/definitions/770.html)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

const (
	policyClient = "policy-client"
	policySecret = "policy-client-secret-32-bytes-ok"
	openClient   = "open-client"
	openSecret   = "open-client-secret-32-bytes-ok!!"
)

func newPolicyEndpoint(t *testing.T) http.Handler {
	t.Helper()
	ctx := context.Background()
	ks := keys.NewInMemoryKeyStore()
	apps := core.NewInMemoryAppStore()
	for id, secret := range map[string]string{policyClient: policySecret, openClient: openSecret} {
		_, err := ks.PutKey(ctx, &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: id, Key: []byte(secret), Algorithm: "HS256"}})
		require.NoError(t, err)
	}
	_, err := apps.SaveApp(ctx, &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID: policyClient, Scope: "read write", AuthorizationDetailsTypes: []string{"payment_initiation"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}})
	require.NoError(t, err)
	_, err = apps.SaveApp(ctx, &core.SaveAppRequest{App: &core.AppRegistration{ClientID: openClient, TokenEndpointAuthMethod: "client_secret_basic"}})
	require.NoError(t, err)

	validate := func(username, password, _ string) (accounts.User, error) {
		if username == "alice" && password == "right" {
			return &accounts.BasicUser{ID: "alice"}, nil
		}
		return nil, errors.New("bad credentials")
	}
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore: ks, AppStore: apps,
		SigningKey: []byte("policy-as-signing-key-32-bytes!!"), SigningAlg: "HS256", Issuer: "as",
		ValidateCredentials: validate,
		GetSubjectScopes:    func(string) ([]string, error) { return []string{"read", "write", "admin"}, nil },
	})
	oa.PasswordGranter = apiauth.NewPasswordGranter(apiauth.PasswordGranterConfig{
		Issuer: oa.Issuer, ValidateCredentials: validate,
		GetSubjectScopes: func(string) ([]string, error) { return []string{"read", "write", "admin"}, nil },
	})
	return apiauth.NewTokenEndpointHandler(oa)
}

func post(t *testing.T, h http.Handler, form url.Values, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func body(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &m), rr.Body.String())
	return m
}

func claimsOf(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	c := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(token, c)
	require.NoError(t, err)
	return c
}

// See: https://www.rfc-editor.org/rfc/rfc6749#section-3.3
func TestTokenInput_ClientCredentialsHonorsTheRegisteredScope(t *testing.T) {
	h := newPolicyEndpoint(t)
	cc := func(scope string) url.Values {
		f := url.Values{"grant_type": {"client_credentials"}}
		if scope != "" {
			f.Set("scope", scope)
		}
		return f
	}

	rr := post(t, h, cc("read"), policyClient, policySecret)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "read", body(t, rr)["scope"])

	rr = post(t, h, cc("read admin"), policyClient, policySecret)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_scope", body(t, rr)["error"])

	rr = post(t, h, cc(""), policyClient, policySecret)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "read write", body(t, rr)["scope"], "no scope asked: the registered default")

	// A registration without a scope places no limit.
	rr = post(t, h, cc("admin"), openClient, openSecret)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "admin", body(t, rr)["scope"])
}

// The token names its client, as RFC 9068 §2.2 asks, so revocation
// ownership and tenant checks can see it.
//
// See: https://www.rfc-editor.org/rfc/rfc9068#section-2.2
func TestTokenInput_ClientCredentialsTokenNamesTheClient(t *testing.T) {
	rr := post(t, newPolicyEndpoint(t), url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}}, policyClient, policySecret)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, policyClient, claimsOf(t, body(t, rr)["access_token"].(string))["client_id"])
}

// See: https://www.rfc-editor.org/rfc/rfc9396#section-5
func TestTokenInput_RARTypesHonorTheRegistration(t *testing.T) {
	h := newPolicyEndpoint(t)
	form := func(typ string) url.Values {
		return url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}, "authorization_details": {`[{"type":"` + typ + `"}]`}}
	}
	rr := post(t, h, form("payment_initiation"), policyClient, policySecret)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	rr = post(t, h, form("account_information"), policyClient, policySecret)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_authorization_details", body(t, rr)["error"])
}

// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2
func TestTokenInput_PasswordGrantErrors(t *testing.T) {
	h := newPolicyEndpoint(t)
	pw := url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"wrong"}}

	rr := post(t, h, pw, "", "")
	assert.Equal(t, http.StatusBadRequest, rr.Code, "a wrong password is invalid_grant, which is 400")
	assert.Equal(t, "invalid_grant", body(t, rr)["error"])

	pw.Set("password", "right")
	pw.Set("authorization_details", `[{"locations":["https://x"]}]`) // no type
	rr = post(t, h, pw, "", "")
	assert.Equal(t, http.StatusBadRequest, rr.Code, "malformed RAR is the client's fault, not a 500")
	assert.Equal(t, "invalid_authorization_details", body(t, rr)["error"])

	// The registered scope applies on the password grant too.
	pw.Del("authorization_details")
	pw.Set("scope", "admin")
	rr = post(t, h, pw, policyClient, policySecret)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_scope", body(t, rr)["error"])
}

// A client that authenticated with Basic and failed gets a challenge.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2
func TestTokenInput_InvalidClientChallengesBasic(t *testing.T) {
	rr := post(t, newPolicyEndpoint(t), url.Values{"grant_type": {"client_credentials"}}, policyClient, "wrong-secret")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Equal(t, "invalid_client", body(t, rr)["error"])
	assert.True(t, strings.HasPrefix(rr.Header().Get("WWW-Authenticate"), "Basic "), rr.Header().Get("WWW-Authenticate"))
}

// failingCodeStore fails every lookup with a message a client must never see.
type failingCodeStore struct{ core.AuthorizationCodeStore }

func (failingCodeStore) GetAuthorizationCode(context.Context, *core.GetAuthorizationCodeRequest) (*core.GetAuthorizationCodeResponse, error) {
	return nil, errors.New("dial tcp 10.0.0.5:5432: password authentication failed for user oneauth")
}

// See: https://cwe.mitre.org/data/definitions/209.html
func TestTokenInput_ServerErrorsSayNothingInternal(t *testing.T) {
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		SigningKey: []byte("policy-as-signing-key-32-bytes!!"), SigningAlg: "HS256", Issuer: "as",
		AuthorizationCodeStore: failingCodeStore{core.NewInMemoryAuthorizationCodeStore()},
	})
	rr := post(t, apiauth.NewTokenEndpointHandler(oa), url.Values{
		"grant_type": {"authorization_code"}, "code": {"c"}, "code_verifier": {"v"}, "redirect_uri": {"https://app/cb"}, "client_id": {"x"},
	}, "", "")
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "server_error", body(t, rr)["error"])
	assert.NotContains(t, rr.Body.String(), "10.0.0.5")
	assert.NotContains(t, rr.Body.String(), "password authentication")
}

// See: https://cwe.mitre.org/data/definitions/770.html
func TestTokenInput_BodyIsBounded(t *testing.T) {
	h := newPolicyEndpoint(t)
	big := `{"grant_type":"client_credentials","scope":"` + strings.Repeat("a", 2<<20) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(policyClient, policySecret)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code, rr.Body.String())
}
