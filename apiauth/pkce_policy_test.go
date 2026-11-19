package apiauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pkcePolicyApps registers the confidential and public clients the PKCE
// policy tests use, each limited to the "read" scope.
func pkcePolicyApps(t *testing.T) core.AppRegistrationStore {
	t.Helper()
	apps := core.NewInMemoryAppStore()
	for _, a := range []*core.AppRegistration{
		{ClientID: acConfClientID, TokenEndpointAuthMethod: "client_secret_post", SigningAlg: "HS256", RedirectURIs: []string{authcodeTestRedirect}, Scope: "read"},
		{ClientID: acPublicClientID, TokenEndpointAuthMethod: "none", RedirectURIs: []string{authcodeTestRedirect}, Scope: "read"},
	} {
		_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: a})
		require.NoError(t, err)
	}
	return apps
}

// authorizeParams is an authorization request without PKCE.
func authorizeParams(clientID, scope string) string {
	return "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {authcodeTestRedirect},
		"scope": {scope}, "state": {"st"},
	}.Encode()
}

func parse(h *apiauth.AuthorizationHandler, target string) (string, string) {
	_, _, code, desc := h.ParseAndValidate(httptest.NewRequest(http.MethodGet, target, nil))
	return code, desc
}

// OIDC Core and OAuth 2.0 let a confidential client omit PKCE; OAuth 2.1
// doesn't. The opt-in policy accepts it from a registered confidential
// client only.
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
// See: https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1
func TestAuthorize_PKCEOptionalForConfidential_AcceptsOnlyConfidentialClients(t *testing.T) {
	apps := pkcePolicyApps(t)
	optional := &apiauth.AuthorizationHandler{Store: core.NewInMemoryAuthorizationCodeStore(), AppStore: apps, IssuerURL: "https://as.example", PKCEPolicy: apiauth.PKCEOptionalForConfidential}

	code, desc := parse(optional, authorizeParams(acConfClientID, "read"))
	assert.Empty(t, code, "a confidential client may omit PKCE: %s", desc)

	code, _ = parse(optional, authorizeParams(acPublicClientID, "read"))
	assert.Equal(t, "invalid_request", code, "a public client must still send PKCE")

	// The scope check after PKCE still runs.
	code, _ = parse(optional, authorizeParams(acConfClientID, "admin"))
	assert.Equal(t, "invalid_scope", code)
}

func TestAuthorize_PKCERequiredByDefault(t *testing.T) {
	h := &apiauth.AuthorizationHandler{Store: core.NewInMemoryAuthorizationCodeStore(), AppStore: pkcePolicyApps(t), IssuerURL: "https://as.example"}
	code, desc := parse(h, authorizeParams(acConfClientID, "read"))
	assert.Equal(t, "invalid_request", code)
	assert.Contains(t, desc, "code_challenge is required")
}

// Without an AppStore the handler can't tell a confidential client from a
// public one, so PKCE stays required whatever the policy says.
func TestAuthorize_PKCEOptionalWithoutAppStoreStillRequires(t *testing.T) {
	h := &apiauth.AuthorizationHandler{Store: core.NewInMemoryAuthorizationCodeStore(), AllowAnyRedirectURI: true, IssuerURL: "https://as.example", PKCEPolicy: apiauth.PKCEOptionalForConfidential}
	code, _ := parse(h, authorizeParams(acConfClientID, "read"))
	assert.Equal(t, "invalid_request", code)
}

// pkceGrantFixture is an AS whose code grant runs under policy, with a
// code seeded for clientID and no code_challenge.
func pkceGrantFixture(t *testing.T, policy apiauth.PKCEPolicy, clientID string) *apiAuthFixture {
	t.Helper()
	codes := core.NewInMemoryAuthorizationCodeStore()
	ks := keys.NewInMemoryKeyStore()
	_, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: acConfClientID, Key: []byte(acConfSecret), Algorithm: "HS256"}})
	require.NoError(t, err)
	fx := newAPIAuthFixture(apiauth.OneAuthConfig{
		KeyStore: ks, SigningKey: []byte("authcode-test-secret-32chars-min!"), SigningAlg: "HS256", Issuer: "test-issuer",
		RefreshStore: newInMemoryRefreshStore(), AuthorizationCodeStore: codes, AppStore: pkcePolicyApps(t), PKCEPolicy: policy,
	}, nil)
	_, err = codes.CreateAuthorizationCode(context.Background(), &core.CreateAuthorizationCodeRequest{Code: &core.AuthorizationCode{
		Code: "code-no-pkce", ClientID: clientID, RedirectURI: authcodeTestRedirect, Scopes: []string{"read"},
		Subject: authcodeTestSubject, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	}})
	require.NoError(t, err)
	return fx
}

func redeemNoPKCECode(t *testing.T, fx *apiAuthFixture, clientID, secret, verifier string) (int, string) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {"code-no-pkce"}, "redirect_uri": {authcodeTestRedirect}, "client_id": {clientID}}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	fx.ServeHTTP(rr, req)
	return rr.Code, rr.Body.String()
}

// A confidential client redeems a code issued without PKCE by
// authenticating, with no code_verifier.
func TestCodeGrant_PKCEOptional_ConfidentialRedeemsWithoutVerifier(t *testing.T) {
	fx := pkceGrantFixture(t, apiauth.PKCEOptionalForConfidential, acConfClientID)
	status, body := redeemNoPKCECode(t, fx, acConfClientID, acConfSecret, "")
	require.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, "access_token")
}

// A code_verifier sent for a code whose request had no code_challenge is
// a PKCE downgrade attempt, and is refused.
// See: https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.8.2
func TestCodeGrant_PKCEOptional_VerifierForANoPKCECodeIsRefused(t *testing.T) {
	fx := pkceGrantFixture(t, apiauth.PKCEOptionalForConfidential, acConfClientID)
	status, body := redeemNoPKCECode(t, fx, acConfClientID, acConfSecret, authcodeTestVerifier)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, body, "invalid_grant")
	assert.Contains(t, body, "had no code_challenge")
}

// Client authentication protects a code issued without PKCE, so a client
// that didn't authenticate can't redeem one.
// See: https://cwe.mitre.org/data/definitions/287.html
func TestCodeGrant_PKCEOptional_PublicClientCantRedeemANoPKCECode(t *testing.T) {
	fx := pkceGrantFixture(t, apiauth.PKCEOptionalForConfidential, acPublicClientID)
	status, body := redeemNoPKCECode(t, fx, acPublicClientID, "", "")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, body, "invalid_grant")
}

// Under the default policy a code without a challenge doesn't redeem,
// whatever path stored it.
func TestCodeGrant_PKCERequired_NoPKCECodeIsRefused(t *testing.T) {
	fx := pkceGrantFixture(t, apiauth.PKCERequired, acConfClientID)
	status, body := redeemNoPKCECode(t, fx, acConfClientID, acConfSecret, "")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, body, "code_verifier is required")
}

// FAPI 2.0 requires PKCE, so the two settings can't be combined, and an
// unknown policy is a configuration error.
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.2
func TestNewOneAuth_RefusesFAPI2WithOptionalPKCEAndUnknownPolicies(t *testing.T) {
	assert.PanicsWithValue(t, "apiauth: NewOneAuth: FAPI2 requires PKCE, so PKCEPolicy must be PKCERequired", func() {
		apiauth.NewOneAuth(apiauth.OneAuthConfig{FAPI2: true, PKCEPolicy: apiauth.PKCEOptionalForConfidential, SigningKey: []byte("x")})
	})
	assert.Panics(t, func() {
		apiauth.NewOneAuth(apiauth.OneAuthConfig{PKCEPolicy: "sometimes", SigningKey: []byte("x")})
	})
}
