// Confidential-client authentication on the RFC 6749 §4.1.3
// authorization_code redemption path (issue 266). These tests were missing
// when the enforcement shipped; they pin the behavior the issue-358 refactor
// (device/authcode onto the shared confidential-auth gate) must preserve —
// notably that authorization_code fails CLOSED on an unregistered client_id.
package apiauth_test

import (
	"context"
	"encoding/json"
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

const (
	acConfClientID   = "ac-conf"
	acConfSecret     = "ac-conf-secret"
	acPublicClientID = "ac-public"
)

// setupConfidentialAuthCode wires an AS with an AppStore that registers a
// confidential client (client_secret_post, secret in the KeyStore) and a
// public client (auth method none).
func setupConfidentialAuthCode(t *testing.T) (*apiAuthFixture, core.AuthorizationCodeStore) {
	t.Helper()
	codeStore := core.NewInMemoryAuthorizationCodeStore()
	apps := core.NewInMemoryAppStore()
	for _, a := range []*core.AppRegistration{
		{ClientID: acConfClientID, TokenEndpointAuthMethod: "client_secret_post", SigningAlg: "HS256"},
		{ClientID: acPublicClientID, TokenEndpointAuthMethod: "none"},
	} {
		_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: a})
		require.NoError(t, err)
	}
	ks := keys.NewInMemoryKeyStore()
	_, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID:  acConfClientID,
		Key:       []byte(acConfSecret),
		Algorithm: "HS256",
	}})
	require.NoError(t, err)

	fx := newAPIAuthFixture(apiauth.OneAuthConfig{
		KeyStore:               ks,
		SigningKey:             []byte("authcode-test-secret-32chars-min!"),
		SigningAlg:             "HS256",
		Issuer:                 "test-issuer",
		RefreshStore:           newInMemoryRefreshStore(),
		AuthorizationCodeStore: codeStore,
		AppStore:               apps,
	}, nil)
	return fx, codeStore
}

func seedAuthCodeFor(t *testing.T, store core.AuthorizationCodeStore, code, clientID string) {
	t.Helper()
	_, err := store.CreateAuthorizationCode(context.Background(), &core.CreateAuthorizationCodeRequest{
		Code: &core.AuthorizationCode{
			Code:                code,
			ClientID:            clientID,
			RedirectURI:         authcodeTestRedirect,
			Scopes:              []string{"read"},
			Subject:             authcodeTestSubject,
			CodeChallenge:       core.ComputeCodeChallenge(authcodeTestVerifier),
			CodeChallengeMethod: core.CodeChallengeMethodS256,
			IssuedAt:            time.Now(),
			ExpiresAt:           time.Now().Add(1 * time.Minute),
		},
	})
	require.NoError(t, err)
}

func redeemAuthCode(t *testing.T, fx *apiAuthFixture, code, clientID, secret string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {authcodeTestVerifier},
		"redirect_uri":  {authcodeTestRedirect},
		"client_id":     {clientID},
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	fx.ServeHTTP(rr, req)
	var body map[string]any
	if rr.Body.Len() > 0 {
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
	}
	return rr.Code, body
}

func TestAuthCodeRedeem_ConfidentialClient_CorrectSecret_Succeeds(t *testing.T) {
	fx, store := setupConfidentialAuthCode(t)
	seedAuthCodeFor(t, store, "code-conf", acConfClientID)

	status, body := redeemAuthCode(t, fx, "code-conf", acConfClientID, acConfSecret)
	require.Equal(t, http.StatusOK, status, body)
	assert.NotEmpty(t, body["access_token"])
}

func TestAuthCodeRedeem_ConfidentialClient_WrongSecret_InvalidClient(t *testing.T) {
	fx, store := setupConfidentialAuthCode(t)
	seedAuthCodeFor(t, store, "code-conf", acConfClientID)

	status, body := redeemAuthCode(t, fx, "code-conf", acConfClientID, "WRONG")
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", body["error"])
}

func TestAuthCodeRedeem_ConfidentialClient_MissingSecret_InvalidClient(t *testing.T) {
	fx, store := setupConfidentialAuthCode(t)
	seedAuthCodeFor(t, store, "code-conf", acConfClientID)

	status, body := redeemAuthCode(t, fx, "code-conf", acConfClientID, "")
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", body["error"])
}

// TestAuthCodeRedeem_UnregisteredClient_FailClosed — with an AppStore wired,
// a code bound to a client_id absent from the AppStore is rejected
// invalid_client. This fail-CLOSED behavior (client_id is bound at authorize
// time, so an unknown one is anomalous) is the semantic the shared-helper
// migration must preserve — the shared gate fails OPEN for jwt-bearer.
func TestAuthCodeRedeem_UnregisteredClient_FailClosed(t *testing.T) {
	fx, store := setupConfidentialAuthCode(t)
	seedAuthCodeFor(t, store, "code-unreg", "ac-unregistered")

	status, body := redeemAuthCode(t, fx, "code-unreg", "ac-unregistered", "whatever")
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", body["error"])
}

func TestAuthCodeRedeem_PublicClient_NoCredsRequired(t *testing.T) {
	fx, store := setupConfidentialAuthCode(t)
	seedAuthCodeFor(t, store, "code-pub", acPublicClientID)

	status, body := redeemAuthCode(t, fx, "code-pub", acPublicClientID, "")
	require.Equal(t, http.StatusOK, status, body)
	assert.NotEmpty(t, body["access_token"])
}
