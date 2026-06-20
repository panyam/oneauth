package apiauth_test

// Tests for the PasswordGranter peer interface — #294. The granter
// is opt-in post-OAuth 2.1 §7.6; the TokenEndpointHandler returns
// unsupported_grant_type when the slot is nil. See:
//   - docs/OAUTH21_ALIGNMENT.md row 3
//   - capability-gating umbrella #344

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/localauth"
	"github.com/panyam/oneauth/stores/fs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPasswordGrant_StrictDefaultRejects pins the strict-2.1 default
// behavior: OneAuth built without wiring PasswordGranter returns
// unsupported_grant_type for grant_type=password. The error message
// names the slot so operators wiring up a deployment can find the
// opt-in path.
func TestPasswordGrant_StrictDefaultRejects(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:   ks,
		SigningKey: []byte("strict-default-test-secret-32!!!"),
		SigningAlg: "HS256",
		Issuer:     "strict-default-test",
	})
	// Deliberately NOT wiring oa.PasswordGranter — this is the
	// strict-2.1 default.
	endpoint := apiauth.NewTokenEndpointHandler(oa)

	body, _ := json.Marshal(map[string]string{
		"grant_type": "password",
		"username":   "user@example.com",
		"password":   "irrelevant",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	endpoint.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code, "strict-2.1 default MUST reject grant_type=password")
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "unsupported_grant_type", resp["error"],
		"missing PasswordGranter MUST surface as unsupported_grant_type (RFC 6749 §5.2)")
	assert.Contains(t, resp["error_description"], "PasswordGranter",
		"error description SHOULD point operators at the opt-in slot")
}

// TestPasswordGrant_WiredOptInAccepts pins the opt-in path: wiring
// OneAuth.PasswordGranter restores the OAuth 2.0 ROPC behavior. The
// granter is the peer-interface application of the pattern #298
// established for the other grants.
func TestPasswordGrant_WiredOptInAccepts(t *testing.T) {
	tmpDir := t.TempDir()
	userStore := fs.NewFSUserStore(tmpDir)
	identityStore := fs.NewFSIdentityStore(tmpDir)
	channelStore := fs.NewFSChannelStore(tmpDir)
	createUser := localauth.NewCreateUserFunc(userStore, identityStore, channelStore)
	email := "ropc@example.com"
	_, err := createUser(&localauth.Credentials{Username: "ropcuser", Email: &email, Password: "password123"})
	require.NoError(t, err)

	ks := keys.NewInMemoryKeyStore()
	validateCreds := localauth.NewCredentialsValidator(identityStore, channelStore, userStore)
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:            ks,
		SigningKey:          []byte("wired-optin-test-secret-32-chr!!"),
		SigningAlg:          "HS256",
		Issuer:              "wired-optin-test",
		RefreshStore:        newInMemoryRefreshStore(),
		ValidateCredentials: validateCreds,
		GetSubjectScopes: func(string) ([]string, error) {
			return []string{core.ScopeRead, core.ScopeWrite}, nil
		},
	})
	oa.PasswordGranter = apiauth.NewPasswordGranter(apiauth.PasswordGranterConfig{
		Issuer:              oa.Issuer,
		ValidateCredentials: validateCreds,
	})
	endpoint := apiauth.NewTokenEndpointHandler(oa)

	body, _ := json.Marshal(map[string]string{
		"grant_type": "password",
		"username":   email,
		"password":   "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	endpoint.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "wired granter MUST accept grant_type=password: %s", rr.Body.String())
	var resp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.NotEmpty(t, resp["access_token"])
	assert.Equal(t, "Bearer", resp["token_type"])
}

// TestPasswordGrant_WiredInvalidCredentialsRejects pins that the
// wired granter still rejects bad credentials with invalid_grant —
// the slot doesn't bypass authentication.
func TestPasswordGrant_WiredInvalidCredentialsRejects(t *testing.T) {
	tmpDir := t.TempDir()
	userStore := fs.NewFSUserStore(tmpDir)
	identityStore := fs.NewFSIdentityStore(tmpDir)
	channelStore := fs.NewFSChannelStore(tmpDir)
	createUser := localauth.NewCreateUserFunc(userStore, identityStore, channelStore)
	email := "bad-creds@example.com"
	_, err := createUser(&localauth.Credentials{Username: "badcreds", Email: &email, Password: "right-password"})
	require.NoError(t, err)

	ks := keys.NewInMemoryKeyStore()
	validateCreds := localauth.NewCredentialsValidator(identityStore, channelStore, userStore)
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:     ks,
		SigningKey:   []byte("bad-creds-test-secret-32-chars!!"),
		SigningAlg:   "HS256",
		Issuer:       "bad-creds-test",
		RefreshStore: newInMemoryRefreshStore(),
	})
	oa.PasswordGranter = apiauth.NewPasswordGranter(apiauth.PasswordGranterConfig{
		Issuer:              oa.Issuer,
		ValidateCredentials: validateCreds,
	})
	endpoint := apiauth.NewTokenEndpointHandler(oa)

	body, _ := json.Marshal(map[string]string{
		"grant_type": "password",
		"username":   email,
		"password":   "wrong-password",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	endpoint.ServeHTTP(rr, req)

	require.Equal(t, http.StatusUnauthorized, rr.Code,
		"wrong credentials with granter wired MUST return 401, got %d: %s", rr.Code, rr.Body.String())
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "invalid_grant", resp["error"])
}

// TestPasswordGrant_DefaultErrorPointsAtSlot ensures the error
// description specifically names the OneAuthConfig knob so wire-level
// debugging surfaces the right next step for operators.
func TestPasswordGrant_DefaultErrorPointsAtSlot(t *testing.T) {
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:   keys.NewInMemoryKeyStore(),
		SigningKey: []byte("error-msg-test-secret-32-chars!!"),
		SigningAlg: "HS256",
		Issuer:     "error-msg-test",
	})
	endpoint := apiauth.NewTokenEndpointHandler(oa)
	body, _ := json.Marshal(map[string]string{"grant_type": "password"})
	req := httptest.NewRequest(http.MethodPost, "/api/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	endpoint.ServeHTTP(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.True(t, strings.Contains(rr.Body.String(), "OneAuthConfig.PasswordGranter"),
		"error must name the field operators set to opt in (got %s)", rr.Body.String())
}
