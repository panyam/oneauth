package main

// The SDK as a relying party against the reference server: LoginWithBrowser
// with VerifyIDToken sends a nonce, and the ID token that comes back passes
// the SDK's own checks against the JWKS discovery names.
// tests/keycloak/oidc_id_token_interop_test.go runs the same login against
// Keycloak and pins the same claim names.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
// See: https://github.com/panyam/oneauth/issues/453

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/client"
)

// sharedIDTokenClaims are the claims both oneauth and Keycloak put in a
// code-flow ID token, `typ: ID` marker included. Keep in step with
// tests/keycloak/oidc_id_token_interop_test.go.
var sharedIDTokenClaims = []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "typ"}

func TestOIDCServer_SDKVerifiesTheIDToken(t *testing.T) {
	f := newOIDCServerFixture(t)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	redirect := "http://" + l.Addr().String() + "/callback"
	reg, _ := json.Marshal(map[string]any{
		"redirect_uris":              []string{redirect},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	resp, err := f.http.Post(f.url+"/apps/dcr", "application/json", strings.NewReader(string(reg)))
	require.NoError(t, err)
	var app struct {
		ClientID string `json:"client_id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&app))
	resp.Body.Close()

	f.postForm(t, "/auth/login", "/auth/login", url.Values{"username": {loginTestEmail}, "password": {loginTestPassword}})

	cred, err := client.NewAuthClient(f.url, nil).LoginWithBrowser(context.Background(), &client.BrowserLoginRequest{
		ClientID:      app.ClientID,
		Listener:      l,
		RedirectURI:   redirect,
		Scopes:        []string{"email"},
		Timeout:       10 * time.Second,
		VerifyIDToken: true,
		OpenBrowser:   client.ApproveConsent(&http.Client{Jar: f.http.Jar}),
	})
	require.NoError(t, err)

	got := cred.IDTokenClaims
	require.NotNil(t, got)
	assert.Equal(t, f.url, got.Issuer)
	assert.Equal(t, []string{app.ClientID}, got.Audience)
	assert.Equal(t, subjectOf(t, f, cred.AccessToken), got.Subject, "the ID token names the same user as the access token")
	assert.Equal(t, loginTestEmail, got.Email)
	assert.Equal(t, loginTestEmail, cred.UserEmail)
	for _, name := range sharedIDTokenClaims {
		assert.Contains(t, got.Claims, name)
	}
	assert.Equal(t, "ID", got.Claims["typ"])
}
