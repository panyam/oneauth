package client

// Every grant AuthClient drives returns a *TokenError when the token
// endpoint refuses it, carrying the RFC 6749 §5.2 error code, while keeping
// the message each call printed before.
//
// See: https://github.com/panyam/oneauth/issues/392
// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tokenEndpoint(t *testing.T, h http.HandlerFunc) *AuthClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewAuthClient(srv.URL, newMockCredentialStore(),
		WithASMetadata(&ASMetadata{TokenEndpoint: srv.URL + "/token"}))
}

func requireTokenError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var te *TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, status, te.Status)
	assert.Equal(t, code, te.Code)
}

func TestTokenError_Grants(t *testing.T) {
	rejected := jsonError(http.StatusUnauthorized, "invalid_client", "client not found")
	ctx := context.Background()
	grants := map[string]func(*AuthClient) error{
		"client_credentials": func(c *AuthClient) error {
			_, err := c.ClientCredentials(ctx, &ClientCredentialsRequest{ClientID: "a", ClientSecret: "s"})
			return err
		},
		"refresh_token": func(c *AuthClient) error {
			_, err := c.RefreshToken(ctx, &RefreshTokenRequest{RefreshToken: "r", ClientID: "a", ClientSecret: "s"})
			return err
		},
		"password": func(c *AuthClient) error {
			_, err := c.Login(ctx, &LoginRequest{Username: "u", Password: "p"})
			return err
		},
		"jwt_bearer": func(c *AuthClient) error {
			_, err := c.JwtBearerGrant(ctx, &JwtBearerGrantRequest{Assertion: "x.y.z", ClientID: "a", ClientSecret: "s"})
			return err
		},
	}
	for name, grant := range grants {
		t.Run(name, func(t *testing.T) {
			err := grant(tokenEndpoint(t, rejected))
			requireTokenError(t, err, http.StatusUnauthorized, "invalid_client")
			assert.Equal(t, "authentication failed: client not found", err.Error())
		})
	}
}

// Login without AS metadata posts JSON to the oneauth-native endpoint.
func TestTokenError_LegacyLogin(t *testing.T) {
	srv := httptest.NewServer(jsonError(http.StatusUnauthorized, "invalid_grant", ""))
	defer srv.Close()
	_, err := NewAuthClient(srv.URL, newMockCredentialStore()).Login(context.Background(), &LoginRequest{Username: "u", Password: "p"})
	requireTokenError(t, err, http.StatusUnauthorized, "invalid_grant")
	assert.Equal(t, "authentication failed: invalid_grant", err.Error())
}

// A non-JSON failure used to surface as a JSON decode error, hiding the status.
func TestTokenError_NonJSONFailure(t *testing.T) {
	c := tokenEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "<html>bad gateway</html>", http.StatusBadGateway)
	})
	_, err := c.ClientCredentials(context.Background(), &ClientCredentialsRequest{ClientID: "a", ClientSecret: "s"})
	requireTokenError(t, err, http.StatusBadGateway, "")
	assert.Equal(t, "authentication failed: HTTP 502", err.Error())
}

func TestTokenError_TokenExchange(t *testing.T) {
	c := tokenEndpoint(t, jsonError(http.StatusBadRequest, "invalid_target", "unknown audience"))
	_, err := c.TokenExchange(context.Background(), &TokenExchangeRequest{
		SubjectToken: "t", SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token", ClientID: "a", ClientSecret: "s",
	})
	requireTokenError(t, err, http.StatusBadRequest, "invalid_target")
	assert.Contains(t, err.Error(), "token exchange failed: status=400 body=")
}

// The four polling codes keep their RFC 8628 sentinels; anything else is a
// TokenError.
func TestTokenError_PollDeviceToken(t *testing.T) {
	poll := func(c *AuthClient) error {
		_, err := c.PollDeviceToken(context.Background(), &PollDeviceTokenRequest{DeviceCode: "d", ClientID: "a"})
		return err
	}

	err := poll(tokenEndpoint(t, jsonError(http.StatusBadRequest, "invalid_client", "gone")))
	requireTokenError(t, err, http.StatusBadRequest, "invalid_client")
	assert.Equal(t, "PollDeviceToken: invalid_client: gone", err.Error())

	err = poll(tokenEndpoint(t, jsonError(http.StatusBadRequest, "access_denied", "")))
	assert.ErrorIs(t, err, ErrAccessDenied)
}
