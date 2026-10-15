package keycloak_test

// The headless OpenBrowser values against a real AS (issue 387). The unit
// tests use mock pages; these check the two behaviors against what Keycloak
// actually serves, which is an error for a bad redirect_uri (an HTML page,
// or JSON when Accept lists application/json) and a username/password form
// for /authorize.
//
// References:
//   - RFC 8252 §7.3 (https://www.rfc-editor.org/rfc/rfc8252#section-7.3)
//   - See: https://github.com/panyam/oneauth/issues/387

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/panyam/oneauth/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const publicClientID = "test-public"

func headlessLoginRequest(t *testing.T, clientID string, opener func(string) error) (*client.BrowserLoginRequest, net.Listener) {
	t.Helper()
	meta, err := client.DiscoverAS(realmURL())
	require.NoError(t, err)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return &client.BrowserLoginRequest{
		AuthorizationEndpoint: meta.AuthorizationEndpoint,
		TokenEndpoint:         meta.TokenEndpoint,
		ClientID:              clientID,
		Listener:              l,
		Timeout:               30 * time.Second,
		OpenBrowser:           opener,
	}, l
}

// test-public registers no redirect URIs, so Keycloak refuses /authorize
// with a 400 ("Invalid parameter: redirect_uri"). FollowRedirects has to
// turn that into an error at once.
func TestKeycloak_FollowRedirects_InvalidRedirectFailsFast(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	req, _ := headlessLoginRequest(t, publicClientID, client.FollowRedirects(nil))

	start := time.Now()
	_, err := client.NewAuthClient(keycloakURL(), nil).LoginWithBrowser(context.Background(), req)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 10*time.Second, "should fail fast, not wait for the timeout")
	assert.Contains(t, err.Error(), "authorization endpoint answered 400")
	assert.Contains(t, err.Error(), "redirect_uri")
	var ae *client.AuthorizeError
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, http.StatusBadRequest, ae.Status)
	// FollowRedirects lists application/json in Accept, and Keycloak then
	// answers with JSON, putting its message in "error" rather than a
	// registered RFC 6749 code.
	// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1
	assert.Equal(t, "Invalid parameter: redirect_uri", ae.Code)
}

// Keycloak's /authorize answers with its login form. ApproveConsent must
// refuse it rather than submit a form asking for a password, and it must
// not post anything.
func TestKeycloak_ApproveConsent_RefusesLoginForm(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	var posts int
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			posts++
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	req, _ := headlessLoginRequest(t, confidentialClientID, client.ApproveConsent(hc))
	req.ClientSecret = confidentialClientSecret

	start := time.Now()
	_, err := client.NewAuthClient(keycloakURL(), nil).LoginWithBrowser(context.Background(), req)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 10*time.Second)
	assert.Contains(t, err.Error(), "no approve button")
	var oe *client.BrowserOpenError
	assert.ErrorAs(t, err, &oe)
	assert.Zero(t, posts, "the login form must not be submitted")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
