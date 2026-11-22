package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// callbackOpener plays the AS: it skips /authorize and delivers the given
// callback parameters straight to the loopback redirect_uri, echoing the
// request's state unless params sets its own. It records the auth URL.
func callbackOpener(t *testing.T, params url.Values, authURL *string) func(string) error {
	return func(u string) error {
		*authURL = u
		parsed, err := url.Parse(u)
		require.NoError(t, err)
		q := parsed.Query()
		cb, err := url.Parse(q.Get("redirect_uri"))
		require.NoError(t, err)
		out := url.Values{}
		for k, v := range params {
			out[k] = v
		}
		if _, ok := params["state"]; !ok {
			out.Set("state", q.Get("state"))
		}
		cb.RawQuery = out.Encode()
		go func() {
			if resp, err := http.Get(cb.String()); err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
}

// loginWithResponseMode logs in with mode. With params nil the mock AS
// runs the whole flow; otherwise the callback carries params instead.
func loginWithResponseMode(t *testing.T, mode string, params url.Values) (string, error) {
	t.Helper()
	authSrv := mockAuthServer(t)
	ac := NewAuthClient(authSrv.URL, newMockCredentialStore())
	var authURL string
	opener := callbackOpener(t, params, &authURL)
	if params == nil {
		opener = func(u string) error {
			authURL = u
			go simulateBrowser(u)
			return nil
		}
	}
	_, err := ac.LoginWithBrowser(context.Background(), &BrowserLoginRequest{
		ClientID:     "test-cli",
		ResponseMode: mode,
		Timeout:      5 * time.Second,
		OpenBrowser:  opener,
	})
	return authURL, err
}

func TestLoginWithBrowser_ResponseModeOnAuthorizeURL(t *testing.T) {
	authURL, err := loginWithResponseMode(t, "query", nil)
	require.NoError(t, err)
	u, _ := url.Parse(authURL)
	assert.Equal(t, "query", u.Query().Get("response_mode"))
}

func TestLoginWithBrowser_NoResponseModeByDefault(t *testing.T) {
	authURL, err := loginWithResponseMode(t, "", nil)
	require.NoError(t, err)
	u, _ := url.Parse(authURL)
	_, sent := u.Query()["response_mode"]
	assert.False(t, sent, "response_mode is left out unless the caller sets it")
}

// An AS that ignores response_mode=jwt and answers with a plain code would
// otherwise get an unsigned response accepted, which is the downgrade JARM
// exists to stop.
//
// See: https://openid.net/specs/oauth-v2-jarm.html#section-4.4
func TestLoginWithBrowser_JWTModeRefusesPlainCode(t *testing.T) {
	for _, mode := range []string{"jwt", "query.jwt", "form_post.jwt"} {
		t.Run(mode, func(t *testing.T) {
			_, err := loginWithResponseMode(t, mode, url.Values{"code": {"mock-code"}})
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrUnverifiedAuthorizationResponse), "got %v", err)
		})
	}
}

// A `response` that doesn't verify is refused, and nothing in it is
// exchanged.
func TestLoginWithBrowser_JWTModeRefusesAnUnverifiableResponse(t *testing.T) {
	_, err := loginWithResponseMode(t, "jwt", url.Values{"response": {"eyJhbGciOiJQUzI1NiJ9.e30.sig"}, "state": nil})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnverifiedAuthorizationResponse), "got %v", err)
}
