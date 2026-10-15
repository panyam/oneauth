package client

// Typed errors from LoginWithBrowser: one test per way a login can fail,
// each asserting errors.As / errors.Is finds the type with the server's
// error code, so a caller can act on the cause without matching text.
//
// See: https://github.com/panyam/oneauth/issues/392
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1
// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loginStack serves authorize at /authorize and token at /token, with the
// login request pointing at both explicitly so no discovery is involved.
func loginStack(t *testing.T, authorize, token http.HandlerFunc) *BrowserLoginRequest {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", authorize)
	mux.HandleFunc("/token", token)
	as := httptest.NewServer(mux)
	t.Cleanup(as.Close)
	return &BrowserLoginRequest{
		ClientID:              "test-cli",
		AuthorizationEndpoint: as.URL + "/authorize",
		TokenEndpoint:         as.URL + "/token",
		Timeout:               5 * time.Second,
		OpenBrowser:           FollowRedirects(nil),
	}
}

func redirectWith(params string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		http.Redirect(w, r, q.Get("redirect_uri")+"?"+params+"&state="+q.Get("state"), http.StatusFound)
	}
}

func jsonError(status int, code, desc string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
	}
}

func unreachable(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { t.Errorf("unexpected %s %s", r.Method, r.URL.Path) }
}

func login(t *testing.T, req *BrowserLoginRequest) error {
	t.Helper()
	_, err := NewAuthClient("http://unused.invalid", nil).LoginWithBrowser(context.Background(), req)
	require.Error(t, err)
	return err
}

// The case mcpkit cares about: the AS has forgotten a cached DCR client and
// refuses /authorize with invalid_client.
func TestLoginWithBrowser_AuthorizeRejected_FollowRedirects(t *testing.T) {
	req := loginStack(t, jsonError(http.StatusBadRequest, "invalid_client", "unknown client"), unreachable(t))
	err := login(t, req)

	var ae *AuthorizeError
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, http.StatusBadRequest, ae.Status)
	assert.Equal(t, "invalid_client", ae.Code)
	assert.Equal(t, "unknown client", ae.Description)
	var oe *BrowserOpenError
	assert.ErrorAs(t, err, &oe, "the AS rejection arrives through the opener")
}

func TestLoginWithBrowser_AuthorizeRejected_ApproveConsent(t *testing.T) {
	req := loginStack(t, jsonError(http.StatusUnauthorized, "invalid_client", "unknown client"), unreachable(t))
	req.OpenBrowser = ApproveConsent(nil)
	err := login(t, req)

	var ae *AuthorizeError
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, http.StatusUnauthorized, ae.Status)
	assert.Equal(t, "invalid_client", ae.Code)
}

// Keycloak's shape: an HTML error page, so there is no error code to report.
func TestLoginWithBrowser_AuthorizeRejected_HTMLPage(t *testing.T) {
	page := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("<html><body>\n  Invalid parameter: redirect_uri\n</body></html>"))
	}
	err := login(t, loginStack(t, page, unreachable(t)))

	var ae *AuthorizeError
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, http.StatusBadRequest, ae.Status)
	assert.Empty(t, ae.Code)
	assert.Equal(t, "<html><body> Invalid parameter: redirect_uri </body></html>", ae.Body)
}

func TestLoginWithBrowser_UserDenied_CallbackError(t *testing.T) {
	req := loginStack(t, redirectWith("error=access_denied&error_description=user+denied"), unreachable(t))
	err := login(t, req)

	var ce *CallbackError
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "access_denied", ce.Code)
	assert.Equal(t, "user denied", ce.Description)
	var ae *AuthorizeError
	assert.False(t, errors.As(err, &ae))
}

func TestLoginWithBrowser_TokenExchangeRejected(t *testing.T) {
	req := loginStack(t, redirectWith("code=c1"), jsonError(http.StatusBadRequest, "invalid_grant", "code expired"))
	err := login(t, req)

	var te *TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, http.StatusBadRequest, te.Status)
	assert.Equal(t, "invalid_grant", te.Code)
	assert.Equal(t, "code expired", te.Description)
}

// A proxy's error page in front of the token endpoint carries no OAuth
// error, but is still a token endpoint failure with a status.
func TestLoginWithBrowser_TokenExchangeNonJSON(t *testing.T) {
	gateway := func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "<html>bad gateway</html>", http.StatusBadGateway)
	}
	err := login(t, loginStack(t, redirectWith("code=c1"), gateway))

	var te *TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, http.StatusBadGateway, te.Status)
	assert.Empty(t, te.Code)
	assert.Equal(t, "token exchange failed: token endpoint returned 502", err.Error())
}

func TestLoginWithBrowser_Timeout_ErrLoginTimeout(t *testing.T) {
	req := loginStack(t, unreachable(t), unreachable(t))
	req.Timeout = 200 * time.Millisecond
	req.OpenBrowser = func(string) error { return nil }
	err := login(t, req)

	assert.ErrorIs(t, err, ErrLoginTimeout)
	assert.Equal(t, "login timed out after 200ms", err.Error())
}

// Cancelling the caller's context is the caller's own doing, not a timeout.
func TestLoginWithBrowser_CallerCancel_NotErrLoginTimeout(t *testing.T) {
	req := loginStack(t, unreachable(t), unreachable(t))
	ctx, cancel := context.WithCancel(context.Background())
	req.OpenBrowser = func(string) error { cancel(); return nil }
	_, err := NewAuthClient("http://unused.invalid", nil).LoginWithBrowser(ctx, req)

	assert.ErrorIs(t, err, context.Canceled)
	assert.NotErrorIs(t, err, ErrLoginTimeout)
}

func TestLoginWithBrowser_OpenerFailed_BrowserOpenError(t *testing.T) {
	noBrowser := errors.New("no browser")
	req := loginStack(t, unreachable(t), unreachable(t))
	req.OpenBrowser = func(string) error { return noBrowser }
	err := login(t, req)

	var oe *BrowserOpenError
	require.ErrorAs(t, err, &oe)
	assert.Contains(t, oe.URL, "/authorize?")
	assert.ErrorIs(t, err, noBrowser)
	var ae *AuthorizeError
	assert.False(t, errors.As(err, &ae))
}

// The texts are what LoginWithBrowser printed before the types existed, so
// anything logging or matching them keeps working.
func TestLoginErrors_KeepTheirText(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&AuthorizeError{Status: 400, Code: "invalid_client", Description: "unknown client"},
			"authorization endpoint answered 400 Bad Request: invalid_client: unknown client"},
		{&AuthorizeError{Status: 401, Body: "unknown client"}, "authorization endpoint answered 401 Unauthorized: unknown client"},
		{&AuthorizeError{Status: 500}, "authorization endpoint answered 500 Internal Server Error"},
		{&CallbackError{Code: "access_denied", Description: "user denied"}, "authorization error: access_denied: user denied"},
		{&TokenError{Status: 400, Code: "invalid_grant", Description: "code expired"}, "invalid_grant: code expired"},
		{&TokenError{Status: 400, Code: "invalid_grant"}, "invalid_grant"},
		{&TokenError{Status: 502}, "token endpoint returned 502"},
		{&BrowserOpenError{URL: "http://as/authorize", Err: errors.New("no browser")},
			"failed to open browser (URL: http://as/authorize): no browser"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, c.err.Error())
	}
}
