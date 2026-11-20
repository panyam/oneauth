package apiauth

// /authorize refuses a repeated parameter, and query-mode redirects carry
// a fragment of their own (issue 519, from the OAuch run in issue 497).
//
// References:
//   - RFC 6749 §3.1: parameters MUST NOT be included more than once
//   - RFC 6749 §4.1.2.1: errors about client_id or redirect_uri must not redirect
//   - RFC 9700 §4.1.3: append a fragment so the request's fragment isn't carried over
//   - See: https://github.com/panyam/oneauth/issues/519

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// See: https://www.rfc-editor.org/rfc/rfc6749#section-3.1
func TestAuthorize_RepeatedParameterIsRedirectedAsInvalidRequest(t *testing.T) {
	mux := newIntakeMux(t, nil)
	q := authorizeQuery(t)
	q.Set("state", "st-1")
	q.Add("scope", "write")
	got := redirectQuery(t, getAuthorize(mux, q))
	assert.Equal(t, "invalid_request", got.Get("error"))
	assert.Contains(t, got.Get("error_description"), "scope")
	assert.Equal(t, "st-1", got.Get("state"))
}

// A repeated client_id or redirect_uri leaves no trustworthy place to
// redirect, so the error page shows it.
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1
func TestAuthorize_RepeatedClientOrRedirectShowsTheErrorPage(t *testing.T) {
	mux := newIntakeMux(t, nil)
	for _, name := range []string{"client_id", "redirect_uri"} {
		t.Run(name, func(t *testing.T) {
			q := authorizeQuery(t)
			q.Add(name, q.Get(name))
			rec := getAuthorize(mux, q)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Empty(t, rec.Header().Get("Location"))
			assert.Contains(t, rec.Body.String(), name)
		})
	}
}

// See: https://www.rfc-editor.org/rfc/rfc8707#section-2
func TestAuthorize_ResourceMayRepeat(t *testing.T) {
	mux := newIntakeMux(t, nil)
	q := authorizeQuery(t)
	q.Add("resource", "https://a.example")
	q.Add("resource", "https://b.example")
	rec := getAuthorize(mux, q)
	assert.NotContains(t, rec.Header().Get("Location"), "invalid_request")
	assert.NotContains(t, rec.Body.String(), "more than once")
}

// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.1.3
func TestAuthorize_QueryRedirectsCarryAFragment(t *testing.T) {
	h := &AuthorizationHandler{}
	req := &AuthorizationRequest{RedirectURI: "https://app.example/cb", State: "st"}

	ok, err := h.SuccessRedirect(req, "code-1")
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(ok, "#_=_"), ok)

	bad, err := h.ErrorRedirect(req, "access_denied", "")
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(bad, "#_=_"), bad)
	u, _ := url.Parse(bad)
	assert.Equal(t, "access_denied", u.Query().Get("error"))

	mux := newIntakeMux(t, nil)
	q := authorizeQuery(t)
	q.Set("response_type", "token")
	rec := getAuthorize(mux, q)
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	assert.True(t, strings.HasSuffix(rec.Header().Get("Location"), "#_=_"), rec.Header().Get("Location"))
}
