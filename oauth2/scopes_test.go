package oauth2_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/panyam/oneauth/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func authorizeScopes(t *testing.T, h http.Handler, query string) (int, []string) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+query, nil))
	if w.Code != http.StatusFound {
		return w.Code, nil
	}
	u, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	return w.Code, strings.Fields(u.Query().Get("scope"))
}

func TestGithubScopes_DefaultUnchanged(t *testing.T) {
	g := oauth2.NewGithubOAuth2("id", "secret", "http://localhost/cb", nil)
	code, scopes := authorizeScopes(t, g.Handler(), "")
	require.Equal(t, http.StatusFound, code)
	assert.Equal(t, []string{"read:user", "user:email"}, scopes)
	assert.Equal(t, []string{"read:user", "user:email"}, g.Scopes())
}

func TestGithubScopes_SetScopesReplacesDefault(t *testing.T) {
	g := oauth2.NewGithubOAuth2("id", "secret", "http://localhost/cb", nil)
	g.SetScopes("read:user", "repo")
	_, scopes := authorizeScopes(t, g.Handler(), "")
	assert.Equal(t, []string{"read:user", "repo"}, scopes)
}

// A later connect asks for more with ?scope=, limited to the allowlist.
// See: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps#requested-scopes-and-granted-scopes
func TestGithubScopes_AllowlistedExtraScopeIsRequested(t *testing.T) {
	g := oauth2.NewGithubOAuth2("id", "secret", "http://localhost/cb", nil)
	g.AllowedExtraScopes = []string{"repo", "read:org"}
	code, scopes := authorizeScopes(t, g.Handler(), "?scope=repo+read:user")
	require.Equal(t, http.StatusFound, code)
	assert.Equal(t, []string{"read:user", "user:email", "repo"}, scopes)
}

// A crafted connect link can't widen the grant past the allowlist, for
// example to delete_repo.
// See: https://cwe.mitre.org/data/definitions/269.html
func TestGithubScopes_ExtraScopeOutsideAllowlistRefused(t *testing.T) {
	g := oauth2.NewGithubOAuth2("id", "secret", "http://localhost/cb", nil)
	g.AllowedExtraScopes = []string{"repo"}
	code, _ := authorizeScopes(t, g.Handler(), "?scope=delete_repo")
	assert.Equal(t, http.StatusBadRequest, code)

	g2 := oauth2.NewGithubOAuth2("id", "secret", "http://localhost/cb", nil)
	code, _ = authorizeScopes(t, g2.Handler(), "?scope=repo")
	assert.Equal(t, http.StatusBadRequest, code, "no allowlist means no extra scopes")
}
