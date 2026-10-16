package admin_test

// DCR initial access tokens (RFC 7591 §3), issue 408: registration can be
// opened to clients holding a registration token without handing them the
// admin key, and the registration token opens nothing else.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-3
// See: https://github.com/panyam/oneauth/issues/408

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/keys"
)

func TestDCRInitialAccessToken(t *testing.T) {
	registrar := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewAPIKeyAuth("the-admin-key-the-admin-key-1234"))
	registrar.IssuerBaseURL = "http://example.com"
	registrar.RegistrationAuth = admin.NewInitialAccessTokenAuth("iat-for-mcp-clients-0123456789ab")
	h := registrar.Handler()

	call := func(method, path string, header map[string]string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(`{"client_name":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range header {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	bearer := map[string]string{"Authorization": "Bearer iat-for-mcp-clients-0123456789ab"}
	adminKey := map[string]string{"X-Admin-Key": "the-admin-key-the-admin-key-1234"}

	assert.Equal(t, http.StatusCreated, call(http.MethodPost, "/apps/dcr", bearer), "the initial access token registers")
	assert.Equal(t, http.StatusCreated, call(http.MethodPost, "/apps/dcr", adminKey), "the admin key still registers")
	assert.Equal(t, http.StatusUnauthorized, call(http.MethodPost, "/apps/dcr", nil), "no credential")
	assert.Equal(t, http.StatusUnauthorized, call(http.MethodPost, "/apps/dcr", map[string]string{"Authorization": "Bearer wrong"}), "a wrong token")
	assert.Equal(t, http.StatusUnauthorized, call(http.MethodGet, "/apps", bearer), "the initial access token is not an admin credential")
}

// With no tokens configured nothing gets through, rather than everything.
func TestDCRInitialAccessToken_EmptyListRefuses(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", nil)
	req.Header.Set("Authorization", "Bearer ")
	assert.Error(t, admin.NewInitialAccessTokenAuth().Authenticate(req))
	assert.Error(t, admin.NewInitialAccessTokenAuth("").Authenticate(req))
}
