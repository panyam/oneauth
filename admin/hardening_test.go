package admin_test

// Admin and registration endpoints that fail closed: a registrar with no
// AdminAuth refuses requests instead of serving them, bodies are bounded,
// auth failures are rate limited, and a rotation can't keep an old secret
// valid indefinitely.
//
// References:
//   - CWE-306 missing authentication (https://cwe.mitre.org/data/definitions/306.html)
//   - CWE-307 brute force (https://cwe.mitre.org/data/definitions/307.html)
//   - CWE-400 unbounded input (https://cwe.mitre.org/data/definitions/400.html)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

// See: https://cwe.mitre.org/data/definitions/306.html
func TestHardening_NilAdminAuthFailsClosed(t *testing.T) {
	h := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), nil).Handler()

	for _, tc := range []struct{ method, target, body string }{
		{http.MethodGet, "/apps", ""},
		{http.MethodPost, "/apps/dcr", dcrBody()},
	} {
		req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
		req.Host = "127.0.0.1:8080"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code, "%s %s with no AdminAuth configured", tc.method, tc.target)
	}

	// Open registration is a deliberate choice: NoAuth.
	open := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewNoAuth()).Handler()
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", strings.NewReader(dcrBody()))
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	open.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
}

// See: https://cwe.mitre.org/data/definitions/400.html
func TestHardening_BodiesAreBounded(t *testing.T) {
	h := newCredentialRegistrar(t)
	huge := `{"client_name":"` + strings.Repeat("a", 2<<20) + `"}`

	rr := serveAdmin(h, http.MethodPost, "/apps/dcr", huge, true)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)

	id := register(t, h)["client_id"].(string)
	rr = serveAdmin(h, http.MethodPost, "/apps/"+id+"/rotate", `{"public_key":"`+strings.Repeat("a", 2<<20)+`"}`, true)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
}

func TestHardening_RotateGracePeriodIsCapped(t *testing.T) {
	h := newCredentialRegistrar(t)
	id := register(t, h)["client_id"].(string)

	rr := serveAdmin(h, http.MethodPost, "/apps/"+id+"/rotate", `{"grace_period":"876000h"}`, true)
	assert.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())

	rr = serveAdmin(h, http.MethodPost, "/apps/"+id+"/rotate", `{"grace_period":"nonsense"}`, true)
	assert.Equal(t, http.StatusBadRequest, rr.Code, "an unparseable grace period isn't silently the default")

	rr = serveAdmin(h, http.MethodPost, "/apps/"+id+"/rotate", `{"grace_period":"48h"}`, true)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

// See: https://cwe.mitre.org/data/definitions/307.html
func TestHardening_AdminAuthFailuresAreRateLimited(t *testing.T) {
	r := admin.NewAppRegistrar(keys.NewInMemoryKeyStore(), admin.NewAPIKeyAuth(testAdminKey))
	r.AuthRateLimiter = core.NewInMemoryRateLimiter(0.001, 3)
	h := r.Handler()

	var last int
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/apps", nil)
		req.Header.Set("X-Admin-Key", "guess")
		req.RemoteAddr = "203.0.113.5:4000"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		last = rr.Code
	}
	require.Equal(t, http.StatusTooManyRequests, last)
}
