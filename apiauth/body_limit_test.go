package apiauth_test

// Revocation and introspection bodies are bounded: valid parameters followed
// by padding are refused rather than read to the end (CWE-770).
//
// See: https://cwe.mitre.org/data/definitions/770.html
// See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
)

func TestBodyLimit_RevocationAndIntrospection(t *testing.T) {
	revoke, fx, introspect := setupRevocation(t)
	tok, err := fx.Issuer().CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "user-1", Scopes: []string{"read"}})
	require.NoError(t, err)

	send := func(h http.Handler, pad int) int {
		form := url.Values{"token": {tok.Token}}
		if pad > 0 {
			form.Set("pad", strings.Repeat("a", pad))
		}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("revoke-client", "revoke-client-secret")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	for name, h := range map[string]http.Handler{"introspection": introspect, "revocation": revoke} {
		assert.Equal(t, http.StatusBadRequest, send(h, 200<<10), "%s with 200 KiB of padding", name)
	}
	assert.Equal(t, http.StatusOK, send(introspect, 0), "an ordinary request still works")
}
