package apiauth_test

// CIMD documents carry the per-client settings DCR does (issue 557):
// dpop_bound_access_tokens, require_pushed_authorization_requests, and the
// userinfo and JARM signing algorithms. An algorithm the AS can't sign
// with makes the document invalid, as DCR refuses it, rather than failing
// later at the response.
//
// See: https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/
// See: https://github.com/panyam/oneauth/issues/557

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
)

func TestCIMD_CarriesPerClientSettings(t *testing.T) {
	s := newCIMDServer(t)
	s.set(func(d map[string]any) {
		d["dpop_bound_access_tokens"] = true
		d["require_pushed_authorization_requests"] = true
		d["userinfo_signed_response_alg"] = "ES256"
		d["authorization_signed_response_alg"] = "ES256"
	})
	store := storeFor(s)
	store.UserinfoSigningAlgs = []string{"ES256"}
	store.AuthorizationSigningAlgs = []string{"ES256"}
	app, err := getApp(store, s.ClientID())
	require.NoError(t, err)
	assert.True(t, app.DPoPBoundAccessTokens)
	assert.True(t, app.RequirePushedAuthorizationRequests)
	assert.Equal(t, "ES256", app.UserinfoSignedResponseAlg)
	assert.Equal(t, "ES256", app.AuthorizationSignedResponseAlg)
}

func TestCIMD_RefusesAnAlgTheASCannotSignWith(t *testing.T) {
	for field, alg := range map[string]string{
		"userinfo_signed_response_alg":      "RS256",
		"authorization_signed_response_alg": "none",
	} {
		t.Run(field, func(t *testing.T) {
			s := newCIMDServer(t)
			s.set(func(d map[string]any) { d[field] = alg })
			store := storeFor(s)
			store.UserinfoSigningAlgs = []string{"ES256"}
			store.AuthorizationSigningAlgs = []string{"ES256"}
			_, err := getApp(store, s.ClientID())
			require.Error(t, err)
			assert.True(t, errors.Is(err, apiauth.ErrInvalidClientMetadata), "got %v", err)
			assert.Contains(t, err.Error(), field)
		})
	}
}

// With OIDC or JARM off the AS signs nothing for that field, so a document
// asking for an algorithm there is invalid.
func TestCIMD_AnAlgWithNothingToSignIsRefused(t *testing.T) {
	s := newCIMDServer(t)
	s.set(func(d map[string]any) { d["authorization_signed_response_alg"] = "ES256" })
	_, err := getApp(storeFor(s), s.ClientID())
	assert.True(t, errors.Is(err, apiauth.ErrInvalidClientMetadata), "got %v", err)
}
