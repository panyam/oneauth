package main

// The AS metadata says what the server does: response types it can
// return, auth methods its token endpoint accepts, RFC 9207 iss on the
// authorization response when /authorize is on.
//
// See: https://www.rfc-editor.org/rfc/rfc8414#section-2
// See: https://www.rfc-editor.org/rfc/rfc9207#section-3
// See: https://github.com/panyam/oneauth/issues/88

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetadata_AdvertisesWhatTheServerDoes(t *testing.T) {
	cfg := loadYAML(t, "jwt:\n  secret_key: \"metadata-test-secret-32-bytes-ok\"\n")

	off := serverASMetadata(cfg, "https://as.example.com", false)
	assert.NotContains(t, off.ResponseTypesSupported, "token", "the implicit grant isn't supported")
	assert.Empty(t, off.ResponseTypesSupported, "no /authorize, no response types")
	assert.Nil(t, off.AuthorizationResponseIssParameterSupported)
	assert.Equal(t, "https://as.example.com/oauth/revoke", off.RevocationEndpoint)

	on := serverASMetadata(cfg, "https://as.example.com", true)
	assert.Equal(t, []string{"code"}, on.ResponseTypesSupported)
	require.NotNil(t, on.AuthorizationResponseIssParameterSupported)
	assert.True(t, *on.AuthorizationResponseIssParameterSupported, "RFC 9207 iss on the authorization response")
	assert.Contains(t, on.TokenEndpointAuthMethods, "none", "public clients redeem codes without authenticating")
}
