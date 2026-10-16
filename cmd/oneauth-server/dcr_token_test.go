package main

// DCR initial access tokens in the reference server, issue 408: a
// deployment can keep the admin API behind api-key and still let clients
// register with a separate token.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-3
// See: https://github.com/panyam/oneauth/issues/408

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDCRToken_ConfiguredTokensBuildARegistrationAuth(t *testing.T) {
	cfg := loadYAML(t, "admin_auth:\n  type: api-key\n  api_key:\n    key: \"admin-key-admin-key-admin-key-12\"\n  dcr_initial_access_tokens:\n    - \"iat-for-mcp-clients-0123456789ab\"\n")
	auth, err := buildRegistrationAuth(cfg)
	require.NoError(t, err)
	require.NotNil(t, auth)
	req := httptest.NewRequest(http.MethodPost, "/apps/dcr", nil)
	req.Header.Set("Authorization", "Bearer iat-for-mcp-clients-0123456789ab")
	assert.NoError(t, auth.Authenticate(req))

	none, err := buildRegistrationAuth(loadYAML(t, "admin_auth:\n  type: api-key\n"))
	require.NoError(t, err)
	assert.Nil(t, none, "no tokens configured, no registration auth")
}

func TestDCRToken_ShortTokensRefused(t *testing.T) {
	_, err := buildRegistrationAuth(loadYAML(t, "admin_auth:\n  dcr_initial_access_tokens:\n    - \"short\"\n"))
	assert.Error(t, err, "a guessable registration token")
}
