package e2e_test

// End-to-end tests for PKCE metadata verification (#65) and resource
// parameter (#66) in the authorization flow.
//
// References:
//   - OAuth 2.1 §4.1.1, §7.5.2: PKCE verification requirement
//   - RFC 8707: Resource Indicators for OAuth 2.0
//   - See: https://github.com/panyam/oneauth/issues/65
//   - See: https://github.com/panyam/oneauth/issues/66

import (
	"testing"

	"github.com/panyam/oneauth/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPKCE_E2E_ASAdvertisesS256 verifies that our e2e auth server's OIDC
// discovery metadata includes code_challenge_methods_supported: ["S256"].
// This ensures LoginWithBrowser's PKCE check (#65) would pass against our
// own server.
//
// See: https://github.com/panyam/oneauth/issues/65
func TestPKCE_E2E_ASAdvertisesS256(t *testing.T) {
	env := NewTestEnv(t)
	if env.IsRemote() {
		t.Skip("requires in-process servers")
	}

	meta, err := client.DiscoverAS(env.BaseURL())
	require.NoError(t, err)

	assert.Contains(t, meta.CodeChallengeMethodsSupported, "S256",
		"auth server should advertise PKCE S256 support in discovery metadata")
}
