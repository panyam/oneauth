package main

// The reference server can run the FAPI 2.0 Security Profile: fapi2: true
// turns OneAuthConfig.FAPI2 on, PAR is served, the metadata says only what
// FAPI allows, and a config that can't satisfy the profile refuses to start.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2
// See: https://www.rfc-editor.org/rfc/rfc9126#section-5
// See: https://github.com/panyam/oneauth/issues/88

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fapiBase = "jwt:\n  secret_key: \"fapi-server-test-secret-32-bytes\"\n"

// fapiSigning is the jwt block a fapi2 config needs to pass checkFAPI2.
const fapiSigning = fapiBase + "  signing_alg: ES256\n  ephemeral_signing_key: true\n"

func TestFAPIServer_RefusesAConfigThatCantMeetTheProfile(t *testing.T) {
	cfg := loadYAML(t, fapiSigning+"fapi2: true\n")
	assert.Error(t, checkFAPI2(cfg), "FAPI without DPoP")

	cfg = loadYAML(t, fapiSigning+"fapi2: true\ndpop:\n  enabled: true\ncode_flow:\n  enabled: true\n")
	assert.Error(t, checkFAPI2(cfg), "FAPI with /authorize but no PAR")

	cfg = loadYAML(t, fapiSigning+"fapi2: true\ndpop:\n  enabled: true\ncode_flow:\n  enabled: true\n  par:\n    enabled: true\n")
	assert.NoError(t, checkFAPI2(cfg))

	assert.NoError(t, checkFAPI2(loadYAML(t, fapiBase)), "FAPI off: nothing to check")
}

func TestFAPIServer_MetadataSaysWhatFAPIAllows(t *testing.T) {
	cfg := loadYAML(t, fapiSigning+"fapi2: true\ndpop:\n  enabled: true\ncode_flow:\n  enabled: true\n  par:\n    enabled: true\n")
	meta := serverASMetadata(cfg, "https://as.example.com", true)
	assert.Equal(t, []string{"private_key_jwt"}, meta.TokenEndpointAuthMethods)
	assert.Equal(t, "https://as.example.com/par", meta.PushedAuthorizationRequestEndpoint)
	require.NotNil(t, meta.RequirePushedAuthorizationRequests)
	assert.True(t, *meta.RequirePushedAuthorizationRequests)
	assert.NotContains(t, baseGrantTypes(cfg), "password")
	for _, alg := range meta.TokenEndpointAuthSigningAlgValuesSupported {
		assert.Contains(t, []string{"PS256", "ES256", "EdDSA"}, alg, "FAPI 2.0 §5.4.1 algorithms only")
	}
}

func TestFAPIServer_PAROutsideFAPI(t *testing.T) {
	cfg := loadYAML(t, fapiBase+"code_flow:\n  enabled: true\n  par:\n    enabled: true\n")
	meta := serverASMetadata(cfg, "https://as.example.com", true)
	assert.Equal(t, "https://as.example.com/par", meta.PushedAuthorizationRequestEndpoint)
	assert.Nil(t, meta.RequirePushedAuthorizationRequests, "PAR offered, not required")
	assert.Contains(t, baseGrantTypes(cfg), "password")
}

func TestFAPIServer_ExampleConfigRunsTheProfile(t *testing.T) {
	cfg, err := LoadConfig("deploy-examples/fapi-dpop.yaml")
	require.NoError(t, err)
	assert.True(t, cfg.FAPI2)
	assert.True(t, cfg.CodeFlow.PAR.Enabled)
	assert.NoError(t, checkFAPI2(cfg))
}
