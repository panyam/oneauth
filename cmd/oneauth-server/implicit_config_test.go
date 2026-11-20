package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// code_flow.implicit (issue 507): discovery lists the implicit response
// types and grant only when it's on, and the server refuses it without
// OIDC (implicit returns an ID token) or under FAPI 2.0, which forbids it.
func TestImplicitConfig(t *testing.T) {
	cfg := &Config{}
	cfg.CodeFlow.Enabled, cfg.CodeFlow.OIDC = true, true
	cfg.JWT.SigningAlg = "ES256"
	off := serverASMetadata(cfg, "https://as.example", true)
	assert.Equal(t, []string{"code"}, off.ResponseTypesSupported)

	cfg.CodeFlow.Implicit = true
	assert.NoError(t, checkOIDC(cfg))
	on := serverASMetadata(cfg, "https://as.example", true)
	assert.Equal(t, []string{"code", "id_token", "id_token token"}, on.ResponseTypesSupported)
	assert.Contains(t, implicitGrantTypes(cfg), "implicit")

	noOIDC := *cfg
	noOIDC.CodeFlow.OIDC = false
	assert.ErrorContains(t, checkImplicit(&noOIDC), "code_flow.oidc")

	fapi := *cfg
	fapi.FAPI2 = true
	assert.ErrorContains(t, checkImplicit(&fapi), "FAPI")
}
