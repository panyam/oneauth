package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// code_flow.jarm (issue 411): discovery lists the JARM response modes and
// the signing alg only when it's on, and the server refuses it without the
// code flow or with an HMAC key, which clients can't verify.
func TestJARMConfig(t *testing.T) {
	cfg := &Config{}
	cfg.CodeFlow.Enabled = true
	cfg.JWT.SigningAlg = "ES256"
	off := serverASMetadata(cfg, "https://as.example", true)
	assert.NotContains(t, off.ResponseModesSupported, "jwt")
	assert.Empty(t, off.AuthorizationSigningAlgValuesSupported)

	cfg.CodeFlow.JARM.Enabled = true
	assert.NoError(t, checkJARM(cfg))
	on := serverASMetadata(cfg, "https://as.example", true)
	assert.Equal(t, []string{"query", "form_post", "jwt", "query.jwt", "fragment.jwt", "form_post.jwt"}, on.ResponseModesSupported)
	assert.Equal(t, []string{"ES256"}, on.AuthorizationSigningAlgValuesSupported)
	assert.Equal(t, []string{"ES256"}, jarmSigningAlgs(cfg), "DCR accepts what discovery advertises (issue 413)")
	assert.Nil(t, jarmSigningAlgs(&Config{}), "JARM off: DCR refuses every authorization_signed_response_alg")

	hmac := *cfg
	hmac.JWT.SigningAlg = ""
	assert.ErrorContains(t, checkJARM(&hmac), "HS256")

	noCodeFlow := *cfg
	noCodeFlow.CodeFlow.Enabled = false
	assert.ErrorContains(t, checkJARM(&noCodeFlow), "code_flow.enabled")
}
