package main

// acr, amr and signed userinfo on the reference server (issue 485).
// code_flow.acr_values lists the classes a password login meets;
// discovery advertises them and the userinfo signing algorithm, and an ID
// token reports the class the client asked for, with amr ["pwd"].
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDToken

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCServer_ACRValuesAndSignedUserinfoInDiscoveryAndIDToken(t *testing.T) {
	f := newLoginFixtureConfig(t, "  signing_alg: ES256\n  ephemeral_signing_key: true", "  oidc: true\n  acr_values: [\"1\"]")

	_, disc := f.get(t, "/.well-known/openid-configuration")
	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(disc), &meta))
	assert.Equal(t, []any{"1"}, meta["acr_values_supported"])
	assert.Equal(t, []any{"ES256"}, meta["userinfo_signing_alg_values_supported"])
	assert.Contains(t, meta["claims_supported"], "acr")
	assert.Contains(t, meta["claims_supported"], "amr")

	authorize := f.authorizePath() + "&" + url.Values{"scope": {"openid"}, "acr_values": {"2 1"}}.Encode()
	tok := redeemCodeAt(t, f, approveCode(t, f, authorize))
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(tok["id_token"].(string), claims)
	require.NoError(t, err)
	assert.Equal(t, "1", claims["acr"])
	assert.Equal(t, []any{"pwd"}, claims["amr"])
}

func TestAuthContext_PicksTheFirstRequestedClassTheServerMeets(t *testing.T) {
	cfg := &Config{CodeFlow: CodeFlowConfig{ACRValues: []string{"urn:oneauth:pwd", "1"}}}
	assert.Equal(t, "1", authContext(cfg, []string{"2", "1"}).ACR)
	assert.Equal(t, "urn:oneauth:pwd", authContext(cfg, []string{"3"}).ACR, "none requested is met: the server's own class")
	assert.Equal(t, "urn:oneauth:pwd", authContext(cfg, nil).ACR)
	assert.Equal(t, []string{"pwd"}, authContext(cfg, nil).AMR)
	assert.Empty(t, authContext(&Config{}, []string{"1"}).ACR, "no acr_values configured leaves acr out")
}
