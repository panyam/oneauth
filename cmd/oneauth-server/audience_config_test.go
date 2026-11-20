package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwt.audience binds every access token to one resource server (issue
// 495). An MCP server rejects a token whose aud isn't its own URL (MCP
// authorization spec, RFC 8707), so a oneauth-server fronting one sets
// this to that URL.
//
// See: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
func TestAudienceConfig_AccessTokensCarryIt(t *testing.T) {
	for _, tc := range []struct{ audience, want string }{
		{"https://mcp.example/mcp", "https://mcp.example/mcp"},
		{"", ""},
	} {
		path := filepath.Join(t.TempDir(), "aud.yaml")
		cfgYAML := fmt.Sprintf(`jwt:
  signing_alg: ES256
  ephemeral_signing_key: true
  secret_key: audience-test-secret-key-32-bytes!
  audience: %q
keystore:
  type: memory
user_stores:
  type: memory
admin_auth:
  type: none
  allow_open: true
`, tc.audience)
		require.NoError(t, os.WriteFile(path, []byte(cfgYAML), 0o600))
		cfg, err := LoadConfig(path)
		require.NoError(t, err)
		handler, cleanup, err := buildServer(cfg)
		require.NoError(t, err)
		t.Cleanup(cleanup)
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)

		resp, err := http.Post(srv.URL+"/apps/dcr", "application/json", strings.NewReader(`{"client_name":"aud","grant_types":["client_credentials"]}`))
		require.NoError(t, err)
		reg := map[string]any{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&reg))
		resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode, reg)

		form := url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}}
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(reg["client_id"].(string), reg["client_secret"].(string))
		resp, err = http.DefaultClient.Do(req)
		require.NoError(t, err)
		tok := map[string]any{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, tok)

		claims := jwt.MapClaims{}
		_, _, err = jwt.NewParser().ParseUnverified(tok["access_token"].(string), claims)
		require.NoError(t, err)
		if tc.want == "" {
			assert.Nil(t, claims["aud"], "no jwt.audience leaves aud out")
		} else {
			assert.Equal(t, tc.want, claims["aud"])
		}
	}
}
