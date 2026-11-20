package main

// POST /admin/signing-key/rotate (issue 507): the server signs with a new
// key, publishes it in the JWKS beside the old one for the grace period
// (issue 421), and tokens from either key verify meanwhile.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
// See: https://github.com/panyam/oneauth/issues/507

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rotationAdminKey = "rotation-admin-key-that-is-long-enough"

func rotationServer(t *testing.T, enabled bool) *httptest.Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rotation.yaml")
	yaml := fmt.Sprintf(`jwt:
  signing_alg: ES256
  ephemeral_signing_key: true
  secret_key: rotation-test-secret-key-32-bytes!!
  key_rotation:
    enabled: %v
    grace_period: 1h
keystore:
  type: memory
user_stores:
  type: memory
admin_auth:
  type: api-key
  api_key:
    key: %s
`, enabled, rotationAdminKey)
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))
	cfg, err := LoadConfig(path)
	require.NoError(t, err)
	handler, cleanup, err := buildServer(cfg)
	require.NoError(t, err)
	t.Cleanup(cleanup)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func jwksKidsAt(t *testing.T, base string) []string {
	t.Helper()
	resp, err := http.Get(base + "/.well-known/jwks.json")
	require.NoError(t, err)
	defer resp.Body.Close()
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&set))
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.Kid)
	}
	return kids
}

func rotate(t *testing.T, base, adminKey string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/admin/signing-key/rotate", nil)
	if adminKey != "" {
		req.Header.Set("X-Admin-Key", adminKey)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp, body
}

func TestSigningKeyRotation_ServerPublishesBothKeysForTheGracePeriod(t *testing.T) {
	srv := rotationServer(t, true)
	before := jwksKidsAt(t, srv.URL)
	require.Len(t, before, 1)

	resp, _ := rotate(t, srv.URL, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "the admin key is required")
	assert.Equal(t, before, jwksKidsAt(t, srv.URL))

	resp, body := rotate(t, srv.URL, rotationAdminKey)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	assert.Equal(t, before[0], body["previous_kid"])
	newKid, _ := body["kid"].(string)
	require.NotEmpty(t, newKid)
	assert.NotEqual(t, before[0], newKid)
	assert.Equal(t, "1h0m0s", body["grace_period"])
	assert.ElementsMatch(t, []string{before[0], newKid}, jwksKidsAt(t, srv.URL), "the retired key stays published (issue 421)")
}

func TestSigningKeyRotation_OffByDefault(t *testing.T) {
	srv := rotationServer(t, false)
	resp, _ := rotate(t, srv.URL, rotationAdminKey)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
