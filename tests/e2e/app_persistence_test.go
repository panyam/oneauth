package e2e_test

// End-to-end "simulated restart" test for AppRegistrationStore (issue #165).
// Builds a self-contained AppRegistrar over a shared store + KeyStore, exercises
// register/list/delete via HTTP, then drops the registrar and builds a fresh one
// over the SAME backing stores to verify persistence survives a process restart.
//
// We deliberately do NOT use TestEnv here: TestEnv constructs the full auth
// server with its own default in-memory stores, and this test specifically
// needs to reuse the same Store/KeyStore across two AppRegistrar instances.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAppRegistrar_PersistsAcrossRestart verifies that registrations created
// against one AppRegistrar are visible to a fresh AppRegistrar instance backed
// by the same store, and that deletions made through the first instance are
// also persisted (i.e., a revoked app does NOT come back after restart). This
// is the canonical regression test for the bug behind issue #20.
func TestAppRegistrar_PersistsAcrossRestart(t *testing.T) {
	store := admin.NewInMemoryAppStore()
	ks := keys.NewInMemoryKeyStore()

	// --- Phase 1: first AppRegistrar instance (the "before-restart" world).
	reg1 := admin.NewAppRegistrarWithStore(ks, admin.NewNoAuth(), store)
	srv1 := httptest.NewServer(reg1.Handler())
	defer srv1.Close()

	// Register two apps; we'll delete one and verify the other survives.
	keepID := registerApp(t, srv1.URL, "keep.example")
	revokeID := registerApp(t, srv1.URL, "revoke.example")

	// Sanity: both visible via the first instance.
	apps := listApps(t, srv1.URL)
	require.Len(t, apps, 2)

	// Revoke (delete) one app via the first instance.
	resp, err := http.NewRequest(http.MethodDelete, srv1.URL+"/apps/"+revokeID, nil)
	require.NoError(t, err)
	delResp, err := http.DefaultClient.Do(resp)
	require.NoError(t, err)
	delResp.Body.Close()
	require.Equal(t, http.StatusOK, delResp.StatusCode)

	srv1.Close()
	// reg1 is now garbage; cache is gone. Persistence must come from `store`.

	// --- Phase 2: fresh AppRegistrar instance over the same backing stores.
	reg2 := admin.NewAppRegistrarWithStore(ks, admin.NewNoAuth(), store)
	srv2 := httptest.NewServer(reg2.Handler())
	defer srv2.Close()

	apps2 := listApps(t, srv2.URL)
	if assert.Len(t, apps2, 1, "exactly the un-revoked app should survive restart") {
		assert.Equal(t, keepID, apps2[0]["client_id"], "kept app survived")
	}

	// The revoked app must NOT resurrect: GET /apps/{revokedID} returns 404.
	getResp, err := http.Get(srv2.URL + "/apps/" + revokeID)
	require.NoError(t, err)
	getResp.Body.Close()
	assert.Equal(t, http.StatusNotFound, getResp.StatusCode, "revoked app must not be resurrected on restart")

	// And the revoked app's signing key must be gone from the KeyStore too.
	if _, err := ks.GetKey(revokeID); err != keys.ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound for revoked app's signing key, got %v", err)
	}
}

func registerApp(t *testing.T, baseURL, domain string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"client_domain": domain, "signing_alg": "HS256"})
	resp, err := http.Post(baseURL+"/apps/register", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	raw, _ := io.ReadAll(resp.Body)
	var data map[string]any
	require.NoError(t, json.Unmarshal(raw, &data))
	return data["client_id"].(string)
}

func listApps(t *testing.T, baseURL string) []map[string]any {
	t.Helper()
	resp, err := http.Get(baseURL + "/apps")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var data struct {
		Apps []map[string]any `json:"apps"`
	}
	raw, _ := io.ReadAll(resp.Body)
	require.NoError(t, json.Unmarshal(raw, &data))
	return data.Apps
}
