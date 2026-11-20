package apiauth_test

// A protected resource with a path publishes its metadata at the path URL
// only (issue 523). RFC 9728 §3.1 builds that URL by inserting the
// well-known string before the path, and §3.3 says a document fetched from
// a well-known URL must name the resource that URL was built from. A
// client that falls back to the root builds it from the origin, so the
// path resource's document there is one the client must discard. The
// official Go SDK's client refuses it with "got metadata resource ...".
//
// See: https://www.rfc-editor.org/rfc/rfc9728#section-3.1
// See: https://www.rfc-editor.org/rfc/rfc9728#section-3.3

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
)

func prmStatus(t *testing.T, base, path string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(base + path)
	require.NoError(t, err)
	defer resp.Body.Close()
	body := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func TestMountProtectedResource_PathedResourceOnlyAtItsPathURL(t *testing.T) {
	mux := http.NewServeMux()
	apiauth.MountProtectedResource(mux, &apiauth.ProtectedResourceMetadata{
		Resource: "https://mcp.example/mcp", AuthorizationServers: []string{"https://as.example"},
	}, false, "/mcp")
	ts := httptest.NewServer(mux)
	defer ts.Close()

	status, body := prmStatus(t, ts.URL, "/.well-known/oauth-protected-resource/mcp")
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "https://mcp.example/mcp", body["resource"])

	status, _ = prmStatus(t, ts.URL, "/.well-known/oauth-protected-resource")
	assert.Equal(t, http.StatusNotFound, status, "the root URL names the origin, not /mcp")
}

func TestMountProtectedResource_ResourceWithoutAPathAtTheRoot(t *testing.T) {
	mux := http.NewServeMux()
	apiauth.MountProtectedResource(mux, &apiauth.ProtectedResourceMetadata{
		Resource: "https://rs.example", AuthorizationServers: []string{"https://as.example"},
	}, false)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	status, body := prmStatus(t, ts.URL, "/.well-known/oauth-protected-resource")
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "https://rs.example", body["resource"])
}
