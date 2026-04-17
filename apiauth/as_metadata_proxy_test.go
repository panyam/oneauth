package apiauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestASMetadataProxy_FetchesFromOIDC verifies that the proxy fetches AS
// metadata from the OIDC discovery endpoint when RFC 8414 is not available
// (the common case for Keycloak and similar OIDC-only providers).
func TestASMetadataProxy_FetchesFromOIDC(t *testing.T) {
	// Mock an OIDC-only AS (serves /.well-known/openid-configuration, not RFC 8414)
	asMux := http.NewServeMux()
	asMux.HandleFunc("/realms/test/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "http://mock-as/realms/test",
			"authorization_endpoint": "http://mock-as/realms/test/protocol/openid-connect/auth",
			"token_endpoint":         "http://mock-as/realms/test/protocol/openid-connect/token",
			"jwks_uri":               "http://mock-as/realms/test/protocol/openid-connect/certs",
		})
	})
	as := httptest.NewServer(asMux)
	defer as.Close()

	proxy := NewASMetadataProxy(as.URL+"/realms/test", 0)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var meta map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if meta["authorization_endpoint"] == nil {
		t.Error("missing authorization_endpoint")
	}
	if meta["token_endpoint"] == nil {
		t.Error("missing token_endpoint")
	}
}

// TestASMetadataProxy_PrefersRFC8414 verifies that the proxy tries RFC 8414
// first and uses it when available.
func TestASMetadataProxy_PrefersRFC8414(t *testing.T) {
	asMux := http.NewServeMux()
	// Serve at RFC 8414 path
	asMux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":         "http://mock-as",
			"token_endpoint": "http://mock-as/token",
			"source":         "rfc8414",
		})
	})
	as := httptest.NewServer(asMux)
	defer as.Close()

	proxy := NewASMetadataProxy(as.URL, 0)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var meta map[string]any
	json.Unmarshal(rec.Body.Bytes(), &meta)
	if meta["source"] != "rfc8414" {
		t.Errorf("expected rfc8414 source, got %v", meta["source"])
	}
}

// TestASMetadataProxy_CachesResponse verifies that the proxy caches the
// fetched metadata and doesn't hit the AS on every request.
func TestASMetadataProxy_CachesResponse(t *testing.T) {
	hits := 0
	asMux := http.NewServeMux()
	asMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		hits++
		json.NewEncoder(w).Encode(map[string]any{"issuer": "http://mock", "hits": hits})
	})
	as := httptest.NewServer(asMux)
	defer as.Close()

	proxy := NewASMetadataProxy(as.URL, 0)

	// First request — fetches
	rec1 := httptest.NewRecorder()
	proxy.ServeHTTP(rec1, httptest.NewRequest("GET", "/", nil))
	if rec1.Code != 200 {
		t.Fatalf("first request: status = %d", rec1.Code)
	}

	// Second request — should use cache
	rec2 := httptest.NewRecorder()
	proxy.ServeHTTP(rec2, httptest.NewRequest("GET", "/", nil))
	if rec2.Code != 200 {
		t.Fatalf("second request: status = %d", rec2.Code)
	}

	if hits != 1 {
		t.Errorf("expected 1 fetch, got %d (caching not working)", hits)
	}
}

// TestASMetadataProxy_MethodNotAllowed verifies that non-GET requests
// are rejected with 405.
func TestASMetadataProxy_MethodNotAllowed(t *testing.T) {
	proxy := NewASMetadataProxy("http://example.com", 0)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest("POST", "/", nil))
	if rec.Code != 405 {
		t.Errorf("POST status = %d, want 405", rec.Code)
	}
}

// TestASMetadataProxy_ASUnreachable verifies that the proxy returns 502
// when the AS is not reachable.
func TestASMetadataProxy_ASUnreachable(t *testing.T) {
	proxy := NewASMetadataProxy("http://localhost:1/nonexistent", 0)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 502 {
		t.Errorf("unreachable AS: status = %d, want 502", rec.Code)
	}
}

// TestMountProtectedResource_WithProxy verifies that MountProtectedResource
// mounts both the PRM endpoint and the RFC 8414 AS metadata proxy.
func TestMountProtectedResource_WithProxy(t *testing.T) {
	// Mock OIDC-only AS
	asMux := http.NewServeMux()
	asMux.HandleFunc("/realms/test/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "http://mock-as/realms/test",
			"authorization_endpoint": "http://mock-as/realms/test/authorize",
			"token_endpoint":         "http://mock-as/realms/test/token",
		})
	})
	as := httptest.NewServer(asMux)
	defer as.Close()

	// Mount on resource server
	mux := http.NewServeMux()
	MountProtectedResource(mux, &ProtectedResourceMetadata{
		Resource:             "http://resource-server",
		AuthorizationServers: []string{as.URL + "/realms/test"},
	}, true)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 1. PRM should be served
	resp, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("PRM status = %d, want 200", resp.StatusCode)
	}
	var prm map[string]any
	json.NewDecoder(resp.Body).Decode(&prm)
	if prm["resource"] != "http://resource-server" {
		t.Errorf("PRM resource = %v", prm["resource"])
	}

	// 2. RFC 8414 proxy should serve AS metadata (path-based)
	resp2, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server/realms/test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Errorf("RFC 8414 proxy status = %d, want 200", resp2.StatusCode)
	}
	var asMeta map[string]any
	json.NewDecoder(resp2.Body).Decode(&asMeta)
	if asMeta["authorization_endpoint"] == nil {
		t.Error("RFC 8414 proxy missing authorization_endpoint")
	}

	// 3. RFC 8414 at simple path should also work
	resp3, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != 200 {
		t.Errorf("RFC 8414 simple path status = %d, want 200", resp3.StatusCode)
	}
}

// TestMountProtectedResource_WithoutProxy verifies that when proxyASMetadata
// is false, only the PRM endpoint is mounted (backward compatible).
func TestMountProtectedResource_WithoutProxy(t *testing.T) {
	mux := http.NewServeMux()
	MountProtectedResource(mux, &ProtectedResourceMetadata{
		Resource:             "http://resource-server",
		AuthorizationServers: []string{"http://example.com"},
	}, false)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// PRM works
	resp, _ := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
	if resp.StatusCode != 200 {
		t.Errorf("PRM status = %d", resp.StatusCode)
	}

	// RFC 8414 not mounted
	resp2, _ := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if resp2.StatusCode != 404 {
		t.Errorf("RFC 8414 should not be mounted, got %d", resp2.StatusCode)
	}
}

// TestBuildASDiscoveryURLs verifies that discovery URLs are constructed
// correctly for both simple and path-based issuer URLs.
func TestBuildASDiscoveryURLs(t *testing.T) {
	tests := []struct {
		issuer string
		want   []string
	}{
		{
			"https://auth.example.com",
			[]string{
				"https://auth.example.com/.well-known/oauth-authorization-server",
				"https://auth.example.com/.well-known/openid-configuration",
			},
		},
		{
			"https://auth.example.com/realms/foo",
			[]string{
				"https://auth.example.com/.well-known/oauth-authorization-server/realms/foo",
				"https://auth.example.com/realms/foo/.well-known/openid-configuration",
			},
		},
	}

	for _, tt := range tests {
		got := buildASDiscoveryURLs(tt.issuer)
		if len(got) != len(tt.want) {
			t.Errorf("buildASDiscoveryURLs(%q): got %d URLs, want %d", tt.issuer, len(got), len(tt.want))
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("buildASDiscoveryURLs(%q)[%d] = %q, want %q", tt.issuer, i, got[i], tt.want[i])
			}
		}
	}
}
