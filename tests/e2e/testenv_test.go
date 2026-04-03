package e2e_test

// TestEnv provides an in-process multi-server test environment.
// All servers run via httptest.NewServer — no subprocess management,
// no port conflicts, race detector works across all servers.
//
// Two modes:
//   - In-process (default): starts auth + resource servers in-process
//   - Remote: TEST_BASE_URL=https://... for deployed server testing (e.g., GAE)

import (
	"net/http/httptest"
	"os"
	"testing"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/localauth"
)

const (
	testAdminKey  = "e2e-test-admin-key"
	testJWTSecret = "e2e-test-jwt-secret-32chars-min!"
	testJWTIssuer = "oneauth-e2e"
)

// TestEnv holds all servers and shared state for e2e tests.
type TestEnv struct {
	// Servers (nil in remote mode)
	AuthServer      *httptest.Server
	ResourceServerA *httptest.Server
	ResourceServerB *httptest.Server

	// Config
	AdminKey  string
	JWTSecret string

	// Shared state (accessible for direct manipulation in tests)
	KeyStore  keys.KeyStorage
	Blacklist *core.InMemoryBlacklist

	// Internal
	apiAuth    *apiauth.APIAuth
	registrar  *admin.AppRegistrar
	localAuth  *localauth.LocalAuth
	remoteMode bool
	remoteURL  string
}

// NewTestEnv creates a full test environment with auth + resource servers.
// If TEST_BASE_URL is set, uses remote mode (no in-process servers).
func NewTestEnv(t *testing.T) *TestEnv {
	t.Helper()

	if url := os.Getenv("TEST_BASE_URL"); url != "" {
		return &TestEnv{
			remoteMode: true,
			remoteURL:  url,
			AdminKey:   os.Getenv("TEST_ADMIN_KEY"),
			JWTSecret:  os.Getenv("TEST_JWT_SECRET"),
		}
	}

	env := &TestEnv{
		AdminKey:  testAdminKey,
		JWTSecret: testJWTSecret,
	}
	env.buildAuthServer(t)
	env.buildResourceServers(t)
	return env
}

// BaseURL returns the auth server URL.
func (e *TestEnv) BaseURL() string {
	if e.remoteMode {
		return e.remoteURL
	}
	return e.AuthServer.URL
}

// ResourceAURL returns resource server A's URL.
func (e *TestEnv) ResourceAURL() string {
	if e.ResourceServerA == nil {
		return ""
	}
	return e.ResourceServerA.URL
}

// ResourceBURL returns resource server B's URL.
func (e *TestEnv) ResourceBURL() string {
	if e.ResourceServerB == nil {
		return ""
	}
	return e.ResourceServerB.URL
}

// IsRemote returns true if testing against a remote server.
func (e *TestEnv) IsRemote() bool {
	return e.remoteMode
}
