package e2e_test

// Full-stack security tests — auth bypass, token revocation, oversized body, concurrency.
//
// References:
//   - RFC 6750 (https://datatracker.ietf.org/doc/html/rfc6750): Bearer Token Usage
//   - CWE-400 (https://cwe.mitre.org/data/definitions/400.html): Resource Consumption
//   - CWE-613 (https://cwe.mitre.org/data/definitions/613.html): Insufficient Session Expiration

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Auth Bypass
// =============================================================================

// TestSecurity_NoAuth_401 verifies protected endpoints reject missing auth.
//
// See: https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
func TestSecurity_NoAuth_401(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)
	resp := c.NoAuthGet("/apps")
	assert.Equal(t, 401, resp.StatusCode)
}

// TestSecurity_MalformedBearer verifies malformed tokens return 401, not 500.
//
// See: https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
func TestSecurity_MalformedBearer(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)

	malformed := []string{
		"not-a-jwt",
		"eyJ.eyJ.invalid",
		strings.Repeat("A", 500),
	}
	for _, token := range malformed {
		resp := c.BearerGet("/api/me", token)
		if resp != nil {
			label := token
			if len(label) > 20 {
				label = label[:20] + "..."
			}
			assert.True(t, resp.StatusCode == 401 || resp.StatusCode == 403,
				"malformed token %q got %d, expected 401/403", label, resp.StatusCode)
			resp.Body.Close()
		}
	}
}

// TestSecurity_TamperedSignature verifies that a JWT with a garbage signature
// returns 401 (not 500 from an unhandled parse error).
func TestSecurity_TamperedSignature(t *testing.T) {
	env := NewTestEnv(t)
	email, password := CreateTestUser(t, env, "tamper")
	access, _ := LoginForTokens(t, env, email, password)
	c := NewTestClient(env)

	// Replace signature with garbage
	parts := strings.SplitN(access, ".", 3)
	require.Len(t, parts, 3)
	tampered := parts[0] + "." + parts[1] + ".AAAA_garbage_signature_BBBB"

	resp := c.BearerGet("/api/me", tampered)
	assert.Equal(t, 401, resp.StatusCode)
}

// =============================================================================
// Token Blacklist
// =============================================================================

// TestSecurity_RevokedToken_Rejected verifies that POST /api/revoke makes
// the access token immediately unusable.
//
// See: https://cwe.mitre.org/data/definitions/613.html
func TestSecurity_RevokedToken_Rejected(t *testing.T) {
	env := NewTestEnv(t)
	email, password := CreateTestUser(t, env, "revoke")
	access, _ := LoginForTokens(t, env, email, password)
	c := NewTestClient(env)

	// Works before revocation
	resp := c.BearerGet("/api/me", access)
	assert.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// Revoke
	resp = c.BearerPost("/api/revoke", access, nil)
	assert.Equal(t, 204, resp.StatusCode)
	resp.Body.Close()

	// Rejected after revocation
	resp = c.BearerGet("/api/me", access)
	assert.Equal(t, 401, resp.StatusCode)
	resp.Body.Close()
}

// TestSecurity_AccessTokenNotUsableAsRefresh verifies type confusion prevention.
//
// See: https://cwe.mitre.org/data/definitions/269.html
func TestSecurity_AccessTokenNotUsableAsRefresh(t *testing.T) {
	env := NewTestEnv(t)
	email, password := CreateTestUser(t, env, "type-confuse")
	access, _ := LoginForTokens(t, env, email, password)
	c := NewTestClient(env)

	resp := c.PostJSON("/api/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": access, // wrong token type
	})
	assert.Equal(t, 401, resp.StatusCode)
}

// =============================================================================
// Oversized Body (DoS prevention)
// =============================================================================

// TestSecurity_OversizedBody verifies that a 10MB body to /apps/register
// is rejected (413 or 400), not accepted.
//
// See: https://cwe.mitre.org/data/definitions/400.html
func TestSecurity_OversizedBody(t *testing.T) {
	env := NewTestEnv(t)
	largeBody := `{"client_domain":"` + strings.Repeat("x", 10*1024*1024) + `"}`

	req, _ := http.NewRequest("POST", env.BaseURL()+"/apps/register",
		strings.NewReader(largeBody))
	req.Header.Set("X-Admin-Key", env.AdminKey)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(largeBody))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.True(t, resp.StatusCode == 400 || resp.StatusCode == 413,
		"oversized body got %d, expected 400/413", resp.StatusCode)
}

// =============================================================================
// Concurrency
// =============================================================================

// TestSecurity_ConcurrentRequests_No500 verifies no 500s under concurrent load.
func TestSecurity_ConcurrentRequests_No500(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var statuses []int

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := c.Get("/apps")
			mu.Lock()
			statuses = append(statuses, resp.StatusCode)
			mu.Unlock()
			resp.Body.Close()
		}()
	}
	wg.Wait()

	for _, code := range statuses {
		assert.NotEqual(t, 500, code, "got 500 under concurrent load")
	}
}
