package e2e_test

// Shared HTTP helpers for e2e tests: client wrappers, CSRF flow,
// user creation, JWT helpers.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// userCounter provides unique, predictable email addresses across tests.
var userCounter atomic.Int64

// TestClient wraps http.Client with helpers for auth server requests.
type TestClient struct {
	BaseURL  string
	AdminKey string
	client   *http.Client
}

// NewTestClient creates a client for the given test environment.
func NewTestClient(env *TestEnv) *TestClient {
	jar, _ := cookiejar.New(nil)
	return &TestClient{
		BaseURL:  env.BaseURL(),
		AdminKey: env.AdminKey,
		client:   &http.Client{Jar: jar},
	}
}

// Get sends a GET with admin key.
func (c *TestClient) Get(path string) *http.Response {
	req, _ := http.NewRequest("GET", c.BaseURL+path, nil)
	req.Header.Set("X-Admin-Key", c.AdminKey)
	resp, _ := c.client.Do(req)
	return resp
}

// PostJSON sends a POST with admin key and JSON body.
func (c *TestClient) PostJSON(path string, body any) *http.Response {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", c.BaseURL+path, strings.NewReader(string(data)))
	req.Header.Set("X-Admin-Key", c.AdminKey)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := c.client.Do(req)
	return resp
}

// Delete sends a DELETE with admin key.
func (c *TestClient) Delete(path string) *http.Response {
	req, _ := http.NewRequest("DELETE", c.BaseURL+path, nil)
	req.Header.Set("X-Admin-Key", c.AdminKey)
	resp, _ := c.client.Do(req)
	return resp
}

// NoAuthGet sends a GET without any auth headers.
func (c *TestClient) NoAuthGet(path string) *http.Response {
	resp, _ := http.Get(c.BaseURL + path)
	return resp
}

// BadKeyGet sends a GET with a wrong admin key.
func (c *TestClient) BadKeyGet(path string) *http.Response {
	req, _ := http.NewRequest("GET", c.BaseURL+path, nil)
	req.Header.Set("X-Admin-Key", "wrong-key")
	resp, _ := c.client.Do(req)
	return resp
}

// BearerGet sends a GET with an Authorization: Bearer header.
// Returns nil if the request fails (e.g., connection error from huge tokens).
func (c *TestClient) BearerGet(path, token string) *http.Response {
	req, err := http.NewRequest("GET", c.BaseURL+path, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	return resp
}

// BearerPost sends a POST with an Authorization: Bearer header and JSON body.
func (c *TestClient) BearerPost(path, token string, body any) *http.Response {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", c.BaseURL+path, strings.NewReader(string(data)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := c.client.Do(req)
	return resp
}

// ReadJSON reads and decodes the response body as JSON.
func ReadJSON(resp *http.Response) map[string]any {
	defer resp.Body.Close()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

// ReadBody reads the raw response body as a string.
func ReadBody(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// =============================================================================
// User creation helpers
// =============================================================================

// CreateTestUser signs up a user via the CSRF-protected signup flow
// and returns their email and password.
func CreateTestUser(t *testing.T, env *TestEnv, emailPrefix string) (email, password string) {
	t.Helper()
	n := userCounter.Add(1)
	email = fmt.Sprintf("%s-%d@example.com", emailPrefix, n)
	password = "testpassword123"

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// GET signup to get CSRF cookie
	resp, err := client.Get(env.BaseURL() + "/auth/signup")
	require.NoError(t, err)
	resp.Body.Close()

	// Extract CSRF token from cookie
	u, _ := url.Parse(env.BaseURL())
	var csrfToken string
	for _, c := range jar.Cookies(u) {
		if c.Name == "csrf_token" {
			csrfToken = c.Value
			break
		}
	}
	require.NotEmpty(t, csrfToken, "CSRF token cookie should be set")

	// POST signup with CSRF token
	resp, err = client.PostForm(env.BaseURL()+"/auth/signup", url.Values{
		"email":      {email},
		"password":   {password},
		"csrf_token": {csrfToken},
	})
	require.NoError(t, err)
	require.True(t, resp.StatusCode >= 200 && resp.StatusCode < 400,
		"signup failed with status %d: %s", resp.StatusCode, ReadBody(resp))
	resp.Body.Close()

	return email, password
}

// LoginForTokens logs in via the API token endpoint and returns the token pair.
func LoginForTokens(t *testing.T, env *TestEnv, email, password string) (accessToken, refreshToken string) {
	t.Helper()
	c := NewTestClient(env)
	resp := c.PostJSON("/api/token", map[string]any{
		"grant_type": "password",
		"username":   email,
		"password":   password,
	})
	data := ReadJSON(resp)
	require.Equal(t, 200, resp.StatusCode, "login failed")
	return data["access_token"].(string), data["refresh_token"].(string)
}

// RegisterApp registers an HS256 app and returns client_id and client_secret.
func RegisterApp(t *testing.T, env *TestEnv, domain string) (clientID, clientSecret string) {
	t.Helper()
	c := NewTestClient(env)
	resp := c.PostJSON("/apps/register", map[string]any{
		"client_domain": domain,
		"signing_alg":   "HS256",
	})
	data := ReadJSON(resp)
	require.Equal(t, 201, resp.StatusCode, "app registration failed")
	require.NotNil(t, data["client_id"], "missing client_id in response")
	require.NotNil(t, data["client_secret"], "missing client_secret in response")
	return data["client_id"].(string), data["client_secret"].(string)
}
