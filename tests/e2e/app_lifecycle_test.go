package e2e_test

// App registration lifecycle — register, get, list, rotate, delete.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppLifecycle_Register(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)

	resp := c.PostJSON("/apps/register", map[string]any{
		"client_domain": "lifecycle-test.example.com",
		"signing_alg":   "HS256",
	})
	require.Equal(t, 201, resp.StatusCode)

	data := ReadJSON(resp)
	assert.NotEmpty(t, data["client_id"])
	assert.NotEmpty(t, data["client_secret"])
	assert.Equal(t, "HS256", data["signing_alg"])

	// Cleanup
	c.Delete("/apps/" + data["client_id"].(string))
}

func TestAppLifecycle_RegisterDefaultAlg(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)

	resp := c.PostJSON("/apps/register", map[string]any{
		"client_domain": "default-alg.example.com",
	})
	require.Equal(t, 201, resp.StatusCode)
	data := ReadJSON(resp)
	assert.Equal(t, "HS256", data["signing_alg"])
	c.Delete("/apps/" + data["client_id"].(string))
}

func TestAppLifecycle_GetApp(t *testing.T) {
	env := NewTestEnv(t)
	clientID, _ := RegisterApp(t, env, "get-test.example.com")
	c := NewTestClient(env)

	resp := c.Get("/apps/" + clientID)
	assert.Equal(t, 200, resp.StatusCode)
	data := ReadJSON(resp)
	assert.Equal(t, clientID, data["client_id"])

	c.Delete("/apps/" + clientID)
}

func TestAppLifecycle_GetApp_NotFound(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)

	resp := c.Get("/apps/nonexistent")
	assert.Equal(t, 404, resp.StatusCode)
}

func TestAppLifecycle_ListApps(t *testing.T) {
	env := NewTestEnv(t)
	clientID, _ := RegisterApp(t, env, "list-test.example.com")
	c := NewTestClient(env)

	resp := c.Get("/apps")
	assert.Equal(t, 200, resp.StatusCode)
	data := ReadJSON(resp)
	apps := data["apps"].([]any)
	assert.GreaterOrEqual(t, len(apps), 1)

	c.Delete("/apps/" + clientID)
}

func TestAppLifecycle_RotateSecret(t *testing.T) {
	env := NewTestEnv(t)
	clientID, oldSecret := RegisterApp(t, env, "rotate-test.example.com")
	c := NewTestClient(env)

	resp := c.PostJSON("/apps/"+clientID+"/rotate", nil)
	assert.Equal(t, 200, resp.StatusCode)
	data := ReadJSON(resp)
	newSecret := data["client_secret"].(string)
	assert.NotEqual(t, oldSecret, newSecret)

	c.Delete("/apps/" + clientID)
}

func TestAppLifecycle_Delete(t *testing.T) {
	env := NewTestEnv(t)
	clientID, _ := RegisterApp(t, env, "delete-test.example.com")
	c := NewTestClient(env)

	resp := c.Delete("/apps/" + clientID)
	assert.Equal(t, 200, resp.StatusCode)

	resp = c.Get("/apps/" + clientID)
	assert.Equal(t, 404, resp.StatusCode)
}

func TestAppLifecycle_Delete_NotFound(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)

	resp := c.Delete("/apps/nonexistent")
	assert.Equal(t, 404, resp.StatusCode)
}
