package e2e_test

// Health check and basic connectivity tests.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHealth(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)

	resp := c.NoAuthGet("/_ah/health")
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "ok", ReadBody(resp))
}

func TestResourceServerHealth(t *testing.T) {
	env := NewTestEnv(t)

	if env.ResourceAURL() == "" {
		t.Skip("resource servers not available")
	}

	resp, err := env.AuthServer.Client().Get(env.ResourceAURL() + "/health")
	assert.NoError(t, err)
	data := ReadJSON(resp)
	assert.Equal(t, "ok", data["status"])
}
