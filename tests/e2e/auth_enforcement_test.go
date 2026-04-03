package e2e_test

// Admin auth enforcement — verifies no key → 401, wrong key → 403, correct key → 200.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthEnforcement_NoKey_401(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)

	resp := c.NoAuthGet("/apps")
	assert.Equal(t, 401, resp.StatusCode)
}

func TestAuthEnforcement_WrongKey_403(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)

	resp := c.BadKeyGet("/apps")
	assert.Equal(t, 403, resp.StatusCode)
}

func TestAuthEnforcement_ValidKey_200(t *testing.T) {
	env := NewTestEnv(t)
	c := NewTestClient(env)

	resp := c.Get("/apps")
	assert.Equal(t, 200, resp.StatusCode)
	data := ReadJSON(resp)
	assert.Contains(t, data, "apps")
}
