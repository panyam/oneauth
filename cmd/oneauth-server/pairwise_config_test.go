package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// code_flow.pairwise_salt turns on pairwise subjects (issue 507). Discovery
// lists pairwise only with a salt, and a short salt stops the server.
func TestPairwiseSaltConfig(t *testing.T) {
	load := func(salt string) (*Config, error) {
		path := filepath.Join(t.TempDir(), "c.yaml")
		require.NoError(t, os.WriteFile(path, []byte("code_flow:\n  enabled: true\n  oidc: true\n  pairwise_salt: \""+salt+"\"\n"), 0o600))
		return LoadConfig(path)
	}
	_, err := load("too-short")
	assert.ErrorContains(t, err, "pairwise_salt")

	cfg, err := load("a-pairwise-salt-that-is-32-bytes-long!")
	require.NoError(t, err)
	assert.Equal(t, []string{"public", "pairwise"}, serverASMetadata(cfg, "https://as.example", true).SubjectTypesSupported)

	cfg, err = load("")
	require.NoError(t, err)
	assert.Equal(t, []string{"public"}, serverASMetadata(cfg, "https://as.example", true).SubjectTypesSupported)
}
