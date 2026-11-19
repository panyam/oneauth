package oidfplan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Each plan's server config accepts exactly the profile claims
// StandardProfile sends, or signup drops some of them and a claims module
// warns for the wrong reason.
func TestStandardProfile_MatchesTheServerConfigs(t *testing.T) {
	for _, name := range ProfileClaims {
		assert.NotEmpty(t, StandardProfile().Get(name), name)
	}
	for _, f := range []string{"oneauth-oidcc.yaml", "oneauth-fapi2.yaml"} {
		raw, err := os.ReadFile(filepath.Join("..", f))
		require.NoError(t, err)
		var cfg struct {
			Signup struct {
				ProfileClaims []string `yaml:"profile_claims"`
			} `yaml:"signup"`
		}
		require.NoError(t, yaml.Unmarshal(raw, &cfg))
		assert.Equal(t, ProfileClaims, cfg.Signup.ProfileClaims, f)
	}
}
