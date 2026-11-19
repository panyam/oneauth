package fapi2

import (
	"path/filepath"
	"testing"

	"github.com/panyam/oneauth/tests/oidf-conformance/oidfplan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The real manifest has to load, and every entry has to name a module this
// plan's config knows how to drive.
func TestLoadExpectations_RepositoryManifest(t *testing.T) {
	got, err := oidfplan.LoadExpectations(filepath.Join("..", "..", "conformance", "known-gaps.yaml"), PlanName)
	require.NoError(t, err)
	assert.Equal(t, oidfplan.StatusExpectedSkip, got["fapi2-security-profile-final-ensure-signed-client-assertion-with-RS256-fails"].Status)
	reviews := 0
	for _, e := range got {
		if e.Status == oidfplan.StatusExpectedReview {
			reviews++
			assert.Contains(t, ModuleBrowsers(testSetup(t)), e.Module, "a REVIEW module needs an error-page browser override")
		}
	}
	assert.Equal(t, 4, reviews)
}
