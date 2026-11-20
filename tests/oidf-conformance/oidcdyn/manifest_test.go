package oidcdyn

import (
	"path/filepath"
	"testing"

	"github.com/panyam/oneauth/tests/oidf-conformance/oidfplan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The real manifest loads for each run, and each REVIEW module has a
// browser override that fills the screenshot, so it can end in REVIEW.
func TestLoadExpectations_RepositoryManifest(t *testing.T) {
	keys := []string{DynamicPlanName}
	for _, a := range TestPlanAuthTypes {
		keys = append(keys, TestPlanKey(a))
	}
	for _, rt := range DynamicImplicitResponseTypes {
		keys = append(keys, DynamicImplicitPlanKey(rt))
	}
	for _, k := range keys {
		got, err := oidfplan.LoadExpectations(filepath.Join("..", "..", "conformance", "known-gaps.yaml"), k)
		require.NoError(t, err, k)
		assert.NotEmpty(t, got, k)
		for _, e := range got {
			if e.Status == oidfplan.StatusExpectedReview {
				assert.Contains(t, ModuleBrowsers(testSetup()), e.Module, "%s: a REVIEW module needs a browser override", k)
			}
		}
	}
}
