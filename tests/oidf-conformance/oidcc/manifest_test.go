package oidcc

import (
	"path/filepath"
	"testing"

	"github.com/panyam/oneauth/tests/oidf-conformance/oidfplan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The real manifest loads for this plan, and each REVIEW module has a
// browser override that fills the screenshot, so it can actually end in
// REVIEW.
func TestLoadExpectations_RepositoryManifest(t *testing.T) {
	got, err := oidfplan.LoadExpectations(filepath.Join("..", "..", "conformance", "known-gaps.yaml"), PlanName)
	require.NoError(t, err)
	assert.Len(t, got, 6)
	for _, e := range got {
		if e.Status == oidfplan.StatusExpectedReview {
			assert.Contains(t, ModuleBrowsers(testSetup()), e.Module, "a REVIEW module needs a browser override")
		}
	}
}

// The Form Post plan shares the Basic OP entries, plus one for the
// request-object module (issue 500).
func TestLoadExpectations_FormPostManifest(t *testing.T) {
	got, err := oidfplan.LoadExpectations(filepath.Join("..", "..", "conformance", "known-gaps.yaml"), FormPostPlanName)
	require.NoError(t, err)
	assert.Len(t, got, 6)
	for _, e := range got {
		if e.Status == oidfplan.StatusExpectedReview {
			assert.Contains(t, ModuleBrowsers(testSetup()), e.Module, "a REVIEW module needs a browser override")
		}
	}
}
