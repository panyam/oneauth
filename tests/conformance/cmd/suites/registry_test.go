package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	repoRegistry = filepath.Join("..", "..", "..", "..", "conformance", "suites.yaml")
	repoMakefile = filepath.Join("..", "..", "..", "..", "conformance", "Makefile")
)

// The checked-in registry and conformance/Makefile agree: every conf-*
// target has an entry and every entry has a target. This is the drift
// check `make test` runs.
func TestRegistry_MatchesTheMakefile(t *testing.T) {
	reg, err := LoadRegistry(repoRegistry)
	require.NoError(t, err)
	targets, err := MakeTargets(repoMakefile)
	require.NoError(t, err)
	assert.Empty(t, reg.Validate(), "registry problems")
	assert.Empty(t, Drift(reg, targets), "registry and Makefile disagree")
	assert.NotEmpty(t, reg.Suites)
}

func TestDrift_ReportsBothDirections(t *testing.T) {
	reg := &Registry{Suites: []Suite{{Name: "a", Kind: KindGating, Covers: "x"}, {Name: "b", Kind: KindInfo, Covers: "y"}}}
	got := Drift(reg, []string{"conf-a", "conf-c"})
	assert.Len(t, got, 2)
	assert.Contains(t, strings.Join(got, "\n"), "conf-c has no entry")
	assert.Contains(t, strings.Join(got, "\n"), `suite "b" has no conf-b target`)
}

func TestValidate_RejectsBadEntries(t *testing.T) {
	reg := &Registry{Suites: []Suite{
		{Name: "a", Kind: KindGating, Covers: "x"},
		{Name: "a", Kind: KindGating, Covers: "x"},
		{Name: "b", Kind: "sometimes", Covers: "x"},
		{Name: "c", Kind: KindInfo},
		{Name: "Bad Name", Kind: KindInfo, Covers: "x"},
		{Name: "d", Kind: KindInfo, Covers: "x", Needs: []string{"env:"}},
	}}
	problems := strings.Join(reg.Validate(), "\n")
	assert.Contains(t, problems, `"a" appears twice`)
	assert.Contains(t, problems, `"b": kind must be gating, info or manual`)
	assert.Contains(t, problems, `"c": covers is empty`)
	assert.Contains(t, problems, `"Bad Name": name must be lower-case`)
	assert.Contains(t, problems, `"d": need "env:" names no variable`)
}

func TestMakeTargets_ReadsConfTargets(t *testing.T) {
	targets, err := MakeTargets(repoMakefile)
	require.NoError(t, err)
	assert.Contains(t, targets, "conf-native")
	assert.NotContains(t, targets, "test", "only conf-* targets are suites")
}
