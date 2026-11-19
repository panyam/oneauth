package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Known gaps that share an expiry date come out in the same order on
// every render. Sorting by expiry alone left ties in map order, so the
// committed docs/conformance/native.md reordered itself on each run.
func TestWriteReport_KnownGapsInAStableOrder(t *testing.T) {
	manifest := map[string]Entry{}
	for _, test := range []string{"m-e", "m-a", "m-d", "m-b", "m-c", "m-f", "m-h", "m-g"} {
		manifest["oidf::p::"+test] = Entry{Suite: "oidf", Plan: "p", Test: test, Status: "expected-fail", Issue: 1, Owner: "o", Reason: "r", Expires: "2027-12-31"}
	}
	manifest["as_metadata::TestZ"] = Entry{Suite: "as_metadata", ID: "TestZ", Status: "expected-fail", Issue: 2, Owner: "o", Reason: "r", Expires: "2027-12-31"}

	gaps := func() string {
		path := filepath.Join(t.TempDir(), "r.md")
		require.NoError(t, writeReport(path, "./...", nil, manifest, nil))
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		s := string(raw)
		return s[strings.Index(s, "## Known gaps"):]
	}
	first := gaps()
	for i := 0; i < 20; i++ {
		require.Equal(t, first, gaps(), "render %d differs", i)
	}
	assert.Less(t, strings.Index(first, "TestZ"), strings.Index(first, "p/m-a"), "ties sort by suite")
	assert.Less(t, strings.Index(first, "p/m-a"), strings.Index(first, "p/m-b"), "then by test")
}
