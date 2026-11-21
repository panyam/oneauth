// Package devservices checks docker-compose.yml against the root Makefile
// (issue 243). The Makefile exports each service's settings and compose
// reads them, with defaults for a bare `docker compose up`. Every default
// must equal the Makefile's value, and every variable must be exported, or
// the two start different containers.
package devservices

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	composeVar  = regexp.MustCompile(`\$\{(\w+):-([^}]*)\}`)
	makefileVar = regexp.MustCompile(`(?m)^(\w+)\s*:?=\s*(.*?)\s*$`)
	exportLine  = regexp.MustCompile(`(?m)^export\s+((?:[^\n]*\\\n)*[^\n]*)$`)
)

// Compose-only settings with no Makefile counterpart.
var composeOnly = map[string]bool{"ONEAUTH_COMPOSE_PROJECT": true}

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", rel))
	require.NoError(t, err)
	return string(b)
}

func TestComposeDefaultsMatchTheMakefile(t *testing.T) {
	compose := read(t, "docker-compose.yml")
	makefile := read(t, "Makefile")

	values := map[string]string{}
	for _, m := range makefileVar.FindAllStringSubmatch(makefile, -1) {
		if _, seen := values[m[1]]; !seen {
			values[m[1]] = m[2]
		}
	}
	exported := map[string]bool{}
	for _, m := range exportLine.FindAllStringSubmatch(makefile, -1) {
		for _, name := range strings.Fields(strings.ReplaceAll(m[1], "\\", " ")) {
			exported[name] = true
		}
	}

	uses := composeVar.FindAllStringSubmatch(compose, -1)
	require.NotEmpty(t, uses, "docker-compose.yml has no ${VAR:-default} settings")
	for _, m := range uses {
		name, def := m[1], m[2]
		if composeOnly[name] {
			continue
		}
		got, ok := values[name]
		if assert.Truef(t, ok, "docker-compose.yml reads %s, and the Makefile doesn't set it", name) {
			assert.Equalf(t, got, def, "docker-compose.yml's default for %s differs from the Makefile's", name)
		}
		assert.Truef(t, exported[name], "the Makefile doesn't export %s, so compose won't see an override", name)
	}
}
