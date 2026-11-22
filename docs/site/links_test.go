package main

// Relative links in the rendered markdown (issue 557). A doc links to
// another file by its repo path, which works on GitHub and 404s on the
// site. The renderer points such a link at the page that renders the
// file, or at the file on GitHub.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewriteLink(t *testing.T) {
	pages := map[string]string{
		"docs/oauth/FAPI.md": "/oneauth/specs/fapi/",
		"docs/ROADMAP.md":    "/oneauth/design/roadmap/",
	}
	for _, tc := range []struct{ src, dest, want string }{
		{"docs/oauth/JARM.md", "FAPI.md", "/oneauth/specs/fapi/"},
		{"docs/oauth/JARM.md", "FAPI.md#wire-pattern", "/oneauth/specs/fapi/#wire-pattern"},
		{"docs/oauth/JARM.md", "../ROADMAP.md", "/oneauth/design/roadmap/"},
		{"docs/oauth/JARM.md", "../SECURITY_AUDIT.md", githubBlob + "docs/SECURITY_AUDIT.md"},
		{"docs/CLIENT_SDK.md", "../cmd/oneauth/", githubBlob + "cmd/oneauth"},
		{"docs/oauth/JARM.md", "https://openid.net/specs/oauth-v2-jarm.html", "https://openid.net/specs/oauth-v2-jarm.html"},
		{"docs/oauth/JARM.md", "#key-concepts", "#key-concepts"},
		{"docs/oauth/JARM.md", "/oneauth/specs/", "/oneauth/specs/"},
		{"docs/oauth/JARM.md", "mailto:x@example.com", "mailto:x@example.com"},
		{"docs/oauth/JARM.md", "NO_SUCH_FILE.md", "NO_SUCH_FILE.md"},
		{"docs/oauth/JARM.md", "../../../outside.md", "../../../outside.md"},
	} {
		assert.Equal(t, tc.want, rewriteLink(tc.src, tc.dest, pages), "%s -> %s", tc.src, tc.dest)
	}
}

func TestPagesForSources(t *testing.T) {
	pages := pagesForSources("./content", "/oneauth")
	assert.Equal(t, "/oneauth/specs/jarm/", pages["docs/oauth/JARM.md"])
	assert.Equal(t, "/oneauth/guides/client-sdk/", pages["docs/CLIENT_SDK.md"])
}

var relativeMDHref = regexp.MustCompile(`href="[^"#:/][^"#:]*\.md(#[^"]*)?"`)

// Every page's markdown renders with no relative .md link left.
func TestRenderedPagesHaveNoRelativeMarkdownLinks(t *testing.T) {
	var checked int
	err := filepath.Walk("./content", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range renderCall.FindAllSubmatch(body, -1) {
			out := string(renderMarkdownFile(string(m[1])))
			assert.Empty(t, relativeMDHref.FindAllString(out, 5), "%s (%s)", path, m[1])
			checked++
		}
		return nil
	})
	require.NoError(t, err)
	assert.Greater(t, checked, 40)
}
