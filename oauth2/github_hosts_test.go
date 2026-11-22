// Tests for GitHubHostsFor, which maps a GitHub REST API root to its web
// host and OAuth endpoints (issue 554).
package oauth2_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	oauth2lib "golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"github.com/panyam/oneauth/oauth2"
)

func TestGitHubHostsFor(t *testing.T) {
	dotCom := oauth2.GitHubHosts{
		Web:         "https://github.com",
		API:         "https://api.github.com",
		Endpoint:    github.Endpoint,
		UserInfoURL: "https://api.github.com/user",
	}
	on := func(web, api string) oauth2.GitHubHosts {
		return oauth2.GitHubHosts{
			Web: web,
			API: api,
			Endpoint: oauth2lib.Endpoint{
				AuthURL:       web + "/login/oauth/authorize",
				TokenURL:      web + "/login/oauth/access_token",
				DeviceAuthURL: web + "/login/device/code",
			},
			UserInfoURL: api + "/user",
		}
	}

	for api, want := range map[string]oauth2.GitHubHosts{
		"":                                    dotCom,
		"https://api.github.com":              dotCom,
		"https://api.github.com/":             dotCom,
		"https://API.GitHub.com":              dotCom,
		"https://ghe.example.com/api/v3":      on("https://ghe.example.com", "https://ghe.example.com/api/v3"),
		"https://ghe.example.com/api/v3/":     on("https://ghe.example.com", "https://ghe.example.com/api/v3"),
		"https://GHE.example.com/api/v3":      on("https://ghe.example.com", "https://ghe.example.com/api/v3"),
		"https://ghe.example.com:8443/api/v3": on("https://ghe.example.com:8443", "https://ghe.example.com:8443/api/v3"),
		"https://api.acme.ghe.com":            on("https://acme.ghe.com", "https://api.acme.ghe.com"),
		"https://api.Acme.GHE.com/":           on("https://acme.ghe.com", "https://api.acme.ghe.com"),
		"http://127.0.0.1:9999":               on("http://127.0.0.1:9999", "http://127.0.0.1:9999"),
		"http://localhost:9999/fake":          on("http://localhost:9999/fake", "http://localhost:9999/fake"),
		"http://127.0.0.1:9999/api/v3":        on("http://127.0.0.1:9999", "http://127.0.0.1:9999/api/v3"),
		// A path under api.github.com or api.<tenant>.ghe.com is no known
		// layout, so the root serves itself.
		"https://api.github.com/proxy": on("https://api.github.com/proxy", "https://api.github.com/proxy"),
	} {
		t.Run(api, func(t *testing.T) {
			got, err := oauth2.GitHubHostsFor(api)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestGitHubHostsFor_RefusesBadRoots(t *testing.T) {
	for _, api := range []string{
		"http://ghe.example.com/api/v3",
		"ghe.example.com/api/v3",
		"https://user:pw@ghe.example.com/api/v3",
		"https://ghe.example.com/api/v3?x=1",
		"https://ghe.example.com/api/v3?",
		"https://ghe.example.com/api/v3#frag",
		"://bad",
	} {
		t.Run(api, func(t *testing.T) {
			_, err := oauth2.GitHubHostsFor(api)
			assert.Error(t, err)
		})
	}
}
