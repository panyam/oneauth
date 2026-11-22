package oauth2

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// GitHubHosts names where one GitHub deployment serves each part of itself.
// Build it with GitHubHostsFor. GithubOAuth2.SetEnterpriseURL uses it too.
type GitHubHosts struct {
	// Web is the host people sign in at and git clones from, with no
	// trailing slash: https://github.com, https://ghe.example.com, or
	// https://acme.ghe.com.
	Web string

	// API is the REST API root, with no trailing slash.
	API string

	// Endpoint is the OAuth authorize, token and device-code URLs on Web.
	Endpoint oauth2.Endpoint

	// UserInfoURL is the API's /user, which returns the signed-in person.
	UserInfoURL string
}

// GitHubHostsFor maps a GitHub REST API root to the rest of the deployment.
// It recognizes three kinds of root:
//
//   - "" or https://api.github.com is github.com.
//   - https://<host>/api/v3 is GitHub Enterprise Server on <host>.
//   - https://api.<tenant>.ghe.com is GHE.com, signed in at <tenant>.ghe.com.
//
// Any other root, such as a test's fake server, serves sign-in, the API
// and git on itself, so Web equals API.
//
// The root must be https, or http on a loopback host so a test can run a
// fake. It may not carry credentials, a query or a fragment. A trailing
// slash is ignored, and host names compare case-insensitively.
func GitHubHostsFor(api string) (GitHubHosts, error) {
	api = strings.TrimSuffix(api, "/")
	if api == "" {
		return githubDotComHosts(), nil
	}
	u, err := url.Parse(api)
	if err != nil {
		return GitHubHosts{}, fmt.Errorf("github API root %q: %w", api, err)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return GitHubHosts{}, fmt.Errorf("github API root %q must be a scheme, host and optional path", api)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return GitHubHosts{}, fmt.Errorf("github API root %q must use https", api)
	}
	host := strings.ToLower(u.Host)
	origin := u.Scheme + "://" + host

	switch {
	case host == "api.github.com" && u.Path == "":
		return githubDotComHosts(), nil
	case strings.HasPrefix(host, "api.") && strings.HasSuffix(host, ".ghe.com") && u.Path == "":
		return githubHosts(u.Scheme+"://"+strings.TrimPrefix(host, "api."), origin), nil
	}
	if web, ok := strings.CutSuffix(origin+u.Path, "/api/v3"); ok {
		return githubHosts(web, web+"/api/v3"), nil
	}
	return githubHosts(origin+u.Path, origin+u.Path), nil
}

func githubDotComHosts() GitHubHosts {
	return GitHubHosts{
		Web:         "https://github.com",
		API:         "https://api.github.com",
		Endpoint:    github.Endpoint,
		UserInfoURL: "https://api.github.com/user",
	}
}

func githubHosts(web, api string) GitHubHosts {
	return GitHubHosts{
		Web: web,
		API: api,
		Endpoint: oauth2.Endpoint{
			AuthURL:       web + "/login/oauth/authorize",
			TokenURL:      web + "/login/oauth/access_token",
			DeviceAuthURL: web + "/login/device/code",
		},
		UserInfoURL: api + "/user",
	}
}
