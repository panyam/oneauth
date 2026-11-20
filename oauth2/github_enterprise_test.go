// Tests for pointing GithubOAuth2 at a GitHub Enterprise host (issue 511).

package oauth2_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/panyam/oneauth/oauth2"
	oauth2lib "golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

func TestGithubEnterprise_SetsAllThreeURLs(t *testing.T) {
	cases := []struct {
		base                        string
		authURL, tokenURL, userinfo string
	}{
		{
			base:     "https://ghe.example.com",
			authURL:  "https://ghe.example.com/login/oauth/authorize",
			tokenURL: "https://ghe.example.com/login/oauth/access_token",
			userinfo: "https://ghe.example.com/api/v3/user",
		},
		{
			base:     "https://ghe.example.com/",
			authURL:  "https://ghe.example.com/login/oauth/authorize",
			tokenURL: "https://ghe.example.com/login/oauth/access_token",
			userinfo: "https://ghe.example.com/api/v3/user",
		},
		{
			base:     "https://acme.ghe.com",
			authURL:  "https://acme.ghe.com/login/oauth/authorize",
			tokenURL: "https://acme.ghe.com/login/oauth/access_token",
			userinfo: "https://api.acme.ghe.com/user",
		},
	}
	for _, c := range cases {
		t.Run(c.base, func(t *testing.T) {
			p := oauth2.NewGithubOAuth2("cid", "cs", "http://localhost/cb", nil)
			if err := p.SetEnterpriseURL(c.base); err != nil {
				t.Fatal(err)
			}
			ep := p.OAuthEndpoint()
			if ep.AuthURL != c.authURL || ep.TokenURL != c.tokenURL {
				t.Errorf("endpoint = %+v, want %s and %s", ep, c.authURL, c.tokenURL)
			}
			if p.UserInfoURL != c.userinfo {
				t.Errorf("UserInfoURL = %q, want %q", p.UserInfoURL, c.userinfo)
			}
		})
	}
}

func TestGithubEnterprise_RefusesBadURLs(t *testing.T) {
	for _, base := range []string{
		"http://ghe.example.com",
		"ghe.example.com",
		"https://",
		"https://ghe.example.com/path",
		"https://ghe.example.com?x=1",
	} {
		t.Run(base, func(t *testing.T) {
			p := oauth2.NewGithubOAuth2("cid", "cs", "http://localhost/cb", nil)
			if err := p.SetEnterpriseURL(base); err == nil {
				t.Errorf("SetEnterpriseURL(%q) accepted", base)
			}
			if p.OAuthEndpoint() != githubDotCom {
				t.Errorf("a refused URL changed the endpoint to %+v", p.OAuthEndpoint())
			}
		})
	}
}

var githubDotCom = github.Endpoint

// A loopback http:// host is allowed so a test can stand up a fake GitHub
// Enterprise server, and the whole sign-in runs against it.
func TestGithubEnterprise_SignInAgainstAFakeServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"ghe_token","token_type":"bearer"}`))
	})
	mux.HandleFunc("/api/v3/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghe_token" {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"id": 7, "login": "enterprise-octo"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var login any
	p := oauth2.NewGithubOAuth2("cid", "cs", "http://localhost/cb",
		func(_, _ string, _ *oauth2lib.Token, info map[string]any, w http.ResponseWriter, _ *http.Request) {
			login = info["login"]
		})
	if err := p.SetEnterpriseURL(srv.URL); err != nil {
		t.Fatal(err)
	}
	p.SetHTTPClient(srv.Client())

	login1 := httptest.NewRecorder()
	p.Handler().ServeHTTP(login1, httptest.NewRequest(http.MethodGet, "/", nil))
	loc, err := url.Parse(login1.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), srv.URL+"/login/oauth/authorize?") {
		t.Fatalf("login redirects to %q, want the fake server's authorize URL", login1.Header().Get("Location"))
	}

	rr := callback(p)
	if login != "enterprise-octo" {
		t.Errorf("HandleUser got login %v (status %d %s)", login, rr.Code, rr.Body.String())
	}
}
