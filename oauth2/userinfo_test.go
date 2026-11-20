// Tests for the userinfo step of the Google and GitHub callbacks: the access
// token stays out of logs and URLs, and an error status from userinfo fails
// the sign-in.

package oauth2_test

import (
	"bytes"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/panyam/oneauth/oauth2"
	oauth2lib "golang.org/x/oauth2"
)

const (
	fakeAccessToken  = "gho_secretaccesstoken123"
	fakeRefreshToken = "ghr_secretrefreshtoken456"
)

// fakeProvider plays an OAuth provider's token and userinfo endpoints and
// records how userinfo was called.
type fakeProvider struct {
	server *httptest.Server

	mu             sync.Mutex
	userinfoStatus int
	userinfoBody   string
	lastQuery      string
	lastAuthHeader string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	f := &fakeProvider{
		userinfoStatus: http.StatusOK,
		userinfoBody:   `{"id": 42, "login": "octo", "email": "octo@example.com"}`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"` + fakeAccessToken + `","token_type":"bearer","refresh_token":"` + fakeRefreshToken + `","expires_in":3600}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.lastQuery = r.URL.RawQuery
		f.lastAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.userinfoStatus)
		w.Write([]byte(f.userinfoBody))
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// provider is what the tests need from GoogleOAuth2 and GithubOAuth2.
type provider interface {
	Handler() http.Handler
	SetHTTPClient(*http.Client)
	SetOAuthEndpoint(oauth2lib.Endpoint)
}

type handled struct {
	called   bool
	userInfo map[string]any
}

func newGithub(f *fakeProvider, h *handled) provider {
	p := oauth2.NewGithubOAuth2("cid", "csecret", "http://localhost/cb", recordUser(h))
	p.UserInfoURL = f.server.URL + "/userinfo"
	return wire(p, f)
}

func newGoogle(f *fakeProvider, h *handled) provider {
	p := oauth2.NewGoogleOAuth2("cid", "csecret", "http://localhost/cb", recordUser(h))
	p.UserInfoURL = f.server.URL + "/userinfo"
	return wire(p, f)
}

func recordUser(h *handled) oauth2.HandleUserFunc {
	return func(authtype, provider string, token *oauth2lib.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
		h.called = true
		h.userInfo = userInfo
		w.WriteHeader(http.StatusOK)
	}
}

func wire(p provider, f *fakeProvider) provider {
	p.SetHTTPClient(f.server.Client())
	p.SetOAuthEndpoint(oauth2lib.Endpoint{AuthURL: f.server.URL + "/auth", TokenURL: f.server.URL + "/token"})
	return p
}

func callback(p provider) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/callback/?code=c&state=s", nil)
	req.AddCookie(&http.Cookie{Name: "oauthstate", Value: "s"})
	req.AddCookie(&http.Cookie{Name: "pkce_verifier", Value: "test-verifier-for-unit-tests"})
	rr := httptest.NewRecorder()
	p.Handler().ServeHTTP(rr, req)
	return rr
}

// captureLogs sends the log package and slog, at debug level, to a buffer
// for the rest of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	prevSlog, prevOut, prevFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		slog.SetDefault(prevSlog)
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return &buf
}

func assertNoTokens(t *testing.T, logs string) {
	t.Helper()
	for _, tok := range []string{fakeAccessToken, fakeRefreshToken} {
		if strings.Contains(logs, tok) {
			t.Errorf("log output contains token %q:\n%s", tok, logs)
		}
	}
}

// See: https://cwe.mitre.org/data/definitions/532.html (issue 510)
func TestGithubCallback_TokenNeverLogged(t *testing.T) {
	logs := captureLogs(t)
	var h handled
	rr := callback(newGithub(newFakeProvider(t), &h))
	if !h.called {
		t.Fatalf("sign-in failed: %d %s", rr.Code, rr.Body.String())
	}
	assertNoTokens(t, logs.String())
}

// failingUserinfo fails every request to /userinfo at the transport, the
// way a DNS or TLS failure does, and passes the rest through.
type failingUserinfo struct{ next http.RoundTripper }

func (f failingUserinfo) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/userinfo" {
		return nil, errors.New("connection reset")
	}
	return f.next.RoundTrip(r)
}

// A transport error's text includes the request URL, so a token in the URL
// reaches the log through the error.
// See: https://cwe.mitre.org/data/definitions/598.html
func TestGoogleCallback_TokenNeverLogged(t *testing.T) {
	f := newFakeProvider(t)
	logs := captureLogs(t)
	var h handled
	p := newGoogle(f, &h)
	p.SetHTTPClient(&http.Client{Transport: failingUserinfo{f.server.Client().Transport}})

	rr := callback(p)
	if h.called || rr.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected a failed sign-in, got %d, HandleUser called=%v", rr.Code, h.called)
	}
	assertNoTokens(t, logs.String())
}

func TestGoogleUserinfo_TokenSentAsBearerHeader(t *testing.T) {
	f := newFakeProvider(t)
	var h handled
	callback(newGoogle(f, &h))
	if !h.called {
		t.Fatal("sign-in failed")
	}
	if strings.Contains(f.lastQuery, fakeAccessToken) {
		t.Errorf("token sent in the userinfo query: %q", f.lastQuery)
	}
	if f.lastAuthHeader != "Bearer "+fakeAccessToken {
		t.Errorf("Authorization = %q, want the bearer token", f.lastAuthHeader)
	}
}

// GitHub answers a bad token with 401 and a JSON body. Before, that body
// went to HandleUser as the person's profile.
func TestUserinfo_ErrorStatusFailsSignIn(t *testing.T) {
	for name, newP := range map[string]func(*fakeProvider, *handled) provider{
		"github": newGithub,
		"google": newGoogle,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeProvider(t)
			f.userinfoStatus = http.StatusUnauthorized
			f.userinfoBody = `{"message": "Bad credentials", "documentation_url": "https://docs.github.com/rest"}`
			var h handled
			rr := callback(newP(f, &h))
			if h.called {
				t.Errorf("HandleUser ran with %v", h.userInfo)
			}
			if rr.Code != http.StatusTemporaryRedirect || rr.Header().Get("Location") != "/auth/failed" {
				t.Errorf("got %d to %q, want 307 to /auth/failed", rr.Code, rr.Header().Get("Location"))
			}
		})
	}
}
