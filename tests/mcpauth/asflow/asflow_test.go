package asflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/panyam/oneauth/client"
)

// stubAS serves a signup form that signs the user in, open DCR, and an
// /authorize that shows a consent page only to a signed-in browser, like
// oneauth-server.
type stubAS struct {
	*httptest.Server
	mu        sync.Mutex
	dcrBodies []map[string]any
}

func newStubAS(t *testing.T) *stubAS {
	s := &stubAS{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/signup", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "csrf", Value: "c1", Path: "/"})
		fmt.Fprint(w, `<form method="post"><input type="hidden" name="csrf_token" value="tok-1"></form>`)
	})
	mux.HandleFunc("POST /auth/signup", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if c, err := r.Cookie("csrf"); err != nil || c.Value != "c1" || r.PostForm.Get("csrf_token") != "tok-1" {
			http.Error(w, "csrf", http.StatusForbidden)
			return
		}
		if r.PostForm.Get("email") == "" || r.PostForm.Get("password") == "" {
			http.Error(w, "missing", http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "oa_token", Value: "session", Path: "/"})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "home") })
	mux.HandleFunc("POST /apps/dcr", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		s.dcrBodies = append(s.dcrBodies, body)
		s.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"client_id":"app_1"}`)
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("oa_token"); err != nil || c.Value != "session" {
			fmt.Fprint(w, `<form method="post" action="/auth/login"><input name="username"><input type="password" name="password"><button type="submit">Sign in</button></form>`)
			return
		}
		fmt.Fprintf(w, `<form method="post" action="/authorize/consent"><input type="hidden" name="q" value="%s"><button name="decision" value="approve">Approve</button></form>`, url.QueryEscape(r.URL.RawQuery))
	})
	mux.HandleFunc("POST /authorize/consent", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		q, _ := url.QueryUnescape(r.PostForm.Get("q"))
		vals, _ := url.ParseQuery(q)
		if r.PostForm.Get("decision") != "approve" {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		http.Redirect(w, r, vals.Get("redirect_uri")+"?code=c&state="+vals.Get("state"), http.StatusFound)
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func jarClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func TestSignUp_LeavesTheSessionInTheJar(t *testing.T) {
	as := newStubAS(t)
	hc := jarClient()
	if err := SignUp(hc, as.URL, "u@example.com", "pw-123456789"); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(as.URL)
	var found bool
	for _, c := range hc.Jar.Cookies(u) {
		found = found || (c.Name == "oa_token" && c.Value == "session")
	}
	if !found {
		t.Fatal("the jar has no session cookie after signup")
	}
}

func TestSignUp_NeedsAJar(t *testing.T) {
	as := newStubAS(t)
	if err := SignUp(&http.Client{}, as.URL, "u@example.com", "pw"); err == nil {
		t.Fatal("SignUp without a cookie jar should fail, since the session would be lost")
	}
}

func TestRegister_SendsAPublicPKCEClientForTheCallback(t *testing.T) {
	as := newStubAS(t)
	id, err := Register(http.DefaultClient, as.URL, "http://127.0.0.1:18400/callback")
	if err != nil {
		t.Fatal(err)
	}
	if id != "app_1" {
		t.Fatalf("client_id = %q", id)
	}
	body := as.dcrBodies[0]
	if body["token_endpoint_auth_method"] != "none" {
		t.Errorf("token_endpoint_auth_method = %v, want none", body["token_endpoint_auth_method"])
	}
	if uris, _ := body["redirect_uris"].([]any); len(uris) != 1 || uris[0] != "http://127.0.0.1:18400/callback" {
		t.Errorf("redirect_uris = %v", body["redirect_uris"])
	}
	if gts, _ := body["grant_types"].([]any); len(gts) != 1 || gts[0] != "authorization_code" {
		t.Errorf("grant_types = %v", body["grant_types"])
	}
}

func TestWatch_ApprovesOnlyAuthorizationURLs(t *testing.T) {
	out := strings.Join([]string{
		"=== Running scenario: authorization-code-grant ===",
		"Ensure http://127.0.0.1:18400/callback is registered as a redirect URI for client 'app_1'.",
		"Access the following URL in your browser and complete the authentication process.",
		"http://as.test/authorize?response_type=code&client_id=app_1",
		"Running client scenario for authorization server 'x' against server: http://as.test",
		"  http://as.test/authorize?response_type=code&client_id=app_2  ",
		"http://as.test/authorizeX?nope",
		"http://as.test/authorize",
	}, "\n")
	var mu sync.Mutex
	var got []string
	var echo bytes.Buffer
	seen, err := Watch(strings.NewReader(out), &echo, "http://as.test/authorize", func(u string) error {
		mu.Lock()
		got = append(got, u)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"http://as.test/authorize?response_type=code&client_id=app_1",
		"http://as.test/authorize?response_type=code&client_id=app_2",
	}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("seen = %v, want %v", seen, want)
	}
	if len(got) != 2 {
		t.Fatalf("approved %d URLs, want 2", len(got))
	}
	if echo.String() != out+"\n" {
		t.Error("Watch should copy the command's output through unchanged")
	}
}

func TestWatch_ReportsTheFirstApprovalError(t *testing.T) {
	boom := errors.New("consent page had no approve button")
	_, err := Watch(strings.NewReader("http://as.test/authorize?a=1\n"), &bytes.Buffer{}, "http://as.test/authorize",
		func(string) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

// The whole path the exercise takes: sign up, then approve the URL the
// framework prints, so the redirect reaches the framework's callback.
func TestWatch_WithApproveConsent_ReachesTheCallback(t *testing.T) {
	as := newStubAS(t)
	hits := make(chan *http.Request, 1)
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- r
		fmt.Fprint(w, "OK")
	}))
	defer callback.Close()

	hc := jarClient()
	if err := SignUp(hc, as.URL, "u@example.com", "pw-123456789"); err != nil {
		t.Fatal(err)
	}
	authURL := as.URL + "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {"app_1"}, "state": {"st"},
		"redirect_uri": {callback.URL + "/callback"},
	}.Encode()
	if _, err := Watch(strings.NewReader(authURL+"\n"), &bytes.Buffer{}, as.URL+"/authorize", client.ApproveConsent(hc)); err != nil {
		t.Fatal(err)
	}
	r := <-hits
	if r.URL.Path != "/callback" || r.URL.Query().Get("state") != "st" || r.URL.Query().Get("code") == "" {
		t.Fatalf("callback got %s", r.URL)
	}
}

// Without the session, /authorize shows a login form, and the approver
// refuses it instead of posting it. The run fails at once.
func TestWatch_WithoutASession_FailsInsteadOfPostingTheLoginForm(t *testing.T) {
	as := newStubAS(t)
	authURL := as.URL + "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {"app_1"}, "redirect_uri": {"http://127.0.0.1:1/callback"},
	}.Encode()
	_, err := Watch(strings.NewReader(authURL+"\n"), &bytes.Buffer{}, as.URL+"/authorize", client.ApproveConsent(jarClient()))
	if err == nil {
		t.Fatal("approving without a signed-in session should fail")
	}
}
