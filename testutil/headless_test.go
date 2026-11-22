package testutil_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/panyam/oneauth/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubKeycloak serves a login page shaped like Keycloak's, keyed on a
// session cookie, and redirects a correct login to the redirect_uri.
func stubKeycloak(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "AUTH_SESSION_ID", Value: "s1", Path: "/"})
		fmt.Fprintf(w, `<form id="kc-form-login" action="/login?session=s1&amp;redirect=%s" method="post"></form>`, r.URL.Query().Get("redirect_uri"))
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("AUTH_SESSION_ID")
		if err != nil || c.Value != "s1" || r.URL.Query().Get("session") != "s1" {
			http.Error(w, "session", http.StatusBadRequest)
			return
		}
		if r.FormValue("username") != "u" || r.FormValue("password") != "p" {
			http.Error(w, "bad login", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, r.URL.Query().Get("redirect")+"?code=c1", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestKeycloakPasswordLogin_ReachesTheRedirect(t *testing.T) {
	var callbacks atomic.Int32
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("code") == "c1" {
			callbacks.Add(1)
		}
	}))
	defer cb.Close()
	kc := stubKeycloak(t)

	login := testutil.KeycloakPasswordLogin(nil, "u", "p")
	require.NoError(t, login(kc.URL+"/auth?redirect_uri="+cb.URL))
	assert.Equal(t, int32(1), callbacks.Load())
}

// A driver watches the callback through hc's Transport, so the opener must
// send every request through it.
func TestKeycloakPasswordLogin_UsesTheCallersTransport(t *testing.T) {
	cb := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer cb.Close()
	kc := stubKeycloak(t)

	var seen []string
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r.URL.Path)
		return http.DefaultTransport.RoundTrip(r)
	})}
	require.NoError(t, testutil.KeycloakPasswordLogin(hc, "u", "p")(kc.URL+"/auth?redirect_uri="+cb.URL+"/callback"))
	assert.Equal(t, []string{"/auth", "/login", "/callback"}, seen)
}

func TestKeycloakPasswordLogin_NoForm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>no form here</html>")
	}))
	defer srv.Close()
	err := testutil.KeycloakPasswordLogin(nil, "u", "p")(srv.URL)
	assert.ErrorContains(t, err, "no Keycloak login form")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// For a form_post response mode Keycloak answers the login with a page
// that posts the response to the redirect_uri. The opener submits it.
func TestKeycloakPasswordLogin_SubmitsAFormPostPage(t *testing.T) {
	var got string
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			got = r.PostForm.Get("response")
		}
	}))
	defer cb.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<form id="kc-form-login" action="/login" method="post"></form>`)
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body onload="javascript:document.forms[0].submit()"><form method="post" action="%s/callback"><input type="hidden" name="response" value="a.b&#43;c"/></form></body></html>`, cb.URL)
	})
	kc := httptest.NewServer(mux)
	defer kc.Close()

	require.NoError(t, testutil.KeycloakPasswordLogin(nil, "u", "p")(kc.URL+"/auth"))
	assert.Equal(t, "a.b+c", got)
}
