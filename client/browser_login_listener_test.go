package client

// Tests for caller-owned loopback listeners, the RedirectURI override, and
// FollowRedirects failing fast on an authorization-endpoint error (issue 387).
//
// The strict AS here matches redirect_uri byte-for-byte against what DCR
// registered, as metronome-mcp does. RFC 8252 §7.3 asks the AS to allow any
// port on a loopback redirect, but clients have to work against servers that
// don't.
//
// See: https://www.rfc-editor.org/rfc/rfc8252#section-7.3
// See: https://github.com/panyam/oneauth/issues/387

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// strictRedirectAS serves DCR at /register and refuses /authorize and /token
// unless redirect_uri is exactly one of the URIs registered for client_id.
// /authorize answers a mismatch with a 400 JSON error, like metronome.
func strictRedirectAS(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	registered := map[string][]string{}
	isRegistered := func(clientID, redirect string) bool {
		mu.Lock()
		defer mu.Unlock()
		for _, r := range registered[clientID] {
			if r == redirect {
				return true
			}
		}
		return false
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var req ClientRegistrationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		clientID := "client-" + req.ClientName
		registered[clientID] = req.RedirectURIs
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"client_id": clientID, "redirect_uris": req.RedirectURIs})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if !isRegistered(q.Get("client_id"), q.Get("redirect_uri")) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": "redirect_uri is not registered"})
			return
		}
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=code-"+q.Get("client_id")+"&state="+q.Get("state"), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if !isRegistered(r.FormValue("client_id"), r.FormValue("redirect_uri")) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at-" + r.FormValue("client_id"), "token_type": "Bearer", "expires_in": 900})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func strictLoginRequest(as *httptest.Server, clientID string) *BrowserLoginRequest {
	return &BrowserLoginRequest{
		AuthorizationEndpoint: as.URL + "/authorize",
		TokenEndpoint:         as.URL + "/token",
		ClientID:              clientID,
		Timeout:               5 * time.Second,
		OpenBrowser:           FollowRedirects(nil),
	}
}

func registerRedirect(t *testing.T, as *httptest.Server, name, redirect string) string {
	t.Helper()
	resp, err := RegisterClient(as.URL+"/register", ClientRegistrationRequest{ClientName: name, RedirectURIs: []string{redirect}}, nil)
	require.NoError(t, err)
	return resp.ClientID
}

func TestLoopbackRedirectURI(t *testing.T) {
	assert.Equal(t, "http://localhost:4242/callback", LoopbackRedirectURI(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}))
	assert.Equal(t, "http://localhost:4242/callback", LoopbackRedirectURI(&net.TCPAddr{IP: net.IPv6loopback, Port: 4242}))
}

// A caller registers LoopbackRedirectURI(l.Addr()) via DCR before the login,
// then hands the same listener over. The strict AS accepts the redirect at
// both /authorize and /token.
func TestLoginWithBrowser_CallerListenerMatchesStrictRegistration(t *testing.T) {
	as := strictRedirectAS(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	clientID := registerRedirect(t, as, "cli", LoopbackRedirectURI(l.Addr()))

	req := strictLoginRequest(as, clientID)
	req.Listener = l
	cred, err := NewAuthClient(as.URL, nil).LoginWithBrowser(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "at-"+clientID, cred.AccessToken)
}

// Two logins running at once, each on its own caller-owned listener, never
// contend for a port: there is no release-then-rebind window to lose.
func TestLoginWithBrowser_ConcurrentCallerListeners(t *testing.T) {
	as := strictRedirectAS(t)
	const n = 2
	var wg sync.WaitGroup
	errs := make([]error, n)
	tokens := make([]string, n)
	clientIDs := make([]string, n)
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		clientIDs[i] = registerRedirect(t, as, string(rune('a'+i)), LoopbackRedirectURI(l.Addr()))
		req := strictLoginRequest(as, clientIDs[i])
		req.Listener = l
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cred, err := NewAuthClient(as.URL, nil).LoginWithBrowser(context.Background(), req)
			errs[i] = err
			if cred != nil {
				tokens[i] = cred.AccessToken
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		require.NoError(t, errs[i], "login %d", i)
		assert.Equal(t, "at-"+clientIDs[i], tokens[i])
	}
}

// LoginWithBrowser owns a caller-supplied listener and closes it on return,
// on success and on an early error alike.
func TestLoginWithBrowser_ClosesCallerListener(t *testing.T) {
	as := strictRedirectAS(t)

	t.Run("success", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		req := strictLoginRequest(as, registerRedirect(t, as, "ok", LoopbackRedirectURI(l.Addr())))
		req.Listener = l
		_, err = NewAuthClient(as.URL, nil).LoginWithBrowser(context.Background(), req)
		require.NoError(t, err)
		_, err = l.Accept()
		assert.ErrorIs(t, err, net.ErrClosed)
	})

	t.Run("missing client id", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		req := strictLoginRequest(as, "")
		req.Listener = l
		_, err = NewAuthClient(as.URL, nil).LoginWithBrowser(context.Background(), req)
		require.Error(t, err)
		_, err = l.Accept()
		assert.ErrorIs(t, err, net.ErrClosed)
	})
}

// RedirectURI is sent byte-for-byte, and its path is where the callback is
// served. Here the registration uses an IP literal and a non-default path.
func TestLoginWithBrowser_RedirectURIOverride(t *testing.T) {
	as := strictRedirectAS(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	redirect := "http://" + l.Addr().String() + "/oauth/done"
	clientID := registerRedirect(t, as, "override", redirect)

	req := strictLoginRequest(as, clientID)
	req.Listener = l
	req.RedirectURI = redirect
	cred, err := NewAuthClient(as.URL, nil).LoginWithBrowser(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "at-"+clientID, cred.AccessToken)
}

// Without a Listener, RedirectURI names the host and port to bind.
func TestLoginWithBrowser_RedirectURIBindsWithoutListener(t *testing.T) {
	as := strictRedirectAS(t)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	redirect := "http://" + probe.Addr().String() + "/cb"
	probe.Close()
	clientID := registerRedirect(t, as, "bind", redirect)

	req := strictLoginRequest(as, clientID)
	req.RedirectURI = redirect
	cred, err := NewAuthClient(as.URL, nil).LoginWithBrowser(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "at-"+clientID, cred.AccessToken)
}

// A RedirectURI that cannot reach the loopback server is refused before the
// browser opens, rather than surfacing as a timeout.
func TestLoginWithBrowser_RedirectURIRejected(t *testing.T) {
	as := strictRedirectAS(t)
	cases := map[string]string{
		"port differs from listener": "http://127.0.0.1:1/callback",
		"not loopback":               "http://example.com:%d/callback",
		"https scheme":               "https://127.0.0.1:%d/callback",
		"no port":                    "http://127.0.0.1/callback",
	}
	for name, tmpl := range cases {
		t.Run(name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			port := l.Addr().(*net.TCPAddr).Port
			redirect := strings.Replace(tmpl, "%d", strconv.Itoa(port), 1)
			opened := false
			req := strictLoginRequest(as, "x")
			req.Listener = l
			req.RedirectURI = redirect
			req.OpenBrowser = func(string) error { opened = true; return nil }
			_, err = NewAuthClient(as.URL, nil).LoginWithBrowser(context.Background(), req)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "RedirectURI")
			assert.False(t, opened, "browser must not open for an unusable RedirectURI")
		})
	}
}

// The case from issue 387: /authorize answers 400 because the redirect is not
// registered. FollowRedirects must turn that into an error carrying the AS's
// description, instead of LoginWithBrowser waiting out its full timeout.
func TestFollowRedirects_ErrorStatusFailsFast(t *testing.T) {
	as := strictRedirectAS(t)
	req := strictLoginRequest(as, "never-registered")
	req.Timeout = 30 * time.Second

	start := time.Now()
	_, err := NewAuthClient(as.URL, nil).LoginWithBrowser(context.Background(), req)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second, "should fail fast, not wait for the timeout")
	assert.Contains(t, err.Error(), "400")
	assert.Contains(t, err.Error(), "redirect_uri is not registered")
}

// A non-JSON error page still reports its status and a snippet of the body.
func TestFollowRedirects_ErrorStatusPlainBody(t *testing.T) {
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unknown client", http.StatusUnauthorized)
	}))
	defer as.Close()
	err := FollowRedirects(nil)(as.URL + "/authorize?redirect_uri=http%3A%2F%2Flocalhost%3A1%2Fcallback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
	assert.Contains(t, err.Error(), "unknown client")
}
