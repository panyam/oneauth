package client

// Tests for ApproveConsent, the headless opener for authorization servers that
// answer /authorize with a consent page. Ported from mcpkit's mcp-auth-proxy
// (approveHeadless), where it was written against metronome-mcp.fly.dev.
//
// See: https://github.com/panyam/oneauth/issues/387

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// metronomeConsentPage is metronome-mcp.fly.dev's /authorize page as served
// on 2026-10-14, trimmed to the form. The subject field is filled by script
// in a browser; served, it is empty.
const metronomeConsentPage = `<!DOCTYPE html><html><body><h1>Demo authorization</h1>
<form method="post" action="/consent" onsubmit="try{localStorage.setItem('x',1)}catch(e){}">
<input type="hidden" name="state" value="st&amp;1">
<label>Your name: <input type="text" name="subject" id="subject" value=""></label>
<button type="submit" name="action" value="approve">Approve</button>
<button type="submit" name="action" value="deny">Deny</button>
</form></body></html>`

// consentStack serves page at /authorize, records the form posted to
// /consent, and redirects that post to a loopback callback, which records
// that it was reached. /consent also requires the cookie /authorize set, so
// a client without a jar fails.
func consentStack(t *testing.T, path, page string, status int) (authURL string, posted *url.Values, reached *bool) {
	t.Helper()
	posted, reached = &url.Values{}, new(bool)
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { *reached = true }))
	t.Cleanup(callback.Close)
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "s1", Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(page))
	})
	mux.HandleFunc("/consent", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "s1" {
			http.Error(w, "no session", http.StatusForbidden)
			return
		}
		_ = r.ParseForm()
		*posted = r.PostForm
		http.Redirect(w, r, callback.URL+"/callback?code=c&state=s", http.StatusFound)
	})
	mux.HandleFunc("/redirect-now", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, callback.URL+"/callback?code=c&state=s", http.StatusFound)
	})
	as := httptest.NewServer(mux)
	t.Cleanup(as.Close)
	q := url.Values{"redirect_uri": {callback.URL + "/callback"}, "state": {"s"}}
	return as.URL + path + "?" + q.Encode(), posted, reached
}

func TestApproveConsent_SubmitsMetronomeConsentForm(t *testing.T) {
	authURL, posted, reached := consentStack(t, "/authorize", metronomeConsentPage, http.StatusOK)
	require.NoError(t, ApproveConsent(nil)(authURL))
	assert.Equal(t, "approve", posted.Get("action"), "never deny")
	assert.Equal(t, "st&1", posted.Get("state"), "hidden field submitted unescaped")
	assert.Contains(t, *posted, "subject", "text input submitted")
	assert.True(t, *reached, "loopback callback reached")
}

// A caller's client without a jar still gets one, and the caller's client is
// not mutated.
func TestApproveConsent_AddsJarWithoutMutatingClient(t *testing.T) {
	authURL, _, reached := consentStack(t, "/authorize", metronomeConsentPage, http.StatusOK)
	hc := &http.Client{}
	require.NoError(t, ApproveConsent(hc)(authURL))
	assert.True(t, *reached)
	assert.Nil(t, hc.Jar)
}

func TestApproveConsent_ImmediateRedirectNeedsNoForm(t *testing.T) {
	authURL, posted, reached := consentStack(t, "/redirect-now", "", http.StatusOK)
	require.NoError(t, ApproveConsent(nil)(authURL))
	assert.Empty(t, *posted, "nothing posted to a server that never asked")
	assert.True(t, *reached)
}

func TestApproveConsent_RefusesFormWithoutApprove(t *testing.T) {
	page := `<form method="post" action="/consent"><input type="password" name="pw" value=""><button type="submit" name="go" value="login">Log in</button></form>`
	authURL, posted, reached := consentStack(t, "/authorize", page, http.StatusOK)
	err := ApproveConsent(nil)(authURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no approve button")
	assert.Empty(t, *posted, "a login page must not be submitted")
	assert.False(t, *reached)
}

// The redirect_uri mismatch metronome reports is a 400 page with no form. It
// must surface as an error at once, carrying the AS's description.
func TestApproveConsent_ErrorPageFailsFast(t *testing.T) {
	authURL, _, _ := consentStack(t, "/authorize", `{"error":"invalid_request","error_description":"redirect_uri is not registered"}`, http.StatusBadRequest)
	err := ApproveConsent(nil)(authURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
	assert.Contains(t, err.Error(), "redirect_uri is not registered")
}
