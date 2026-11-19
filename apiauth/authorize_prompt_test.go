package apiauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// promptFixture mounts /authorize with a session read from test headers:
// X-Test-Subject names the logged-in user and X-Test-AuthTime (unix
// seconds) says when they logged in. consents is nil for a mount without
// remembered consent.
type promptFixture struct {
	mux      *http.ServeMux
	consents *core.InMemoryConsentStore
}

func newPromptFixture(t *testing.T, remember bool) *promptFixture {
	t.Helper()
	appStore := core.NewInMemoryAppStore()
	require.NoError(t, seedClient(appStore, "client-x", "https://app.example/cb"))
	oa := NewOneAuth(OneAuthConfig{
		AuthorizationCodeStore: core.NewInMemoryAuthorizationCodeStore(),
		AppStore:               appStore,
	})
	f := &promptFixture{mux: http.NewServeMux()}
	cfg := AuthorizeMountConfig{
		OneAuth:              oa,
		IssuerURL:            "https://issuer.example",
		SubjectFromRequest:   func(r *http.Request) string { return r.Header.Get("X-Test-Subject") },
		AuthTimeFromRequest:  testAuthTime,
		CSRFTokenFromRequest: func(r *http.Request) string { return "csrf" },
	}
	if remember {
		f.consents = core.NewInMemoryConsentStore()
		cfg.ConsentStore = f.consents
		cfg.ConsentLifetime = time.Hour
	}
	MountAuthorize(f.mux, cfg)
	return f
}

func testAuthTime(r *http.Request) time.Time {
	sec, err := strconv.ParseInt(r.Header.Get("X-Test-AuthTime"), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// session describes the browser's login state for one request. A zero
// subject is a browser with no session.
type session struct {
	subject  string
	loggedIn time.Time
}

func (f *promptFixture) get(q url.Values, s session) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	if s.subject != "" {
		req.Header.Set("X-Test-Subject", s.subject)
		req.Header.Set("X-Test-AuthTime", strconv.FormatInt(s.loggedIn.Unix(), 10))
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func (f *promptFixture) approve(t *testing.T, q url.Values, s session) {
	t.Helper()
	form := url.Values{}
	for k, v := range q {
		form[k] = v
	}
	form.Set("action", "approve")
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Test-Subject", s.subject)
	req.Header.Set("X-Test-AuthTime", strconv.FormatInt(s.loggedIn.Unix(), 10))
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code, "approve: %s", rec.Body.String())
}

func (f *promptFixture) remember(t *testing.T, subject string, scopes ...string) {
	t.Helper()
	_, err := f.consents.SaveConsent(context.Background(), &core.SaveConsentRequest{Grant: &core.ConsentGrant{
		Subject: subject, ClientID: "client-x", Scopes: scopes,
		GrantedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}})
	require.NoError(t, err)
}

func withParams(t *testing.T, kv ...string) url.Values {
	q := authorizeQuery(t)
	for i := 0; i < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	return q
}

// loginRedirect asserts a redirect to the login page and returns the URL
// the user comes back to.
func loginRedirect(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	require.Equal(t, http.StatusSeeOther, rec.Code, "want the login page, got %d %s", rec.Code, rec.Header().Get("Location"))
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/auth/login", loc.Path)
	next, err := url.Parse(loc.Query().Get("next"))
	require.NoError(t, err)
	return next
}

func consentPage(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, "want the consent page, got %d %s", rec.Code, rec.Header().Get("Location"))
	assert.Contains(t, rec.Body.String(), `value="approve"`)
}

var now = func() time.Time { return time.Now() }

// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest (prompt, max_age)

// prompt=none never shows a page. With no session the client hears
// login_required at its redirect URI.
func TestPrompt_NoneWithoutSessionIsLoginRequired(t *testing.T) {
	f := newPromptFixture(t, true)
	got := redirectQuery(t, f.get(withParams(t, "prompt", "none"), session{}))
	assert.Equal(t, "login_required", got.Get("error"))
	assert.Equal(t, "state-1", got.Get("state"))
}

// A session without an approval that covers the request would need the
// consent screen, so prompt=none answers consent_required.
func TestPrompt_NoneWithoutRememberedConsentIsConsentRequired(t *testing.T) {
	for _, tc := range []struct {
		name     string
		remember bool
		scopes   []string
	}{
		{"no consent store", false, nil},
		{"nothing remembered", true, nil},
		{"remembered scopes don't cover the request", true, []string{"other"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPromptFixture(t, tc.remember)
			if tc.scopes != nil {
				f.remember(t, "user-1", tc.scopes...)
			}
			got := redirectQuery(t, f.get(withParams(t, "prompt", "none"), session{"user-1", now()}))
			assert.Equal(t, "consent_required", got.Get("error"))
			assert.Empty(t, got.Get("code"))
		})
	}
}

// With a session and remembered consent covering the request, prompt=none
// gets a code without any page.
func TestPrompt_NoneWithSessionAndConsentIssuesACode(t *testing.T) {
	f := newPromptFixture(t, true)
	f.remember(t, "user-1", "read", "write")
	got := redirectQuery(t, f.get(withParams(t, "prompt", "none"), session{"user-1", now()}))
	assert.NotEmpty(t, got.Get("code"))
	assert.Empty(t, got.Get("error"))
}

// Remembered consent skips the consent screen for an ordinary request,
// and prompt=consent shows it anyway.
func TestPrompt_RememberedConsentSkipsTheScreenUnlessPromptConsent(t *testing.T) {
	f := newPromptFixture(t, true)
	f.remember(t, "user-1", "read")
	s := session{"user-1", now()}

	got := redirectQuery(t, f.get(authorizeQuery(t), s))
	assert.NotEmpty(t, got.Get("code"))

	consentPage(t, f.get(withParams(t, "prompt", "consent"), s))
}

// Without a consent store every request shows the consent screen, as
// before.
func TestPrompt_NoConsentStoreAlwaysShowsTheScreen(t *testing.T) {
	f := newPromptFixture(t, false)
	consentPage(t, f.get(authorizeQuery(t), session{"user-1", now()}))
}

// Approving records the consent, keeping scopes approved before, so a
// narrower approval doesn't take back a wider one.
func TestPrompt_ApprovalIsRememberedAndMerged(t *testing.T) {
	f := newPromptFixture(t, true)
	s := session{"user-1", now()}
	f.approve(t, withParams(t, "scope", "read write"), s)
	f.approve(t, withParams(t, "scope", "read"), s)

	resp, err := f.consents.GetConsent(context.Background(), &core.GetConsentRequest{Subject: "user-1", ClientID: "client-x"})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"read", "write"}, resp.Grant.Scopes)
	assert.WithinDuration(t, time.Now().Add(time.Hour), resp.Grant.ExpiresAt, 5*time.Second, "ConsentLifetime sets the expiry")

	got := redirectQuery(t, f.get(withParams(t, "scope", "read write", "prompt", "none"), s))
	assert.NotEmpty(t, got.Get("code"))
}

// prompt=login sends a logged-in user back through login. The return URL
// carries when the request arrived, and a login after that satisfies it,
// so the user isn't sent round again.
func TestPrompt_LoginForcesAFreshLogin(t *testing.T) {
	f := newPromptFixture(t, false)
	before := now().Add(-time.Hour)
	next := loginRedirect(t, f.get(withParams(t, "prompt", "login"), session{"user-1", before}))
	assert.Equal(t, "/authorize", next.Path)
	assert.Equal(t, "login", next.Query().Get("prompt"))
	marker, err := strconv.ParseInt(next.Query().Get(loginAfterParam), 10, 64)
	require.NoError(t, err, "the return URL carries %s", loginAfterParam)

	consentPage(t, f.get(next.Query(), session{"user-1", time.Unix(marker, 0)}))
	loginRedirect(t, f.get(next.Query(), session{"user-1", time.Unix(marker-1, 0)}))
}

// prompt=login from a browser with no session is an ordinary login.
func TestPrompt_LoginWithoutSessionGoesToLogin(t *testing.T) {
	f := newPromptFixture(t, false)
	next := loginRedirect(t, f.get(withParams(t, "prompt", "login"), session{}))
	assert.NotEmpty(t, next.Query().Get(loginAfterParam))
}

// max_age: a login older than max_age seconds goes back through login,
// and a recent one doesn't.
func TestPrompt_MaxAge(t *testing.T) {
	f := newPromptFixture(t, false)
	consentPage(t, f.get(withParams(t, "max_age", "60"), session{"user-1", now().Add(-10 * time.Second)}))

	next := loginRedirect(t, f.get(withParams(t, "max_age", "60"), session{"user-1", now().Add(-2 * time.Minute)}))
	assert.Equal(t, "60", next.Query().Get("max_age"))
	marker, err := strconv.ParseInt(next.Query().Get(loginAfterParam), 10, 64)
	require.NoError(t, err)
	consentPage(t, f.get(next.Query(), session{"user-1", time.Unix(marker, 0)}))
}

// max_age=0 would never be satisfied by elapsed time alone. The marker
// lets the login it forces count.
func TestPrompt_MaxAgeZeroDoesNotLoop(t *testing.T) {
	f := newPromptFixture(t, false)
	next := loginRedirect(t, f.get(withParams(t, "max_age", "0"), session{"user-1", now()}))
	marker, _ := strconv.ParseInt(next.Query().Get(loginAfterParam), 10, 64)
	consentPage(t, f.get(next.Query(), session{"user-1", time.Unix(marker, 0)}))
}

// A login that's too old with prompt=none is login_required, not a page.
func TestPrompt_NoneWithStaleLoginIsLoginRequired(t *testing.T) {
	f := newPromptFixture(t, true)
	f.remember(t, "user-1", "read", "write")
	got := redirectQuery(t, f.get(withParams(t, "prompt", "none", "max_age", "1"), session{"user-1", now().Add(-time.Hour)}))
	assert.Equal(t, "login_required", got.Get("error"))
}

// Malformed values are invalid_request at the redirect URI: none with any
// other prompt value (§3.1.2.1), and a max_age that isn't a
// non-negative integer.
func TestPrompt_MalformedValuesAreInvalidRequest(t *testing.T) {
	f := newPromptFixture(t, true)
	for _, kv := range [][]string{
		{"prompt", "none login"},
		{"prompt", "consent none"},
		{"max_age", "-1"},
		{"max_age", "soon"},
	} {
		got := redirectQuery(t, f.get(withParams(t, kv...), session{"user-1", now()}))
		assert.Equal(t, "invalid_request", got.Get("error"), "%s=%s", kv[0], kv[1])
	}
}

// Without AuthTimeFromRequest the handler can't tell when the user logged
// in, so prompt=login and max_age can't be honoured. It shows consent
// rather than sending the user round the login page forever; the ID token
// then has no auth_time, which tells the client.
func TestPrompt_WithoutAuthTimeLoginPromptsAreNotEnforced(t *testing.T) {
	appStore := core.NewInMemoryAppStore()
	require.NoError(t, seedClient(appStore, "client-x", "https://app.example/cb"))
	mux := http.NewServeMux()
	MountAuthorize(mux, AuthorizeMountConfig{
		OneAuth:              NewOneAuth(OneAuthConfig{AuthorizationCodeStore: core.NewInMemoryAuthorizationCodeStore(), AppStore: appStore}),
		IssuerURL:            "https://issuer.example",
		SubjectFromRequest:   func(r *http.Request) string { return "user-1" },
		CSRFTokenFromRequest: func(r *http.Request) string { return "csrf" },
	})
	for _, kv := range [][]string{{"prompt", "login"}, {"max_age", "0"}} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+withParams(t, kv...).Encode(), nil))
		consentPage(t, rec)
	}
}
