package httpauth_test

// The httpauth login session: cookie flags, session renewal, the session
// JWT's claims, the signing secret, and logout.
//
// References:
//   - OWASP Session Management Cheat Sheet (renewal on privilege change, cookie attributes)
//   - CWE-384 session fixation (https://cwe.mitre.org/data/definitions/384.html)
//   - CWE-1004 cookie without HttpOnly (https://cwe.mitre.org/data/definitions/1004.html)
//   - CWE-614 cookie without Secure (https://cwe.mitre.org/data/definitions/614.html)
//   - CWE-798 hard-coded credentials (https://cwe.mitre.org/data/definitions/798.html)
//   - CWE-601 open redirect (https://cwe.mitre.org/data/definitions/601.html)
//   - CWE-352 CSRF (https://cwe.mitre.org/data/definitions/352.html)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/httpauth"
)

const sessionTestSecret = "session-test-secret-32-chars!!!!"

func newSessionAuth(t *testing.T) *httpauth.OneAuth {
	t.Helper()
	a := &httpauth.OneAuth{AppName: "App", Session: scs.New(), JWTSecretKey: sessionTestSecret}
	return a.EnsureDefaults()
}

// login runs SetLoggedInSubject inside the session middleware, optionally
// carrying an existing session cookie, and returns the response cookies.
func login(t *testing.T, a *httpauth.OneAuth, subject string, existing *http.Cookie) []*http.Cookie {
	t.Helper()
	h := a.Session.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.SetLoggedInSubject(subject, w, r)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if existing != nil {
		req.AddCookie(existing)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Result().Cookies()
}

func cookieNamed(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

func TestSession_CookieFlags(t *testing.T) {
	a := newSessionAuth(t)
	cookies := login(t, a, "user-1", nil)

	tok := cookieNamed(cookies, a.AuthTokenSessionVar)
	require.NotNil(t, tok)
	assert.True(t, tok.HttpOnly, "the session JWT cookie must not be readable from script (CWE-1004)")
	assert.True(t, tok.Secure, "CWE-614")
	assert.Equal(t, http.SameSiteLaxMode, tok.SameSite)

	sub := cookieNamed(cookies, "loggedInSubject")
	require.NotNil(t, sub)
	assert.True(t, sub.Secure)
	assert.Equal(t, http.SameSiteLaxMode, sub.SameSite)
}

// Plain-HTTP development outside localhost needs an explicit opt-out.
func TestSession_InsecureCookiesOptOut(t *testing.T) {
	a := newSessionAuth(t)
	a.InsecureCookies = true
	tok := cookieNamed(login(t, a, "user-1", nil), a.AuthTokenSessionVar)
	require.NotNil(t, tok)
	assert.False(t, tok.Secure)
	assert.True(t, tok.HttpOnly)
}

// See: https://cwe.mitre.org/data/definitions/384.html
func TestSession_LoginRenewsTheSessionToken(t *testing.T) {
	a := newSessionAuth(t)
	// An anonymous session first, as an attacker would plant.
	seed := a.Session.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.Session.Put(r.Context(), "visited", true)
	}))
	rr := httptest.NewRecorder()
	seed.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	planted := cookieNamed(rr.Result().Cookies(), a.Session.Cookie.Name)
	require.NotNil(t, planted)

	after := cookieNamed(login(t, a, "user-1", planted), a.Session.Cookie.Name)
	require.NotNil(t, after, "login must issue a session cookie")
	assert.NotEqual(t, planted.Value, after.Value, "login must not keep the pre-login session token")
}

func TestSession_EveryCookieDomainGetsTheLogin(t *testing.T) {
	a := newSessionAuth(t)
	a.CookieDomains = []string{"a.example", "b.example"}
	cookies := login(t, a, "user-1", nil)

	domains := map[string]bool{}
	for _, c := range cookies {
		if c.Name == a.AuthTokenSessionVar && c.MaxAge > 0 {
			domains[c.Domain] = true
		}
	}
	assert.True(t, domains["a.example"], "a.example")
	assert.True(t, domains["b.example"], "b.example")
}

// The session JWT says what it is, has a sane iat, and is refused where an
// API access token is expected.
func TestSession_JWTIsASessionTokenNotAnAccessToken(t *testing.T) {
	a := newSessionAuth(t)
	tok := cookieNamed(login(t, a, "user-1", nil), a.AuthTokenSessionVar)
	require.NotNil(t, tok)

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tok.Value, claims, func(*jwt.Token) (any, error) { return []byte(sessionTestSecret), nil })
	require.NoError(t, err)
	assert.Equal(t, "session", claims["type"])
	iat, err := claims.GetIssuedAt()
	require.NoError(t, err)
	assert.False(t, iat.After(time.Now().Add(time.Minute)), "iat must not be in the future")

	mw := &apiauth.APIMiddleware{JWTSecretKey: sessionTestSecret}
	called := false
	h := mw.ValidateToken(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Value)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.False(t, called, "a session cookie must not pass as an API access token")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// See: https://cwe.mitre.org/data/definitions/798.html
func TestSession_NoHardCodedDefaultSecret(t *testing.T) {
	t.Setenv("ONEAUTH_JWT_SECRET_KEY", "")
	a := httpauth.New("App")
	assert.NotEqual(t, "MyTestJWTSecretKey123456", a.JWTSecretKey)
	assert.GreaterOrEqual(t, len(a.JWTSecretKey), 32)
	assert.NotEqual(t, a.JWTSecretKey, httpauth.New("App").JWTSecretKey, "each process gets its own random secret")
}

// A token signed with the session secret under another HMAC algorithm is
// refused: the verifier pins HS256.
func TestSession_VerifierPinsHS256(t *testing.T) {
	a := newSessionAuth(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{"sub": "user-1", "exp": time.Now().Add(time.Hour).Unix()})
	signed, err := tok.SignedString([]byte(sessionTestSecret))
	require.NoError(t, err)
	sub, _, err := a.Middleware.VerifyToken(signed)
	assert.Error(t, err)
	assert.Empty(t, sub)
}

func TestSession_LogoutIsPOSTAndRedirectsLocally(t *testing.T) {
	a := newSessionAuth(t)
	h := a.Session.LoadAndSave(a.Handler())

	t.Run("GET is refused (CWE-352)", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/logout", nil))
		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	})
	for to, want := range map[string]string{
		"/home":                  "/home",
		"https://evil.example/x": "/",
		"//evil.example":         "/",
		"/\\evil.example":        "/",
	} {
		t.Run("to="+to, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/logout?to="+to, nil))
			require.Equal(t, http.StatusFound, rr.Code)
			assert.Equal(t, want, rr.Header().Get("Location"))
		})
	}
}
