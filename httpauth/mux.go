package httpauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/golang-jwt/jwt/v5"
)

// OneAuth owns the session/JWT/mux transport machinery shared across
// auth flows. Provider-mediated (OAuth/SAML) callback orchestration lives
// in federatedauth/; username/password handlers live in localauth/.
type OneAuth struct {
	mux        *http.ServeMux
	Session    *scs.SessionManager
	Middleware Middleware

	// Optional name that can be used as a prefix for all required vars
	AppName string

	// Name of the session variable where the auth token is stored
	AuthTokenSessionVar string

	// All the domains where the auth token cookies will be set on a login success or logout
	CookieDomains []string

	// JWT related fields
	JwtIssuer    string
	JWTSecretKey string

	// How long is a session cookie valid for.  Defaults to 1 day
	SessionTimeoutInSeconds int

	// InsecureCookies drops the Secure attribute from the login cookies.
	// They are Secure by default, which browsers honour over https and on
	// http://localhost; set this only for plain-http development on any
	// other host. Every other attribute (HttpOnly on the token, SameSite)
	// is kept either way.
	InsecureCookies bool
}

func New(appName string) *OneAuth {
	out := (&OneAuth{AppName: appName}).EnsureDefaults()
	return out
}

func (a *OneAuth) EnsureDefaults() *OneAuth {
	// ensure some defaults
	if a.AppName == "" {
		a.AppName = "OneAuth"
	}
	if a.SessionTimeoutInSeconds <= 0 {
		a.SessionTimeoutInSeconds = 86400
	}
	if a.JwtIssuer == "" {
		a.JwtIssuer = fmt.Sprintf("%s-Issuer", a.AppName)
	}
	if a.AuthTokenSessionVar == "" {
		a.AuthTokenSessionVar = fmt.Sprintf("%sAuthToken", a.AppName)
	}
	if a.JWTSecretKey == "" {
		a.JWTSecretKey = strings.TrimSpace(os.Getenv("ONEAUTH_JWT_SECRET_KEY"))
		if a.JWTSecretKey == "" {
			// A fixed fallback would be a public signing key: anyone could
			// mint a session for any user (CWE-798). A random per-process
			// secret is safe, at the cost of logging everyone out on restart.
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				panic(fmt.Sprintf("httpauth: generate session secret: %v", err))
			}
			a.JWTSecretKey = hex.EncodeToString(b)
			slog.Warn("httpauth: JWTSecretKey and ONEAUTH_JWT_SECRET_KEY are unset; using a random per-process secret, so sessions end on restart")
		}
	}
	if a.Middleware.AuthTokenCookieName == "" {
		a.Middleware.AuthTokenCookieName = a.AuthTokenSessionVar
	}

	if a.Middleware.VerifyToken == nil {
		a.Middleware.VerifyToken = a.verifyJWT
	}
	return a
}

func (a *OneAuth) Handler() http.Handler {
	return a.setupRoutes().mux
}

func (a *OneAuth) AddAuth(prefix string, handler http.Handler) *OneAuth {
	a.setupRoutes()
	a.EnsureDefaults()
	prefix = strings.TrimSuffix(prefix, "/")
	log.Println("Adding Auth for prefix: ", prefix)
	// Register the handler at prefix/ (with trailing slash) for subtree matching.
	// This allows the handler to receive requests like /google/, /google/callback/, etc.
	withSlashPattern := prefix + "/"
	a.mux.Handle(withSlashPattern, http.StripPrefix(prefix, handler))

	// Register a redirect handler at prefix (without trailing slash) that redirects
	// to the original path with trailing slash. This fixes the issue where
	// requests to /google (after StripPrefix) would result in an empty path.
	//
	// We use r.RequestURI to get the original unmodified request path, which
	// preserves any parent prefixes that were stripped (e.g., /auth/google even
	// though our mux only sees /google after the parent's StripPrefix).
	a.mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
		// Parse the original request URI to get the full path
		origPath := r.RequestURI
		// Remove query string if present to get just the path
		if idx := strings.Index(origPath, "?"); idx != -1 {
			origPath = origPath[:idx]
		}
		// Add trailing slash and reconstruct with query string
		target := origPath + "/"
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		// Use 308 PermanentRedirect to preserve the HTTP method (POST, PUT, etc.)
		// 301 MovedPermanently changes POST to GET which breaks API endpoints
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})

	return a
}

func (a *OneAuth) setupRoutes() *OneAuth {
	if a.mux == nil {
		a.mux = http.NewServeMux()
		// POST only: a GET logout can be fired by any page the user visits
		// (an <img> tag), logging them out cross-site (CWE-352).
		a.mux.HandleFunc("POST /logout", a.onLogout)
	}
	return a
}

func (a *OneAuth) verifyJWT(tokenString string) (loggedInSubject string, t any, err error) {
	// Parse the token with the secret key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return []byte(a.JWTSecretKey), nil
	}, jwt.WithValidMethods([]string{"HS256"}))

	// Check for verification errors
	if err != nil {
		return "", nil, err
	}

	// Check if the token is valid
	if !token.Valid {
		return "", nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims == nil {
		return "", nil, fmt.Errorf("claims is not a map")
	}
	// A login cookie is a session JWT. An access token signed with the
	// same secret is not a login (RFC 8725 §3.11).
	if t, _ := claims["type"].(string); t != "session" {
		return "", nil, fmt.Errorf("not a session token")
	}
	// Return the verified token
	sub, err := claims.GetSubject()
	if sub == "" {
		return "", nil, fmt.Errorf("subject not found")
	} else if err != nil {
		return "", nil, err
	}
	return sub, token, nil
}

func (a *OneAuth) onLogout(w http.ResponseWriter, r *http.Request) {
	log.Println("Logging out user...")
	a.SetLoggedInSubject("", w, r)
	log.Println("Accept Header Type: ", r.Header["Accept"])
	to := r.URL.Query().Get("to")
	if to == "" {
		fmt.Fprintf(w, "Logged Out")
		return
	}
	http.Redirect(w, r, LocalRedirect(to, "/"), http.StatusFound)
}

// SetLoggedInSubject stores the authenticated subject (RFC 7519 `sub`
// — a user ID for human-driven flows or a client_id for
// client_credentials) on each configured cookie domain. Pass an empty
// string to clear (logout).
//
// Callers (typically federatedauth or localauth) translate their User
// object to user.Id() at the call site.
func (a *OneAuth) SetLoggedInSubject(subject string, w http.ResponseWriter, r *http.Request) string {
	a.EnsureDefaults()
	domains := a.CookieDomains
	if slices.Index(a.CookieDomains, "") < 0 { // default domain
		domains = append(domains, "")
	}

	// A new session token on every login and logout, so a session ID that
	// someone planted before login is worthless after it (CWE-384).
	if err := a.Session.RenewToken(r.Context()); err != nil {
		slog.Warn("error renewing session token", "err", err)
	}

	var tokenString string
	if subject != "" {
		a.Session.Put(r.Context(), "loggedInSubject", subject)
		now := time.Now()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": subject,
			"iss": a.JwtIssuer,
			"aud": "admin", // replace with Role for the user later on
			"exp": now.Add(time.Hour).Unix(),
			"iat": now.Unix(),
			// A session token, not an API access token: apiauth's
			// middleware accepts only type "access" or none, so this keeps
			// a stolen login cookie from working as a Bearer token.
			"type": "session",
		})
		var err error
		tokenString, err = token.SignedString([]byte(a.JWTSecretKey))
		if err != nil {
			slog.Info("error signing token", "err", err)
		}
		a.Session.Put(r.Context(), a.AuthTokenSessionVar, tokenString)
	} else if err := a.Session.Clear(r.Context()); err != nil {
		slog.Warn("error clearing session ", "err", err)
	}

	for _, cookieDomain := range domains {
		a.setCookie(w, "oauthstate", "", cookieDomain, -1)
		if subject == "" {
			a.setCookie(w, "loggedInSubject", "", cookieDomain, -1)
			a.setCookie(w, a.AuthTokenSessionVar, "", cookieDomain, -1)
			continue
		}
		a.setCookie(w, "loggedInSubject", subject, cookieDomain, a.SessionTimeoutInSeconds)
		a.setCookie(w, a.AuthTokenSessionVar, tokenString, cookieDomain, a.SessionTimeoutInSeconds)
	}
	return tokenString
}

// setCookie writes one login cookie with the attributes every one of them
// gets: Secure unless InsecureCookies, SameSite=Lax, and HttpOnly (no
// page reads them from script). maxAge < 0 deletes it.
func (a *OneAuth) setCookie(w http.ResponseWriter, name, value, domain string, maxAge int) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   domain,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   !a.InsecureCookies,
		SameSite: http.SameSiteLaxMode,
	}
	if maxAge < 0 {
		c.Expires = time.Unix(0, 0)
	} else {
		c.Expires = time.Now().Add(time.Duration(maxAge) * time.Second)
	}
	http.SetCookie(w, c)
}
