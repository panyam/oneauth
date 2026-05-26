package httpauth

import (
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
			a.JWTSecretKey = "MyTestJWTSecretKey123456"
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
		a.mux.HandleFunc("/logout", a.onLogout)
	}
	return a
}

func (a *OneAuth) verifyJWT(tokenString string) (loggedInUserId string, t any, err error) {
	// Parse the token with the secret key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return []byte(a.JWTSecretKey), nil
	})

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
	a.SetLoggedInUserID("", w, r)
	log.Println("Accept Header Type: ", r.Header["Accept"])
	toUrl := r.URL.Query()["to"]
	log.Println("TOURL: ", toUrl)
	if len(toUrl) == 0 || toUrl[0] == "" {
		fmt.Fprintf(w, "Logged Out")
	} else {
		http.Redirect(w, r, toUrl[0], http.StatusFound)
	}
}

// SetLoggedInUserID sets the auth token and logged-in user ID on each
// configured cookie domain. Pass an empty userID to clear (logout).
//
// Renamed from the previous setLoggedInUser(user core.User, ...) — httpauth
// now owns only the transport layer and never sees the accounts.User shape.
// Callers (typically federatedauth or localauth) translate their User
// object to user.Id() at the call site.
func (a *OneAuth) SetLoggedInUserID(userID string, w http.ResponseWriter, r *http.Request) string {
	a.EnsureDefaults()
	log.Println("ReqHost, Cookie Domains: ", r.Host, a.CookieDomains)
	domains := a.CookieDomains
	if slices.Index(a.CookieDomains, "") < 0 { // default domain
		domains = append(domains, "")
	}
	for _, cookieDomain := range domains {
		http.SetCookie(w, &http.Cookie{
			Name:   "oauthstate",
			Value:  "",
			MaxAge: -1, Expires: time.Now(),
			Domain: cookieDomain,
			Path:   "/",
		})

		if userID != "" {
			a.Session.Put(r.Context(), "loggedInUserId", userID)
			http.SetCookie(w, &http.Cookie{
				Name:    "loggedInUserId",
				Value:   userID,
				Domain:  cookieDomain,
				Path:    "/",
				Expires: time.Now().Add(time.Second * time.Duration(a.SessionTimeoutInSeconds)),
				MaxAge:  a.SessionTimeoutInSeconds,
			})

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"sub": userID,
				"iss": a.JwtIssuer,
				"aud": "admin", // replace with Role for the user later on
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Add(time.Hour).Unix(), // issued at
			})
			tokenString, err := token.SignedString([]byte(a.JWTSecretKey))
			if err != nil {
				slog.Info("error signing token", "err", err)
			}

			a.Session.Put(r.Context(), a.AuthTokenSessionVar, tokenString)
			http.SetCookie(w, &http.Cookie{
				Name:    a.AuthTokenSessionVar,
				Value:   tokenString,
				Domain:  cookieDomain,
				Path:    "/",
				Expires: time.Now().Add(time.Second * time.Duration(a.SessionTimeoutInSeconds)),
				MaxAge:  a.SessionTimeoutInSeconds,
			})
			return tokenString
		}

		// clear the session and cookie values
		log.Println("Logging out user")
		if err := a.Session.Clear(r.Context()); err != nil {
			slog.Warn("error clearing session ", "err", err)
		}
		http.SetCookie(w, &http.Cookie{
			Name:    "loggedInUserId",
			Domain:  cookieDomain,
			Path:    "/",
			MaxAge:  -1,
			Expires: time.Now(),
		})
		http.SetCookie(w, &http.Cookie{
			Name:    a.AuthTokenSessionVar,
			Domain:  cookieDomain,
			Path:    "/",
			MaxAge:  -1,
			Expires: time.Now(),
		})
	}
	return ""
}
