package httpauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// middlewareContextKey is a local context key type used by Middleware
// to store the authenticated subject with a configurable param name.
type middlewareContextKey string

type Middleware struct {
	AuthTokenHeaderName string
	AuthTokenCookieName string
	SubjectParamName    string
	CallbackURLParam    string
	SessionGetter       func(r *http.Request, param string) any
	GetRedirURL         func(r *http.Request) string
	DefaultRedirectURL  string
	VerifyToken         func(tokenString string) (loggedInSubject string, token any, err error)
}

/**
 * Ensures that config values have reasonable defaults.
 */
func (a *Middleware) EnsureReasonableDefaults() {
	if a.SubjectParamName == "" {
		a.SubjectParamName = "loggedInSubject"
	}
	if a.CallbackURLParam == "" {
		a.CallbackURLParam = "/"
	}
	if a.AuthTokenHeaderName == "" {
		a.AuthTokenHeaderName = "Authorization"
	}
}

// GetLoggedInSubject returns the authenticated subject (RFC 7519 `sub`)
// for the current request — a user ID for human-driven flows or a
// client_id for client_credentials.
func (a *Middleware) GetLoggedInSubject(r *http.Request) string {
	a.EnsureReasonableDefaults()

	v := r.Context().Value(middlewareContextKey(a.SubjectParamName))
	if v != nil {
		loggedInSubject := v.(string)
		if loggedInSubject != "" {
			return loggedInSubject
		}
	}

	if a.SessionGetter != nil {
		sessParam := a.SessionGetter(r, a.SubjectParamName)
		if sessParam != "" && sessParam != nil {
			return sessParam.(string)
		}
	}

	// TODO - Decouple jwt details from Auth Middleware
	if a.VerifyToken == nil {
		slog.Warn("No auth token verifier found.  Please set one")
		return ""
	}

	// Otherwise check the Auth header
	authTokens := r.Header.Values(a.AuthTokenHeaderName)
	for _, cookie := range r.CookiesNamed(a.AuthTokenCookieName) {
		if len(cookie.Value) > 0 {
			// see if a cookie was sent instead - as we may be making non-api calls
			authTokens = append(authTokens, cookie.Value)
		}
	}

	for _, authToken := range authTokens {
		// Strip "Bearer " prefix if present
		token := authToken
		if strings.HasPrefix(strings.ToLower(authToken), "bearer ") {
			token = strings.TrimSpace(authToken[7:])
		}
		if token == "" {
			continue
		}
		loggedInSubject, _, err := a.VerifyToken(token)
		if err == nil && loggedInSubject != "" {
			return loggedInSubject
		} else if err != nil {
			slog.Warn("Error verifying token: ", "token", token[:min(len(token), 20)]+"...", "error", err)
		}
	}

	return ""
}

/**
 * Fetches the subject from the request and loads it into the request
 * context for downstream handlers.
 *
 * Note this does not perform any redirects if a valid subject does not
 * exist. To also enforce that, use EnsureUser.
 */
func (a *Middleware) ExtractUser(next http.Handler) http.Handler {
	a.EnsureReasonableDefaults()
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			subject := a.GetLoggedInSubject(r)
			next.ServeHTTP(w, a.setLoggedInSubject(subject, r))
		},
	)
}

func (a *Middleware) EnsureUser(next http.Handler) http.Handler {
	a.EnsureReasonableDefaults()
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			subject := a.GetLoggedInSubject(r)
			if subject == "" {
				redirUrl := ""
				if a.GetRedirURL != nil {
					redirUrl = a.GetRedirURL(r)
				}
				shouldRedirect := redirUrl != ""
				if shouldRedirect {
					originalUrl := r.URL.Path
					encodedUrl := strings.ReplaceAll(url.QueryEscape(originalUrl), "+", "%20")
					fullRedirUrl := fmt.Sprintf("%s?%s=%s", redirUrl, a.CallbackURLParam, encodedUrl)
					http.Redirect(w, r, fullRedirUrl, http.StatusFound)
				} else {
					http.Error(w, "Login Failed", http.StatusUnauthorized)
				}
				return
			}
			next.ServeHTTP(w, a.setLoggedInSubject(subject, r))
		},
	)
}

// setLoggedInSubject stores the authenticated subject in the request
// context under the configured param name so downstream handlers can
// read it back via GetLoggedInSubject.
func (a *Middleware) setLoggedInSubject(subject string, r *http.Request) *http.Request {
	contextWithSubject := context.WithValue(r.Context(), middlewareContextKey(a.SubjectParamName), subject)
	return r.WithContext(contextWithSubject)
}
