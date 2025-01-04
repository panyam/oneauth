package oneauth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type userParamNameKey string

type Middleware struct {
	UserParamName      string
	CallbackURLParam   string
	SessionGetter      func(r *http.Request, param string) any
	GetRedirURL        func(r *http.Request) string
	DefaultRedirectURL string
	VerifyToken        func(tokenString string) (loggedInUserId string, token any, err error)
}

/**
 * Ensures that config values have reasonable defaults.
 */
func (a *Middleware) EnsureReasonableDefaults() {
	if a.UserParamName == "" {
		a.UserParamName = "loggedInUserId"
	}
	if a.CallbackURLParam == "" {
		a.CallbackURLParam = "/"
	}
}

// Get the ID of the logged in user from the current request
func (a *Middleware) GetLoggedInUserId(r *http.Request) string {
	loggedInUserId := r.Context().Value(userParamNameKey(a.UserParamName)).(string)
	if loggedInUserId != "" {
		return loggedInUserId
	}

	userParam := a.SessionGetter(r, a.UserParamName)
	if userParam != "" && userParam != nil {
		return userParam.(string)
	}

	// Otherwise check the Auth header
	authHeader := r.Header.Get("Authorization")
	log.Println("Auth Headers: ", authHeader)
	log.Println("Cookies: ", r.Cookies())

	// TODO - Decouple jwt details from Auth Middleware
	if authHeader != "" && a.VerifyToken != nil {
		loggedInUserId, _, err := a.VerifyToken(authHeader)
		if err == nil {
			return loggedInUserId
		}
		log.Println("Error verifying token: ", err)
	}

	// Verify the JWT
	return ""
}

/**
 * Fetches the user from the request and loads the UserId and User variables
 * available for other handlers.
 *
 * Note this does not perform any redirects if a valid user does not exist.
 * To also enforce a user exists, use the EnsureUser handler which both
 * calls ExgractUser and ensures that user is logged in.
 */
func (a *Middleware) ExtractUser(next http.Handler) http.Handler {
	a.EnsureReasonableDefaults()
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// See if the userId session token is set
			userParam := a.getLoggedInUserId(r)
			// set the logged in user ID as the request scoped variable
			next.ServeHTTP(w, a.setLoggedInUserId(userParam, r))
		},
	)
}

func (a *Middleware) EnsureUser(next http.Handler) http.Handler {
	a.EnsureReasonableDefaults()
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// See if the userId session token is set
			userParam := a.getLoggedInUserId(r)
			if userParam == "" {
				// Redirect to a login if user not logged in
				// `/${a.redirectURLPrefix || "auth"}/login?callbackURL=${encodeURIComponent(req.originalUrl)}`;
				redirUrl := ""
				if a.GetRedirURL != nil {
					redirUrl = a.GetRedirURL(r)
				}
				shouldRedirect := redirUrl != ""
				if shouldRedirect {
					originalUrl := r.URL.Path
					encodedUrl := strings.Replace(url.QueryEscape(originalUrl), "+", "%20", -1)
					fullRedirUrl := fmt.Sprintf("%s?%s=%s", redirUrl, a.CallbackURLParam, encodedUrl)
					http.Redirect(w, r, fullRedirUrl, http.StatusFound)
				} else {
					// otherwise a 401
					http.Error(w, "Login Failed", http.StatusUnauthorized)
				}
				return
			} else {
				// set the logged in user ID as the request scoped variable
				next.ServeHTTP(w, a.setLoggedInUserId(userParam, r))
			}
		},
	)
}

// Gets the logged in user from the session first
func (a *Middleware) getLoggedInUserId(r *http.Request) string {
	out := a.SessionGetter(r, a.UserParamName)
	if out == nil {
		return ""
	}
	return out.(string)
}

// Set the logged in user id into the request's variable set
// This will make it available to all other handlers downstream
func (a *Middleware) setLoggedInUserId(userId string, r *http.Request) *http.Request {
	// set the logged in user ID as the request scoped variable
	contextWithUser := context.WithValue(r.Context(), userParamNameKey(a.UserParamName), userId)
	//create a new request using that new context
	return r.WithContext(contextWithUser)
}