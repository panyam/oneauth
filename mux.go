package oneauth

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// BasicUser is a simple implementation of the User interface
type BasicUser struct {
	id      string
	profile map[string]any
}

func (b *BasicUser) Id() string              { return b.id }
func (b *BasicUser) Profile() map[string]any { return b.profile }

// AuthUserStore combines the store interfaces needed for authentication
type AuthUserStore interface {
	UserStore
	IdentityStore
	ChannelStore

	// EnsureAuthUser orchestrates user creation/lookup across stores
	// This is the main entry point for OAuth and local authentication
	EnsureAuthUser(authtype string, provider string, token *oauth2.Token, userInfo map[string]any) (User, error)
}

type OneAuth struct {
	mux        *http.ServeMux
	Session    *scs.SessionManager
	Middleware Middleware

	// Optional name that can be used as a prefix for all required vars
	AppName string

	// Name of the session variable where the auth token is stored
	AuthTokenSessionVar string

	// Must be passed in
	UserStore AuthUserStore

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
	a.setLoggedInUser(nil, w, r)
	log.Println("Accept Header Type: ", r.Header["Accept"])
	// c.Redirect(http.StatusFound, callbackURL)
	toUrl := r.URL.Query()["to"]
	log.Println("TOURL: ", toUrl)
	if len(toUrl) == 0 || toUrl[0] == "" {
		// Send json?
		fmt.Fprintf(w, "Logged Out")
	} else {
		http.Redirect(w, r, toUrl[0], http.StatusFound)
	}
}

/**
 * Called by the oauth callback handler with auth token and user info after
 * a successful auth flow and redirect.
 *
 * Here is our opportunity to:
 * 	1. Create a userId that is unique to our system based on userInfo
 *	2. Set the right session cookies from this.
 */
func (a *OneAuth) SaveUserAndRedirect(authtype, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
	// log.Println("Provider: ", provider)
	// log.Println("Token: ", token)
	log.Println("userInfo: ", a.UserStore, userInfo)
	user, err := a.UserStore.EnsureAuthUser(authtype, provider, token, userInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// we have verified an identity and a channel that is verifying this identity
	// Now create the user object corresponding to this
	a.setLoggedInUser(user, w, r)

	// Auth done - go back to where we need to be
	callbackURL := "/"
	callbackURLCookie, _ := r.Cookie("oauthCallbackURL")
	// log.Println("Callback URL Cookie value before: ", callbackURLCookie)
	if callbackURLCookie != nil {
		callbackURL = callbackURLCookie.Value
	}
	if callbackURL == "" {
		callbackURL = "/"
	}
	u, _ := url.Parse(callbackURL)
	if u != nil && u.Scheme == "" {
		callbackURL = os.Getenv("OAUTH2_BASE_URL") + callbackURL
	}
	log.Println("Redirecting to CallbackURL: ", callbackURL)
	// then delete it too so it wont be used for subsequent redirects
	http.SetCookie(w, &http.Cookie{
		Name:   "oauthCallbackURL",
		Value:  "",
		Path:   "/",
		MaxAge: -1, Expires: time.Now(),
		// Domain: cookieDomain,
	})
	http.Redirect(w, r, callbackURL, http.StatusFound)
}

// Generic helper method to set the auth token and logged in user ID on a bunch of cookie domains we care about.
// This can also be used to "unset/logout" the logged in user.
//
// TODO - See if we should just pass a userID instead of a user object.  Reason for passing the user object
// was in case we wanted to store any other user profile details (via jwt claims) in the cookie but may not
// be needed.
func (a *OneAuth) setLoggedInUser(user User, w http.ResponseWriter, r *http.Request) string {
	a.EnsureDefaults()
	// Add extra domains here if needed
	// cookieDomains := []string{a.BaseUrl.Hostname()}
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

		if user != nil {
			a.Session.Put(r.Context(), "loggedInUserId", user.Id())
			bytes := user.Id() //
			http.SetCookie(w, &http.Cookie{
				Name:    "loggedInUserId",
				Value:   bytes,
				Domain:  cookieDomain,
				Path:    "/",
				Expires: time.Now().Add(time.Second * time.Duration(a.SessionTimeoutInSeconds)), MaxAge: a.SessionTimeoutInSeconds,
			})

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"sub": user.Id(),
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
				Expires: time.Now().Add(time.Second * time.Duration(a.SessionTimeoutInSeconds)), MaxAge: a.SessionTimeoutInSeconds,
			})
			return tokenString
		} else {
			// clear the session and cookie values
			log.Println("Logging out user")
			// session.Set("loggedInUserId", "")
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
	}
	return ""
}

// =============================================================================
// OAuth Linking (Phase 4)
// =============================================================================

// LinkOAuthConfig holds configuration for OAuth account linking
type LinkOAuthConfig struct {
	UserStore     UserStore
	IdentityStore IdentityStore
	ChannelStore  ChannelStore
}

// HandleLinkOAuthCallback returns an HTTP handler for linking an OAuth provider
// to an existing local-only user.
//
// # Who Calls This
//
// This is called by OAuth providers after the user authorizes linking. The flow is:
//
//  1. Local-only user visits profile, clicks "Link Google Account"
//  2. App stores user ID in session as "linkingUserID"
//  3. App redirects to Google OAuth with special state
//  4. Google redirects back to /auth/google/callback
//  5. OAuth callback sees "linkingUserID" in session
//  6. Instead of normal login, calls this handler to link the account
//
// # How to Set Up
//
// Modify your OAuth callback to detect linking mode:
//
//	func googleCallback(w http.ResponseWriter, r *http.Request) {
//	    // ... exchange code for token, get userInfo ...
//
//	    // Check if this is a linking flow
//	    linkingUserID := session.Get("linkingUserID")
//	    if linkingUserID != "" {
//	        session.Delete("linkingUserID")
//	        linkConfig := oneauth.LinkOAuthConfig{
//	            UserStore:     stores.UserStore,
//	            IdentityStore: stores.IdentityStore,
//	            ChannelStore:  stores.ChannelStore,
//	        }
//	        oneAuth.HandleLinkOAuthCallback(linkConfig, linkingUserID, "google", userInfo, w, r)
//	        return
//	    }
//
//	    // Normal login flow
//	    oneAuth.SaveUserAndRedirect("oauth", "google", token, userInfo, w, r)
//	}
//
// # What It Does
//
//  1. Verifies the OAuth email matches the user's existing email identity
//  2. Creates OAuth channel for the provider
//  3. Updates user profile["channels"] to include the new provider
//  4. Redirects to callback URL (or returns JSON success)
//
// # Security
//
// The OAuth email MUST match the user's existing email to prevent account hijacking.
// Users cannot link to a different email address.
func (a *OneAuth) HandleLinkOAuthCallback(config LinkOAuthConfig, linkingUserID, provider string, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
	// Get the OAuth email
	oauthEmail, _ := userInfo["email"].(string)
	if oauthEmail == "" {
		http.Error(w, `{"error": "OAuth provider did not return email"}`, http.StatusBadRequest)
		return
	}

	// Get the user being linked
	user, err := config.UserStore.GetUserById(linkingUserID)
	if err != nil {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	// Get user's email from profile
	profile := user.Profile()
	userEmail, _ := profile["email"].(string)

	// SECURITY: OAuth email must match user's email
	if userEmail == "" {
		http.Error(w, `{"error": "User has no email identity to link"}`, http.StatusBadRequest)
		return
	}
	if !strings.EqualFold(oauthEmail, userEmail) {
		log.Printf("OAuth link rejected: OAuth email %s != user email %s", oauthEmail, userEmail)
		http.Error(w, `{"error": "OAuth email does not match your account email"}`, http.StatusForbidden)
		return
	}

	// Create identity key
	identityKey := IdentityKey("email", userEmail)

	// Check if channel already exists
	existingChannel, _, err := config.ChannelStore.GetChannel(provider, identityKey, false)
	if err == nil && existingChannel != nil {
		// Channel already exists - that's fine, just update it
		log.Printf("Updating existing %s channel for user %s", provider, linkingUserID)
	}

	// Create/update OAuth channel
	channel := &Channel{
		Provider:    provider,
		IdentityKey: identityKey,
		Credentials: make(map[string]any),
		Profile:     userInfo,
	}
	if err := config.ChannelStore.SaveChannel(channel); err != nil {
		http.Error(w, `{"error": "Failed to link OAuth account"}`, http.StatusInternalServerError)
		return
	}

	// Update user profile with linked channel
	if profile == nil {
		profile = make(map[string]any)
	}
	channels := getProfileChannels(profile)
	if !containsChannel(channels, provider) {
		channels = append(channels, provider)
		profile["channels"] = channels

		// Also update profile with OAuth info if not set
		if profile["name"] == nil || profile["name"] == "" {
			if name, ok := userInfo["name"].(string); ok && name != "" {
				profile["name"] = name
			}
		}
		if profile["picture"] == nil || profile["picture"] == "" {
			if picture, ok := userInfo["picture"].(string); ok && picture != "" {
				profile["picture"] = picture
			}
		}

		updatedUser := &BasicUser{id: linkingUserID, profile: profile}
		if err := config.UserStore.SaveUser(updatedUser); err != nil {
			log.Printf("Warning: failed to update user profile: %v", err)
		}
	}

	log.Printf("Linked %s account to user %s", provider, linkingUserID)

	// Redirect back to app
	callbackURL := "/"
	if callbackCookie, _ := r.Cookie("oauthCallbackURL"); callbackCookie != nil && callbackCookie.Value != "" {
		callbackURL = callbackCookie.Value
	}

	// Clear the callback cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "oauthCallbackURL",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, callbackURL, http.StatusFound)
}

// getProfileChannels extracts channels list from profile
func getProfileChannels(profile map[string]any) []string {
	if profile == nil {
		return []string{}
	}
	switch v := profile["channels"].(type) {
	case []string:
		return v
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return []string{}
	}
}

// containsChannel checks if provider is in channels list
func containsChannel(channels []string, provider string) bool {
	for _, c := range channels {
		if c == provider {
			return true
		}
	}
	return false
}

// StartLinkOAuth initiates OAuth account linking by storing the user ID in session.
// Call this from your "Link [Provider] Account" button handler.
//
// # Example Usage
//
//	func handleLinkGoogle(w http.ResponseWriter, r *http.Request) {
//	    userID := getLoggedInUserID(r)
//	    oneAuth.StartLinkOAuth(r, userID)
//	    // Redirect to Google OAuth
//	    http.Redirect(w, r, "/auth/google/", http.StatusFound)
//	}
func (a *OneAuth) StartLinkOAuth(r *http.Request, userID string) {
	a.Session.Put(r.Context(), "linkingUserID", userID)
}

// GetLinkingUserID retrieves and clears the linking user ID from session.
// Call this in your OAuth callback to detect linking mode.
//
// # Example Usage
//
//	func googleCallback(w http.ResponseWriter, r *http.Request) {
//	    linkingUserID := oneAuth.GetLinkingUserID(r)
//	    if linkingUserID != "" {
//	        // Linking flow
//	        oneAuth.HandleLinkOAuthCallback(config, linkingUserID, "google", userInfo, w, r)
//	        return
//	    }
//	    // Normal login flow
//	    oneAuth.SaveUserAndRedirect(...)
//	}
func (a *OneAuth) GetLinkingUserID(r *http.Request) string {
	userID := a.Session.PopString(r.Context(), "linkingUserID")
	return userID
}
