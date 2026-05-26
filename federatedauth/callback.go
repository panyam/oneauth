package federatedauth

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/httpauth"
	"golang.org/x/oauth2"
)

// AuthUserStore combines the store interfaces needed for federated-auth
// callbacks plus the EnsureAuthUser orchestration that turns provider
// userInfo into an accounts.User.
type AuthUserStore interface {
	accounts.UserStore
	accounts.IdentityStore
	accounts.ChannelStore

	// EnsureAuthUser orchestrates user creation/lookup across stores.
	// This is the main entry point for OAuth and local authentication.
	EnsureAuthUser(authtype string, provider string, token *oauth2.Token, userInfo map[string]any) (accounts.User, error)
}

// OAuthBridge wires httpauth's session/cookie machinery to the federated-auth
// callback flow. Construct one per OneAuth instance and hand its methods to
// your OAuth provider handlers.
//
// Example:
//
//	bridge := federatedauth.NewOAuthBridge(oneauth, authUserStore)
//	oneauth.AddAuth("/google", oa2.NewGoogleOAuth2(
//	    clientID, clientSecret, callbackURL,
//	    bridge.SaveUserAndRedirect,
//	).Handler())
type OAuthBridge struct {
	OneAuth   *httpauth.OneAuth
	UserStore AuthUserStore
}

// NewOAuthBridge creates an OAuthBridge that callbacks dispatch through.
func NewOAuthBridge(oneAuth *httpauth.OneAuth, userStore AuthUserStore) *OAuthBridge {
	return &OAuthBridge{OneAuth: oneAuth, UserStore: userStore}
}

// SaveUserAndRedirect is called by an OAuth callback handler with the auth
// token and user info after a successful auth flow and redirect.
//
// Here is our opportunity to:
//  1. Create a userId that is unique to our system based on userInfo
//  2. Set the right session cookies from this
func (b *OAuthBridge) SaveUserAndRedirect(authtype, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
	log.Println("userInfo: ", b.UserStore, userInfo)
	user, err := b.UserStore.EnsureAuthUser(authtype, provider, token, userInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// We have verified an identity and a channel that is verifying this identity —
	// now establish the logged-in session.
	b.OneAuth.SetLoggedInSubject(user.Id(), w, r)

	// Auth done — go back to where we need to be
	callbackURL := "/"
	callbackURLCookie, _ := r.Cookie("oauthCallbackURL")
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
	// then delete the cookie too so it won't be used for subsequent redirects
	http.SetCookie(w, &http.Cookie{
		Name:   "oauthCallbackURL",
		Value:  "",
		Path:   "/",
		MaxAge: -1, Expires: time.Now(),
	})
	http.Redirect(w, r, callbackURL, http.StatusFound)
}

// =============================================================================
// OAuth Linking
// =============================================================================

// HandleLinkOAuthCallback links an OAuth provider channel onto an existing,
// already-logged-in user.
//
// # Who Calls This
//
// This is called by OAuth providers after the user authorizes linking. The flow is:
//
//  1. Local-only user visits profile, clicks "Link Google Account"
//  2. App stores user ID in session as "linkingUserID" (via b.StartLinkOAuth)
//  3. App redirects to Google OAuth with special state
//  4. Google redirects back to /auth/google/callback
//  5. OAuth callback sees "linkingUserID" in session (via b.GetLinkingUserID)
//  6. Instead of normal login, calls this handler to link the account
//
// # How to Set Up
//
// Modify your OAuth callback to detect linking mode:
//
//	func googleCallback(w http.ResponseWriter, r *http.Request) {
//	    // ... exchange code for token, get userInfo ...
//
//	    linkingUserID := bridge.GetLinkingUserID(r)
//	    if linkingUserID != "" {
//	        bridge.HandleLinkOAuthCallback(linkingUserID, "google", userInfo, w, r)
//	        return
//	    }
//
//	    bridge.SaveUserAndRedirect("oauth", "google", token, userInfo, w, r)
//	}
//
// # What It Does
//
//  1. Verifies the OAuth email matches the user's existing email identity
//  2. Creates OAuth channel for the provider
//  3. Updates user profile["channels"] to include the new provider
//  4. Redirects to callback URL
//
// # Security
//
// The OAuth email MUST match the user's existing email to prevent account hijacking.
// Users cannot link to a different email address.
func (b *OAuthBridge) HandleLinkOAuthCallback(linkingUserID, provider string, userInfo map[string]any, w http.ResponseWriter, r *http.Request) {
	oauthEmail, _ := userInfo["email"].(string)
	if oauthEmail == "" {
		http.Error(w, `{"error": "OAuth provider did not return email"}`, http.StatusBadRequest)
		return
	}

	user, err := b.UserStore.GetUserById(linkingUserID)
	if err != nil {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

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

	identityKey := accounts.IdentityKey("email", userEmail)

	existingChannel, _, err := b.UserStore.GetChannel(provider, identityKey, false)
	if err == nil && existingChannel != nil {
		log.Printf("Updating existing %s channel for user %s", provider, linkingUserID)
	}

	channel := &accounts.Channel{
		Provider:    provider,
		IdentityKey: identityKey,
		Credentials: make(map[string]any),
		Profile:     userInfo,
	}
	if err := b.UserStore.SaveChannel(channel); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to link OAuth account: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	if profile == nil {
		profile = make(map[string]any)
	}
	channels := accounts.LinkedChannels(profile)
	if !containsString(channels, provider) {
		channels = append(channels, provider)
		profile["channels"] = channels

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

		updatedUser := &accounts.BasicUser{ID: linkingUserID, ProfileData: profile}
		if err := b.UserStore.SaveUser(updatedUser); err != nil {
			log.Printf("Warning: failed to update user profile: %v", err)
		}
	}

	log.Printf("Linked %s account to user %s", provider, linkingUserID)

	callbackURL := "/"
	if callbackCookie, _ := r.Cookie("oauthCallbackURL"); callbackCookie != nil && callbackCookie.Value != "" {
		callbackURL = callbackCookie.Value
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "oauthCallbackURL",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, callbackURL, http.StatusFound)
}

// StartLinkOAuth initiates OAuth account linking by storing the user ID in
// session. Call this from your "Link [Provider] Account" button handler.
//
// Example:
//
//	func handleLinkGoogle(w http.ResponseWriter, r *http.Request) {
//	    userID := getLoggedInUserID(r)
//	    bridge.StartLinkOAuth(r, userID)
//	    http.Redirect(w, r, "/auth/google/", http.StatusFound)
//	}
func (b *OAuthBridge) StartLinkOAuth(r *http.Request, userID string) {
	b.OneAuth.Session.Put(r.Context(), "linkingUserID", userID)
}

// GetLinkingUserID retrieves and clears the linking user ID from session.
// Call this in your OAuth callback to detect linking mode.
func (b *OAuthBridge) GetLinkingUserID(r *http.Request) string {
	return b.OneAuth.Session.PopString(r.Context(), "linkingUserID")
}
