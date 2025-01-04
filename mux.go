package oneauth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"

	oa2 "github.com/panyam/oneauth/oauth2"
	"github.com/panyam/oneauth/saml"
)

type User interface {
	Id() string
}

type BasicUser struct {
	id string
}

func (b *BasicUser) Id() string { return b.id }

type UserStore interface {
	GetUserByID(userId string) (User, error)
	EnsureAuthUser(authtype string, provider string, token *oauth2.Token, userInfo map[string]any) (User, error)
}

type OneAuth struct {
	mux        *http.ServeMux
	Session    *scs.SessionManager
	BaseUrl    *url.URL
	Middleware *Middleware

	// Name of the session variable where the auth token is stored
	AuthTokenSessionVar string

	// Must be passed in
	UserStore UserStore

	// JWT related fields
	JwtIssuer    string
	JWTSecretKey string
}

func New() *OneAuth {
	return (&OneAuth{}).EnsureDefaults()
}

func (a *OneAuth) EnsureDefaults() *OneAuth {
	// ensure some defaults
	if a.JwtIssuer == "" {
		a.JwtIssuer = "oneauth-issuer"
	}
	if a.AuthTokenSessionVar == "" {
		a.AuthTokenSessionVar = "OneAuthToken"
	}
	if a.JWTSecretKey == "" {
		a.JWTSecretKey = strings.TrimSpace(os.Getenv("ONEAUTH_JWT_SECRET_KEY"))
		if a.JWTSecretKey == "" {
			a.JWTSecretKey = "MyTestJWTSecretKey123456"
		}
	}
	if a.Middleware.VerifyToken == nil {
		a.Middleware.VerifyToken = a.verifyJWT
	}
	return a
}

func (a *OneAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func (a *OneAuth) SetupRoutes(router *mux.Router) {
	var err error
	baseUrl := strings.TrimSpace(os.Getenv("OAUTH2_BASE_URL"))
	a.BaseUrl, err = url.Parse(baseUrl)
	if err != nil {
		log.Fatal("Invalid Base Url: ", err)
		panic(err)
	}

	log.Println("Creating OneAuth Router with base url ", a.BaseUrl)
	// log.Println("UserStore: ", a.UserStore)

	router.HandleFunc("/profile", a.onUserProfile).Methods("GET")
	router.HandleFunc("/login", a.onUsernameLogin).Methods("POST")

	router.HandleFunc("/logout", a.onLogout).Methods("GET", "POST")

	if os.Getenv("OAUTH2_GOOGLE_CLIENT_ID") != "" {
		clientId := os.Getenv("OAUTH2_GOOGLE_CLIENT_ID")
		clientSecret := os.Getenv("OAUTH2_GOOGLE_CLIENT_SECRET")
		callbackUrl := os.Getenv("OAUTH2_GOOGLE_CALLBACK_URL")
		oauthCallbackUrl := a.BaseUrl.String() + callbackUrl
		oa2.RegisterGoogleAuth(router, clientId, clientSecret, oauthCallbackUrl, a.SaveUserAndRedirect)
	}

	if os.Getenv("OAUTH2_GITHUB_CLIENT_ID") != "" {
		clientId := os.Getenv("OAUTH2_GITHUB_CLIENT_ID")
		clientSecret := os.Getenv("OAUTH2_GITHUB_CLIENT_SECRET")
		callbackUrl := os.Getenv("OAUTH2_GITHUB_CALLBACK_URL")
		oauthCallbackUrl := a.BaseUrl.String() + callbackUrl
		oa2.RegisterGithubAuth(router, clientId, clientSecret, oauthCallbackUrl, a.SaveUserAndRedirect)
	}

	if os.Getenv("SAML_CALLBACK_URL") != "" && os.Getenv("SAML_ISSUER") != "" {
		samlCallbackUrl := a.BaseUrl.String() + strings.TrimSpace(os.Getenv("SAML_CALLBACK_URL"))
		if err = saml.RegisterSamlAuth(router, samlCallbackUrl, a.SaveUserAndRedirect); err != nil {
			log.Fatal("Error registering SAML handlers: ", err)
			panic(err)
		}
	}
}

func (a *OneAuth) verifyJWT(tokenString string) (loggedInUserId string, t any, err error) {
	// Parse the token with the secret key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
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

func (a *OneAuth) onUserProfile(w http.ResponseWriter, r *http.Request) {
	// return the User's profile
	userId := a.Middleware.GetLoggedInUserId(r)
	log.Println("Logged In User: ", userId)
	if userId == "" {
		http.Error(w, `{"error": "User not logged in"}`, http.StatusUnauthorized)
	}
}

// For now we only accept JSON encoded username/password (as a proxy for Grafana)
func (a *OneAuth) onUsernameLogin(w http.ResponseWriter, r *http.Request) {
	grafanaAdminPassword := strings.TrimSpace(os.Getenv("GRAFANA_ADMIN_PASSWORD"))

	var data map[string]any
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil || data == nil {
		log.Println("Invalid post body: ", err)
		http.Error(w, `{"error": "Invalid Post Body"}`, http.StatusBadRequest)
		return
	}

	username, password := data["username"], data["password"]
	if username == nil || username == "" || password == "" || password == nil {
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	u, ok := username.(string)
	if !ok || u == "" {
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	p, ok := password.(string)
	if !ok || p == "" {
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	log.Println("Secret Key: ", a.JWTSecretKey, grafanaAdminPassword)
	log.Println("Username, Password: ", username, password)
	if username != "admin" || password != grafanaAdminPassword {
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	authToken := a.setLoggedInUser(&BasicUser{id: u}, w, r)
	fmt.Fprintf(w, `{"token": "%s"}`, authToken)
}

func (a *OneAuth) onLogout(w http.ResponseWriter, r *http.Request) {
	log.Println("Logging out user...")
	callbackURL := r.URL.Query().Get("callbackURL")
	if callbackURL == "" {
		callbackURL = "/"
	}
	log.Println("Callback URL: ", callbackURL)
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
func (a *OneAuth) SaveUserAndRedirect(authtype, provider string, token *oauth2.Token, userInfo map[string]interface{}, w http.ResponseWriter, r *http.Request) {
	// log.Println("Provider: ", provider)
	// log.Println("Token: ", token)
	// log.Println("userInfo: ", a.UserStore, userInfo)
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
	cookieDomains := []string{a.BaseUrl.Hostname()}
	for _, cookieDomain := range cookieDomains {
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
				Expires: time.Now().Add(3600 * time.Second), MaxAge: 3600,
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
				log.Println("error signing token: ", err)
			}

			a.Session.Put(r.Context(), a.AuthTokenSessionVar, tokenString)
			http.SetCookie(w, &http.Cookie{
				Name:    a.AuthTokenSessionVar,
				Value:   tokenString,
				Domain:  cookieDomain,
				Path:    "/",
				Expires: time.Now().Add(3600 * time.Second), MaxAge: 3600,
			})
			return tokenString
		} else {
			// clear the session and cookie values
			log.Println("Logging out user")
			// session.Set("loggedInUserId", "")
			if err := a.Session.Clear(r.Context()); err != nil {
				log.Println("Error clearning session: ", err)
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
