package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleOAuth2 struct {
	*BaseOAuth2
}

func NewGoogleOAuth2(clientId string, clientSecret string, callbackUrl string, handleUser HandleUserFunc) *GoogleOAuth2 {
	if clientId == "" {
		clientId = os.Getenv("OAUTH2_GOOGLE_CLIENT_ID")
	}
	if clientSecret == "" {
		clientSecret = os.Getenv("OAUTH2_GOOGLE_CLIENT_SECRET")
	}
	if callbackUrl == "" {
		callbackUrl = os.Getenv("OAUTH2_GOOGLE_CALLBACK_URL")
	}

	out := GoogleOAuth2{
		BaseOAuth2: NewBaseOAuth2(clientId, clientSecret, callbackUrl),
	}
	out.BaseOAuth2.oauthConfig.Endpoint = google.Endpoint
	out.BaseOAuth2.oauthConfig.Scopes = []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	}

	// rg.HandleFunc("/google/callback/", func(w http.ResponseWriter, r *http.Request) {
	out.mux.HandleFunc("/callback/", out.handleCallback)

	return &out
}

func (g *GoogleOAuth2) handleCallback(w http.ResponseWriter, r *http.Request) {
	oauthState, _ := r.Cookie("oauthstate")
	// log.Println("OauthState: ", oauthState, "FormState: ", r.FormValue("state"), "==?", r.URL.Query().Get("state"))
	if oauthState == nil {
		log.Println("oauth state is nil")
		http.Error(w, "OauthState is nil", http.StatusBadRequest)
		return
	}
	if r.FormValue("state") != oauthState.Value {
		http.SetCookie(w, &http.Cookie{
			Name:   "oauthstate",
			MaxAge: 0,
		})
		http.Error(w, fmt.Sprintf("invalid oauth google state: %s, CookieOauthState: %s", r.FormValue("state"), oauthState.Value), http.StatusBadRequest)
		// ctx.Redirect(http.StatusFound, "/auth/google/fail/")
		return
	}

	// Get auth token
	var userInfo map[string]any
	code := r.FormValue("code")
	// token, err := getAuthTokens(oauthConfig, code)
	token, err := g.oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Println("code exchange wrong: ", err)
	} else {
		// log.Println("Received Token Type: ", reflect.TypeOf(token))
		// log.Println("Received Token: ", token)
		userInfo, err = validateGoogleAccessTokenToken(token)
		if err == nil {
			g.HandleUser("oauth", "google", token, userInfo, w, r)
		}
	}
	if err != nil {
		log.Println("Error, so redirecting: ", err)
		http.Redirect(w, r, "/auth/google/fail/", http.StatusTemporaryRedirect)
	}
}

func validateGoogleAccessTokenToken(token *oauth2.Token) (userInfo map[string]any, err error) {
	log.Println("Validating Token ...")
	var data []byte
	data, err = getUserDataFromGoogle(token)
	if err == nil {
		err = json.Unmarshal(data, &userInfo)
	}
	if err != nil {
		log.Println("Error validating login tokens: ", err.Error())
	}
	return
}

func getUserDataFromGoogle(token *oauth2.Token) ([]byte, error) {
	// Use code to get token and get user info from Google.
	const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	log.Println("Getting User data from google: ", oauthGoogleUrlAPI)
	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, nil
}
