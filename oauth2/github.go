package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type GithubOAuth2 struct {
	*BaseOAuth2
}

func NewGithubOAuth2(clientId string, clientSecret string, callbackUrl string, handleUser HandleUserFunc) *GithubOAuth2 {
	if clientId == "" {
		clientId = os.Getenv("OAUTH2_GITHUB_CLIENT_ID")
	}
	if clientSecret == "" {
		clientSecret = os.Getenv("OAUTH2_GITHUB_CLIENT_SECRET")
	}
	if callbackUrl == "" {
		callbackUrl = os.Getenv("OAUTH2_GITHUB_CALLBACK_URL")
	}

	out := GithubOAuth2{
		BaseOAuth2: NewBaseOAuth2(clientId, clientSecret, callbackUrl),
	}

	// rg.HandleFunc("/google/callback/", func(w http.ResponseWriter, r *http.Request) {
	out.mux.HandleFunc("/callback/", out.handleCallback)

	return &out
}

func RegisterGithubAuth(rg *mux.Router, clientId string, clientSecret string, callbackUrl string, handleUser HandleUserFunc) {
	oauthConfig := &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  callbackUrl,
		Scopes: []string{
			"https://www.githubapis.com/auth/userinfo.email",
			"https://www.githubapis.com/auth/userinfo.profile",
		},
		Endpoint: github.Endpoint,
	}

	rg.HandleFunc("/github", OauthRedirector(oauthConfig))

	// An "easier" way to login by github if we already have the access tokens
	// If the access tokens have expired then the user would have to re login
	/*
		rg.HandleFunc("/github/login/", func(w http.ResponseWriter, r *http.Request) {
			var token oauth2.Token
			var err error
			if err = ctx.BindJSON(&token); err != nil {
				log.Println("Bind Error: ", err)
				// TOCHECK - should this be json?
				http.Error(w, err.Error(), http.StatusBadRequest)
			} else {
				userInfo, err := validateGithubAccessTokenToken(w, r, &token)
				if err != nil {
					// TOCHECK - should this be json?
					http.Error(w, "Could not validate access token", http.StatusBadRequest)
				} else {
					handleUser("github", &token, userInfo, w, r)
				}
			}
		}).Methods("POST")
	*/

	rg.HandleFunc("/github/callback/", func(w http.ResponseWriter, r *http.Request) {
		oauthState, _ := r.Cookie("oauthstate")
		log.Println("OauthState: ", oauthState)
		log.Println("FormState: ", r.FormValue("state"), "==?", r.URL.Query().Get("state"))
		if oauthState == nil {
			http.Error(w, fmt.Sprintf("OauthState is nil"), http.StatusBadRequest)
			return
		}
		if r.FormValue("state") != oauthState.Value {
			http.SetCookie(w, &http.Cookie{
				Name:   "oauthstate",
				MaxAge: 0,
			})
			http.Error(w, fmt.Sprintf("invalid oauth github state: %s, CookieOauthState: %s", r.FormValue("state"), oauthState.Value), http.StatusBadRequest)
			// ctx.Redirect(http.StatusFound, "/auth/github/fail/")
			return
		}

		// Get auth token
		var userInfo map[string]any
		code := r.FormValue("code")
		// token, err := getAuthTokens(oauthConfig, code)
		token, err := oauthConfig.Exchange(context.Background(), code)
		if err != nil {
			log.Println("code exchange wrong: ", err)
		} else {
			log.Println("Received Token: ", token)
			userInfo, err = validateGithubAccessTokenToken(token)
			if err == nil {
				handleUser("oauth", "github", token, userInfo, w, r)
			}
		}
		if err != nil {
			http.Redirect(w, r, "/auth/github/fail/", http.StatusTemporaryRedirect)
		}
	}).Methods("GET")
}

func validateGithubAccessTokenToken(token *oauth2.Token) (userInfo map[string]any, err error) {
	log.Println("Validating Token: ", token)
	if err == nil {
		var data []byte
		data, err = getUserDataFromGithub(token)
		if err == nil {
			err = json.Unmarshal(data, &userInfo)
		}
	}
	if err != nil {
		log.Println("Error validating login tokens: ", err.Error())
	}
	return
}

func getUserDataFromGithub(token *oauth2.Token) ([]byte, error) {
	// Use code to get token and get user info from Github.
	log.Println("Getting User dat from github....")
	const oauthGithubUrlAPI = "https://www.githubapis.com/oauth2/v2/userinfo?access_token="
	response, err := http.Get(oauthGithubUrlAPI + token.AccessToken)
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
