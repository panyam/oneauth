package oauth2

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	ghttp "github.com/panyam/goutils/http"
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
		BaseOAuth2: NewBaseOAuth2(clientId, clientSecret, callbackUrl, handleUser),
	}
	out.BaseOAuth2.oauthConfig.Endpoint = github.Endpoint
	out.BaseOAuth2.oauthConfig.Scopes = []string{
		"read:user", "user:email",
	}

	// rg.HandleFunc("/google/callback/", func(w http.ResponseWriter, r *http.Request) {
	out.mux.HandleFunc("/callback/", out.handleCallback)

	return &out
}

func (g *GithubOAuth2) handleCallback(w http.ResponseWriter, r *http.Request) {
	oauthState, _ := r.Cookie("oauthstate")
	log.Println("OauthState: ", oauthState)
	log.Println("FormState: ", r.FormValue("state"), "==?", r.URL.Query().Get("state"))
	if oauthState == nil {
		http.Error(w, "OauthState is nil", http.StatusBadRequest)
		return
	}
	if r.FormValue("state") != oauthState.Value {
		http.SetCookie(w, &http.Cookie{
			Name:   "oauthstate",
			MaxAge: 0,
		})
		http.Error(w, fmt.Sprintf("invalid oauth github state: %s, CookieOauthState: %s", r.FormValue("state"), oauthState.Value), http.StatusBadRequest)
		// ctx.Redirect(http.StatusFound, g.AuthFailureUrl)
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
		userInfo, err = validateGithubAccessTokenToken(token)
		if err == nil {
			g.HandleUser("oauth", "github", token, userInfo, w, r)
		}
	}
	if err != nil {
		http.Redirect(w, r, g.AuthFailureUrl, http.StatusTemporaryRedirect)
	}
}

func validateGithubAccessTokenToken(token *oauth2.Token) (userInfo map[string]any, err error) {
	log.Println("Validating Token: ", token)
	response, err := getUserDataFromGithub(token)
	if err == nil {
		if userInfo, ok := response.(map[string]any); !ok {
			return nil, nil
		} else {
			return userInfo, nil
		}
	}
	if err != nil {
		log.Println("Error validating login tokens: ", err.Error())
	}
	return
}

func getUserDataFromGithub(token *oauth2.Token) (any, error) {
	// Use code to get token and get user info from Github.
	log.Println("Getting User data from github....")
	req, _ := ghttp.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", token.AccessToken)
	// response, err := http.Get(oauthGithubUrlAPI + token.AccessToken)
	return ghttp.Call(req, nil)
}
