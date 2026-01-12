package oauth2

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type GithubOAuth2 struct {
	*BaseOAuth2

	// UserInfoURL is the URL to fetch user info from. Defaults to GitHub's API.
	// Can be overridden for testing.
	UserInfoURL string
}

func NewGithubOAuth2(clientId string, clientSecret string, callbackUrl string, handleUser HandleUserFunc) *GithubOAuth2 {
	if clientId == "" {
		clientId = strings.TrimSpace(os.Getenv("OAUTH2_GITHUB_CLIENT_ID"))
	}
	if clientSecret == "" {
		clientSecret = strings.TrimSpace(os.Getenv("OAUTH2_GITHUB_CLIENT_SECRET"))
	}
	if callbackUrl == "" {
		callbackUrl = strings.TrimSpace(os.Getenv("OAUTH2_GITHUB_CALLBACK_URL"))
	}

	out := GithubOAuth2{
		BaseOAuth2:  NewBaseOAuth2(clientId, clientSecret, callbackUrl, handleUser),
		UserInfoURL: "https://api.github.com/user",
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
	// log.Println("OauthState: ", oauthState, "FormState: ", r.FormValue("state"), "==?", r.URL.Query().Get("state"))
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
	token, err := g.oauthConfig.Exchange(g.ExchangeContext(), code)
	if err != nil {
		slog.Info("Invalid code exchange", "err", err)
	} else {
		// log.Println("Received Token Type: ", reflect.TypeOf(token))
		// log.Println("Received Token: ", token)
		userInfo, err = g.validateAccessToken(token)
		if err == nil {
			g.HandleUser("oauth", "github", token, userInfo, w, r)
		}
	}
	if err != nil {
		slog.Info("redirecting due to error ", "err", err)
		http.Redirect(w, r, g.AuthFailureUrl, http.StatusTemporaryRedirect)
	}
}

func (g *GithubOAuth2) validateAccessToken(token *oauth2.Token) (userInfo map[string]any, err error) {
	log.Println("Validating Token: ", token)
	userInfo, err = g.getUserData(token)
	if err != nil {
		slog.Info("error validating tokens", "err", err)
	}
	return
}

func (g *GithubOAuth2) getUserData(token *oauth2.Token) (map[string]any, error) {
	// Use code to get token and get user info from Github.
	log.Println("Getting User data from github....")
	req, err := http.NewRequest("GET", g.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %s", err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")

	// Use injectable client if set
	client := g.getHTTPClient()
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info from github: %s", err.Error())
	}
	defer response.Body.Close()

	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}

	var userInfo map[string]any
	if err := json.Unmarshal(contents, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %s", err.Error())
	}
	return userInfo, nil
}
