package oauth2

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type GithubOAuth2 struct {
	*BaseOAuth2

	// UserInfoURL is where the callback fetches the signed-in person's
	// profile, with the access token as a Bearer header. It defaults to
	// https://api.github.com/user. SetEnterpriseURL sets it for a GitHub
	// Enterprise host, and a test can point it at a fake. A status other
	// than 200 fails the sign-in.
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
	if !VerifyState(w, r) {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}

	// Get auth token
	var userInfo map[string]any
	code := r.FormValue("code")

	// PKCE: read code_verifier from cookie and include in token exchange
	var exchangeOpts []oauth2.AuthCodeOption
	if !g.DisablePKCE {
		verifier := GetPKCEVerifier(r)
		if verifier == "" {
			http.Error(w, "PKCE verifier missing — authorization flow may have expired", http.StatusBadRequest)
			return
		}
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam("code_verifier", verifier))
		ClearPKCECookie(w)
	}

	token, err := g.oauthConfig.Exchange(g.ExchangeContext(), code, exchangeOpts...)
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
	userInfo, err = g.getUserData(token)
	if err != nil {
		slog.Info("error validating tokens", "err", err)
	}
	return
}

func (g *GithubOAuth2) getUserData(token *oauth2.Token) (map[string]any, error) {
	slog.Debug("fetching GitHub user info", "url", g.UserInfoURL)
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
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github user info returned %s", response.Status)
	}

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

// SetEnterpriseURL points the sign-in at a GitHub Enterprise host, given as
// its base URL such as https://ghe.example.com. It sets the authorize,
// token and device URLs on that host, and sets UserInfoURL to the host's
// API. A GitHub Enterprise Server host serves its API under /api/v3. A
// GHE.com host such as https://acme.ghe.com serves it at
// https://api.acme.ghe.com.
//
// The URL must be https with no path, query or fragment. http is allowed
// only for a loopback host, so a test can run a fake server. On an error
// nothing changes. Call it before serving, like SetScopes.
func (g *GithubOAuth2) SetEnterpriseURL(baseURL string) error {
	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("github enterprise URL %q: %w", baseURL, err)
	}
	if u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("github enterprise URL %q must be a scheme and host only", baseURL)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return fmt.Errorf("github enterprise URL %q must use https", baseURL)
	}
	base := u.Scheme + "://" + u.Host
	userInfo := base + "/api/v3/user"
	if strings.HasSuffix(strings.ToLower(u.Hostname()), ".ghe.com") {
		userInfo = u.Scheme + "://api." + u.Host + "/user"
	}
	g.SetOAuthEndpoint(oauth2.Endpoint{
		AuthURL:       base + "/login/oauth/authorize",
		TokenURL:      base + "/login/oauth/access_token",
		DeviceAuthURL: base + "/login/device/code",
	})
	g.UserInfoURL = userInfo
	return nil
}
