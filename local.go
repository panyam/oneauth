package oneauth

import (
	"encoding/json"
	"log"
	"log/slog"
	"net/http"

	"golang.org/x/oauth2"
)

type HandleUserFunc func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request)

// Allows local username/password based authentication
type LocalAuth struct {
	// A function that can validate username/passwords
	ValidateUsernamePassword func(username string, password string) (User, error)
	Provider                 string
	UsernameField            string
	PasswordField            string
	HandleUser               HandleUserFunc
}

// For now we only accept JSON encoded username/password (as a proxy for Grafana)
func (a *LocalAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("ContnetType: ", r.Header)
	contentType := r.Header.Get("Content-Type")
	usernameField := "username"
	if a.UsernameField != "" {
		usernameField = a.UsernameField
	}
	passwordField := "password"
	if a.PasswordField != "" {
		passwordField = a.PasswordField
	}

	var username, password any
	if contentType == "application/x-www-form-urlencoded" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		username = r.FormValue(usernameField)
		password = r.FormValue(passwordField)
	} else {
		// form post
		var data map[string]any
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil || data == nil {
			slog.Error("Invalid post body: ", "err", err)
			http.Error(w, `{"error": "Invalid Post Body"}`, http.StatusBadRequest)
			return
		}
		username, password = data[usernameField], data[passwordField]
		if username == nil || username == "" || password == "" || password == nil {
			http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
			return
		}
	}
	log.Println("Username, password: ", usernameField, username, passwordField, password)
	u, ok := username.(string)
	if !ok || u == "" {
		http.Error(w, `{"error": "Invalid username"}`, http.StatusUnauthorized)
		return
	}
	p, ok := password.(string)
	if !ok || p == "" {
		http.Error(w, `{"error": "Invalid password"}`, http.StatusUnauthorized)
		return
	}

	log.Println("Username, Password: ", username, password)
	user, err := a.ValidateUsernamePassword(u, p)
	if err != nil || user == nil {
		if err != nil {
			log.Println("error validating user: ", err)
		}
		// if !username != "admin" || password != grafanaAdminPassword {
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	token := &oauth2.Token{
		AccessToken:  "AccessTokenLocal",
		RefreshToken: "RefreshTokenLocal",
		TokenType:    "Bearer",
		ExpiresIn:    86400,
	}
	userInfo := map[string]any{
		"email": username,
	}
	a.HandleUser("local", a.Provider, token, userInfo, w, r)
	// fmt.Fprintf(w, `{"token": "%s"}`, authToken)
}
