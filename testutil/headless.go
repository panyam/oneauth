package testutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Headless login helpers for exercises and interop tests that drive an
// authorization server without a person at a browser. Unlike the helpers in
// helpers.go they return errors instead of taking a *testing.T, so a
// standalone driver (a `make exercise-*` program) can use them too.

var csrfField = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// SignUp creates a user through oneauth-server's signup form at
// serverURL/auth/signup. The server signs a new user in, so hc's cookie jar
// holds that session afterwards, and a later /authorize on the same jar
// reaches the consent page (client.ApproveConsent then approves it). hc
// needs a Jar, since the session would otherwise be lost.
func SignUp(hc *http.Client, serverURL, email, password string) error {
	if hc.Jar == nil {
		return fmt.Errorf("signup needs a client with a cookie jar")
	}
	resp, err := hc.Get(serverURL + "/auth/signup")
	if err != nil {
		return fmt.Errorf("get signup form: %w", err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := csrfField.FindSubmatch(page)
	if m == nil {
		return fmt.Errorf("signup form has no csrf_token field (status %d)", resp.StatusCode)
	}
	form := url.Values{"csrf_token": {string(m[1])}, "email": {email}, "password": {password}}
	req, _ := http.NewRequest(http.MethodPost, serverURL+"/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", serverURL)
	resp, err = hc.Do(req)
	if err != nil {
		return fmt.Errorf("post signup: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("signup answered %d", resp.StatusCode)
	}
	return nil
}

// RegisterClient posts metadata as an RFC 7591 registration request to an
// open registration endpoint and returns the client_id. Any status other
// than 200 or 201, or a response without a client_id, is an error that
// quotes the start of the body.
//
// See: https://www.rfc-editor.org/rfc/rfc7591#section-3.1
func RegisterClient(hc *http.Client, registrationEndpoint string, metadata map[string]any) (string, error) {
	raw, _ := json.Marshal(metadata)
	resp, err := hc.Post(registrationEndpoint, "application/json", bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("dcr: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("dcr answered %d: %.300s", resp.StatusCode, body)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.ClientID == "" {
		return "", fmt.Errorf("dcr response has no client_id: %.300s", body)
	}
	return out.ClientID, nil
}

var keycloakLoginForm = regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)

// KeycloakPasswordLogin returns an OpenBrowser function for
// client.BrowserLoginRequest that fills in Keycloak's login form as
// username. client.FollowRedirects and client.ApproveConsent stop at that
// form on purpose. Keycloak then redirects to the redirect_uri, or for a
// form_post response mode serves a page that posts to it, which the
// function submits. Either way the login's loopback server receives the
// callback.
//
// Requests go through a copy of hc, so its Transport and CheckRedirect
// still apply; a driver uses them to watch the callback go by. The copy
// gets a fresh cookie jar, since Keycloak keys the form on a session. With
// hc nil it uses a 20-second timeout.
func KeycloakPasswordLogin(hc *http.Client, username, password string) func(string) error {
	browser := &http.Client{Timeout: 20 * time.Second}
	if hc != nil {
		copied := *hc
		browser = &copied
	}
	return func(authURL string) error {
		b := *browser
		b.Jar, _ = cookiejar.New(nil)
		resp, err := b.Get(authURL)
		if err != nil {
			return err
		}
		page, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		m := keycloakLoginForm.FindSubmatch(page)
		if m == nil {
			return fmt.Errorf("no Keycloak login form at %s (HTTP %d)", authURL, resp.StatusCode)
		}
		action, err := resp.Request.URL.Parse(html.UnescapeString(string(m[1])))
		if err != nil {
			return fmt.Errorf("keycloak login form action: %w", err)
		}
		resp, err = b.PostForm(action.String(), url.Values{
			"username": {username}, "password": {password}, "credentialId": {""},
		})
		if err != nil {
			return err
		}
		page, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		return submitFormPost(&b, resp.Request.URL, page)
	}
}

var (
	formPostForm  = regexp.MustCompile(`(?is)<form[^>]*method="post"[^>]*action="([^"]+)"[^>]*>(.*?)</form>`)
	formPostInput = regexp.MustCompile(`(?is)<input[^>]*type="hidden"[^>]*>`)
	formPostAttr  = regexp.MustCompile(`(?i)\b(name|value)="([^"]*)"`)
)

// submitFormPost posts the hidden fields of a form_post response page to
// its action, as the page's auto-submit script would in a browser. A page
// without a POST form is left alone, since a redirect already reached the
// redirect_uri.
//
// See: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
func submitFormPost(b *http.Client, base *url.URL, page []byte) error {
	m := formPostForm.FindSubmatch(page)
	if m == nil {
		return nil
	}
	action, err := base.Parse(html.UnescapeString(string(m[1])))
	if err != nil {
		return fmt.Errorf("form_post action: %w", err)
	}
	values := url.Values{}
	for _, input := range formPostInput.FindAll(m[2], -1) {
		var name, value string
		for _, a := range formPostAttr.FindAllSubmatch(input, -1) {
			if strings.EqualFold(string(a[1]), "name") {
				name = html.UnescapeString(string(a[2]))
			} else {
				value = html.UnescapeString(string(a[2]))
			}
		}
		if name != "" {
			values.Add(name, value)
		}
	}
	resp, err := b.PostForm(action.String(), values)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}
