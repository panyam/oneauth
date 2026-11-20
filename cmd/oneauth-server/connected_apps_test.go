package main

// The connected-apps page lists the clients a signed-in user approved,
// and disconnecting one withdraws the remembered consent and ends that
// client's sessions for the user: its refresh tokens stop working and its
// access tokens are blacklisted. The user comes from the session cookie,
// never from the form, so naming another user's client changes nothing
// for that user.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#Consent
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
// See: https://cwe.mitre.org/data/definitions/352.html
// See: https://cwe.mitre.org/data/definitions/639.html
// See: https://github.com/panyam/oneauth/issues/516

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	bobEmail    = "bob-connected@example.com"
	bobPassword = "another-correct-horse-battery"
)

func newConnectedAppsFixture(t *testing.T) *loginFixture {
	t.Helper()
	return newLoginFixtureConfig(t, "", "  consent:\n    remember: true\n    lifetime: 1h")
}

// registerNamedClient registers another public client through DCR.
func registerNamedClient(t *testing.T, f *loginFixture, name string) string {
	t.Helper()
	reg, _ := json.Marshal(map[string]any{
		"client_name":                name,
		"redirect_uris":              []string{f.redirect},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	resp, err := f.http.Post(f.url+"/apps/dcr", "application/json", strings.NewReader(string(reg)))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var app struct {
		ClientID string `json:"client_id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&app))
	return app.ClientID
}

// forClient is f aimed at another client, sharing f's cookies.
func (f *loginFixture) forClient(clientID string) *loginFixture {
	c := *f
	c.clientID = clientID
	return &c
}

// newBrowser is f with an empty cookie jar, for a second user.
func (f *loginFixture) newBrowser() *loginFixture {
	c := *f
	jar, _ := cookiejar.New(nil)
	c.http = &http.Client{Jar: jar, CheckRedirect: f.http.CheckRedirect}
	return &c
}

type issuedTokens struct {
	access, refresh string
}

// connectAs signs in as email, approves f's client and redeems the code.
func connectAs(t *testing.T, f *loginFixture, email, password string) issuedTokens {
	t.Helper()
	tok := redeemCodeAt(t, f, approveCodeAs(t, f, email, password, f.authorizePath()))
	at, _ := tok["access_token"].(string)
	rt, _ := tok["refresh_token"].(string)
	require.NotEmpty(t, at)
	require.NotEmpty(t, rt, "code redemption issues a refresh token")
	return issuedTokens{access: at, refresh: rt}
}

func (f *loginFixture) accessWorks(t *testing.T, token string) bool {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, f.url+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := f.http.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (f *loginFixture) refreshWorks(t *testing.T, token string) bool {
	t.Helper()
	resp, err := f.http.PostForm(f.url+"/api/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {f.clientID},
	})
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (f *loginFixture) signup(t *testing.T, email, password string) {
	t.Helper()
	f.postForm(t, "/auth/signup", "/auth/signup", url.Values{"email": {email}, "password": {password}})
}

func TestConnectedApps_ListsTheUsersApprovedClients(t *testing.T) {
	f := newConnectedAppsFixture(t)
	named := registerNamedClient(t, f, "Sketch Pad")
	connectAs(t, f, loginTestEmail, loginTestPassword)
	connectAs(t, f.forClient(named), loginTestEmail, loginTestPassword)

	bob := f.newBrowser()
	bob.signup(t, bobEmail, bobPassword)
	bobsOnly := registerNamedClient(t, f, "Bobs Only App")
	connectAs(t, bob.forClient(bobsOnly), bobEmail, bobPassword)

	resp, page := f.get(t, "/auth/connected-apps")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, page, f.clientID)
	assert.Contains(t, page, named)
	assert.Contains(t, page, "Sketch Pad", "the registered client_name")
	assert.Contains(t, page, `name="client_id" value="`+named+`"`, "a revoke form per app")
	assert.Regexp(t, loginCSRFField, page, "the revoke forms carry a CSRF token")
	assert.NotContains(t, page, bobsOnly, "another user's approval")
	assert.NotContains(t, page, "Bobs Only App")

	_, dash := f.get(t, "/dashboard")
	assert.Contains(t, dash, `href="/auth/connected-apps"`, "the dashboard links the page")
}

func TestConnectedApps_LoggedOutGoesToLogin(t *testing.T) {
	f := newConnectedAppsFixture(t)
	resp, _ := f.get(t, "/auth/connected-apps")
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/auth/login?next="+url.QueryEscape("/auth/connected-apps"), resp.Header.Get("Location"))

	resp, err := f.http.PostForm(f.url+"/auth/connected-apps/revoke", url.Values{"client_id": {f.clientID}})
	require.NoError(t, err)
	resp.Body.Close()
	assert.NotEqual(t, http.StatusSeeOther, resp.StatusCode, "no CSRF token, no session: refused, not redirected to success")
}

func TestConnectedApps_DisconnectEndsTheAppsSession(t *testing.T) {
	f := newConnectedAppsFixture(t)
	other := f.forClient(registerNamedClient(t, f, "Other App"))
	target := connectAs(t, f, loginTestEmail, loginTestPassword)
	kept := connectAs(t, other, loginTestEmail, loginTestPassword)

	resp := f.postForm(t, "/auth/connected-apps", "/auth/connected-apps/revoke", url.Values{"client_id": {f.clientID}})
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/auth/connected-apps?revoked=1", resp.Header.Get("Location"))

	_, page := f.get(t, "/auth/connected-apps?revoked=1")
	assert.NotContains(t, page, `value="`+f.clientID+`"`, "the disconnected app is gone")
	assert.Contains(t, page, other.clientID)

	assert.False(t, f.accessWorks(t, target.access), "the app's access token is blacklisted")
	assert.False(t, f.refreshWorks(t, target.refresh), "the app's refresh token is revoked")
	assert.True(t, other.accessWorks(t, kept.access), "another app's access token")
	assert.True(t, other.refreshWorks(t, kept.refresh), "another app's refresh token")

	resp, _ = f.get(t, withQuery(t, f.authorizePath(), "prompt", "none"))
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "consent_required", mustURL(t, resp.Header.Get("Location")).Query().Get("error"),
		"the app has to ask for consent again")
}

func TestConnectedApps_DisconnectNeedsCSRFToken(t *testing.T) {
	f := newConnectedAppsFixture(t)
	tok := connectAs(t, f, loginTestEmail, loginTestPassword)

	form := url.Values{"client_id": {f.clientID}}
	req, _ := http.NewRequest(http.MethodPost, f.url+"/auth/connected-apps/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.url)
	resp, err := f.http.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	_, page := f.get(t, "/auth/connected-apps")
	assert.Contains(t, page, `value="`+f.clientID+`"`, "still connected")
	assert.True(t, f.accessWorks(t, tok.access))
}

// A user who names another user's client, and even that user, revokes
// only their own grant for it, which here is nothing.
func TestConnectedApps_CannotDisconnectAnotherUsersApp(t *testing.T) {
	f := newConnectedAppsFixture(t)
	bob := f.newBrowser()
	bob.signup(t, bobEmail, bobPassword)
	bobs := connectAs(t, bob, bobEmail, bobPassword)
	connectAs(t, f.forClient(registerNamedClient(t, f, "Alice App")), loginTestEmail, loginTestPassword)

	bobSub := subjectOf(t, bob, bobs.access)
	resp := f.postForm(t, "/auth/connected-apps", "/auth/connected-apps/revoke", url.Values{
		"client_id": {f.clientID}, "subject": {bobSub}, "sub": {bobSub}, "user_id": {bobSub},
	})
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)

	_, page := bob.get(t, "/auth/connected-apps")
	assert.Contains(t, page, `value="`+f.clientID+`"`, "bob is still connected")
	assert.True(t, bob.accessWorks(t, bobs.access))
	assert.True(t, bob.refreshWorks(t, bobs.refresh))
}

func TestConnectedApps_DisconnectNeedsAClientID(t *testing.T) {
	f := newConnectedAppsFixture(t)
	connectAs(t, f, loginTestEmail, loginTestPassword)
	resp := f.postForm(t, "/auth/connected-apps", "/auth/connected-apps/revoke", url.Values{})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// Without remembered consent there is nothing to list, so the page isn't
// served and the dashboard doesn't link it.
func TestConnectedApps_NotServedWithoutRememberedConsent(t *testing.T) {
	f := newLoginFixture(t)
	approveCode(t, f, f.authorizePath())
	resp, _ := f.get(t, "/auth/connected-apps")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	_, dash := f.get(t, "/dashboard")
	assert.NotContains(t, dash, "/auth/connected-apps")
}
