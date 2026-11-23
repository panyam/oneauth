package oidctest

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type authCode struct {
	sub, clientID, redirectURI, challenge, nonce, scope string
}

type deviceGrant struct {
	clientID, userCode, scope string
	expires                   time.Time
	sub                       string // set by Approve
	denied, used              bool
	lastPoll                  time.Time
}

// authorize answers the authorization endpoint for the person SignInAs
// picked. An unknown client, or a redirect_uri the client didn't
// register, answers 400 here and redirects nowhere (RFC 6749 §4.1.2.1).
// Every other error goes back to the redirect_uri, with state and iss
// (RFC 9207).
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID, redirectURI := q.Get("client_id"), q.Get("redirect_uri")
	if _, ok := s.clients[clientID]; !ok {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	back, ok := s.registeredRedirect(clientID, redirectURI)
	if !ok {
		http.Error(w, "redirect_uri is not registered for this client; pass it to WithClient", http.StatusBadRequest)
		return
	}
	reply := func(params url.Values) {
		bq := back.Query()
		for k, v := range params {
			bq[k] = v
		}
		if st := q.Get("state"); st != "" {
			bq.Set("state", st)
		}
		bq.Set("iss", s.URL)
		back.RawQuery = bq.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	}
	fail := func(code, desc string) {
		reply(url.Values{"error": {code}, "error_description": {desc}})
	}

	switch {
	case q.Get("response_type") != "code":
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	case !hasScope(q.Get("scope"), "openid"):
		fail("invalid_scope", "scope must include openid")
		return
	case q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}

	s.mu.Lock()
	sub := s.signedIn
	if sub == "" {
		s.mu.Unlock()
		fail("login_required", "no user signed in; call SignInAs")
		return
	}
	code := randomToken()
	s.codes[code] = &authCode{
		sub: sub, clientID: clientID, redirectURI: redirectURI,
		challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), scope: q.Get("scope"),
	}
	s.mu.Unlock()
	reply(url.Values{"code": {code}})
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	clientID, ok := s.authenticateClient(r)
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.codeGrant(w, r, clientID)
	case "urn:ietf:params:oauth:grant-type:device_code":
		s.deviceGrant(w, r, clientID)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

// codeGrant redeems a code once. A second try with the same code fails
// even when the first failed, as RFC 6749 §4.1.2 allows.
func (s *Server) codeGrant(w http.ResponseWriter, r *http.Request, clientID string) {
	s.mu.Lock()
	c := s.codes[r.PostForm.Get("code")]
	delete(s.codes, r.PostForm.Get("code"))
	s.mu.Unlock()
	switch {
	case c == nil || c.clientID != clientID:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code not valid")
	case r.PostForm.Get("redirect_uri") != c.redirectURI:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
	case pkceChallenge(r.PostForm.Get("code_verifier")) != c.challenge:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
	default:
		s.issue(w, c.sub, clientID, c.nonce, c.scope)
	}
}

// deviceGrant answers a poll with the RFC 8628 §3.5 error for the code's
// state, or tokens once it was approved. A device code yields tokens once.
// A poll sooner than the advertised interval after the last one, less
// pollJitter, answers slow_down, as Keycloak does, whatever the code's state. The first poll
// may come at any time.
func (s *Server) deviceGrant(w http.ResponseWriter, r *http.Request, clientID string) {
	s.mu.Lock()
	g := s.devices[r.PostForm.Get("device_code")]
	var errCode, sub, scope string
	now := time.Now()
	var last time.Time
	if g != nil {
		last, g.lastPoll = g.lastPoll, now
	}
	switch {
	case g == nil || g.clientID != clientID || g.used:
		errCode = "invalid_grant"
	case !last.IsZero() && now.Sub(last) < s.pollInterval()-pollJitter:
		errCode = "slow_down"
	case time.Now().After(g.expires):
		errCode = "expired_token"
	case g.denied:
		errCode = "access_denied"
	case g.sub == "":
		errCode = "authorization_pending"
	default:
		g.used = true
		sub, scope = g.sub, g.scope
	}
	s.mu.Unlock()
	if errCode != "" {
		oauthError(w, http.StatusBadRequest, errCode, "")
		return
	}
	s.issue(w, sub, clientID, "", scope)
}

func (s *Server) issue(w http.ResponseWriter, sub, clientID, nonce, scope string) {
	at := randomToken()
	idToken, err := s.idToken(sub, clientID, nonce, at)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	s.mu.Lock()
	s.access[at] = sub
	s.mu.Unlock()
	resp := map[string]any{
		"access_token": at, "token_type": "Bearer", "expires_in": 300,
		"id_token": idToken, "scope": scope,
	}
	for _, edit := range s.tokenResponse {
		edit(resp)
	}
	writeJSON(w, http.StatusOK, resp)
}

// deviceAuthorization starts a device grant. A confidential client must
// authenticate here too (RFC 8628 §3.1), as Keycloak requires.
func (s *Server) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	clientID, ok := s.authenticateClient(r)
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	dc, uc := randomToken(), userCode()
	s.mu.Lock()
	s.devices[dc] = &deviceGrant{
		clientID: clientID, userCode: uc, scope: r.PostForm.Get("scope"),
		expires: time.Now().Add(s.deviceExpiry),
	}
	s.byUser[uc] = dc
	s.mu.Unlock()
	interval := int(s.pollInterval() / time.Second)
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               dc,
		"user_code":                 uc,
		"verification_uri":          s.URL + "/device",
		"verification_uri_complete": s.URL + "/device?user_code=" + url.QueryEscape(uc),
		"expires_in":                int(s.deviceExpiry / time.Second),
		"interval":                  interval,
	})
}

// pollJitter is how much sooner than the interval a poll may come without
// slow_down. A client polling on a ticker lands a few milliseconds either
// side of the interval.
const pollJitter = 200 * time.Millisecond

// pollInterval is the device polling interval in whole seconds, at least
// one, since the response carries an integer and clients treat 0 as 5.
func (s *Server) pollInterval() time.Duration {
	d := s.deviceInterval.Truncate(time.Second)
	if d < time.Second {
		d = time.Second
	}
	return d
}

// verificationPage is the verification_uri. No person visits it in a
// test, so it only says how to answer the code.
func (s *Server) verificationPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("oidctest: answer this code with Server.Approve or Server.Deny\n"))
}

// Approve stands in for the person sub entering userCode at the
// verification page and agreeing. The next poll for that device code gets
// tokens for sub. It reports false when the user code is unknown, already
// answered, or expired, or when sub was never added.
func (s *Server) Approve(userCode, sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.pendingLocked(userCode)
	if g == nil {
		return false
	}
	if _, ok := s.users[sub]; !ok {
		return false
	}
	g.sub = sub
	return true
}

// Deny stands in for the person refusing userCode. The next poll gets
// access_denied. It reports false when the user code is unknown, already
// answered, or expired.
func (s *Server) Deny(userCode string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.pendingLocked(userCode)
	if g == nil {
		return false
	}
	g.denied = true
	return true
}

func (s *Server) pendingLocked(userCode string) *deviceGrant {
	g := s.devices[s.byUser[userCode]]
	if g == nil || g.sub != "" || g.denied || time.Now().After(g.expires) {
		return nil
	}
	return g
}

// logout answers RP-initiated logout. It redirects to
// post_logout_redirect_uri with state when that URI is registered for
// client_id, as Keycloak does for a client whose post-logout URIs are its
// redirect URIs. Otherwise it answers with a page and redirects nowhere.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	back, ok := s.registeredRedirect(q.Get("client_id"), q.Get("post_logout_redirect_uri"))
	if !ok {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("logged out"))
		return
	}
	if st := q.Get("state"); st != "" {
		bq := back.Query()
		bq.Set("state", st)
		back.RawQuery = bq.Encode()
	}
	http.Redirect(w, r, back.String(), http.StatusFound)
}

// registeredRedirect finds uri among clientID's registered redirect URIs
// and returns the registered copy, parsed. The redirect target then comes
// from the test's own configuration, never from the request.
func (s *Server) registeredRedirect(clientID, uri string) (*url.URL, bool) {
	for _, reg := range s.redirects[clientID] {
		if reg == uri {
			u, err := url.Parse(reg)
			return u, err == nil && u.IsAbs()
		}
	}
	return nil, false
}

// authenticateClient reads client credentials from HTTP Basic auth or the
// form (client_secret_basic, client_secret_post), or client_id alone for a
// public client. It parses the form, so callers read r.PostForm after it.
func (s *Server) authenticateClient(r *http.Request) (string, bool) {
	_ = r.ParseForm()
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	want, ok := s.clients[id]
	if !ok || subtle.ConstantTimeCompare([]byte(secret), []byte(want)) != 1 {
		return "", false
	}
	return id, true
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	body := map[string]any{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidctest"`)
	}
	writeJSON(w, status, body)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func hasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// userCode is eight letters as XXXX-XXXX, from an alphabet without vowels
// or look-alikes, as RFC 8628 §6.1 suggests.
func userCode() string {
	const alphabet = "BCDFGHJKLMNPQRSTVWXZ"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("oidctest: " + err.Error())
	}
	out := make([]byte, 0, 9)
	for i, c := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(c)%len(alphabet)])
	}
	return string(out)
}
