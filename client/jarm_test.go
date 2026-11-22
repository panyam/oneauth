package client

// Signed authorization responses (JARM, issue 412). With a JARM
// response_mode, LoginWithBrowser takes code and state only from a
// `response` JWT that verifies against the AS's JWKS, names the AS as iss
// and this client as aud, and hasn't expired.
//
// See: https://openid.net/specs/oauth-v2-jarm.html#section-2.4
// See: https://github.com/panyam/oneauth/issues/412

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const jarmClientID = "jarm-cli"

// jarmKey is an ES256 signing key and its kid.
type jarmKey struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func newJARMKey(t *testing.T) *jarmKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kid, err := utils.ComputeKid(priv, "ES256")
	require.NoError(t, err)
	return &jarmKey{priv: priv, kid: kid}
}

func (k *jarmKey) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = k.kid
	s, err := tok.SignedString(k.priv)
	require.NoError(t, err)
	return s
}

func (k *jarmKey) lookup() staticKeys {
	return staticKeys{k.kid: {Key: &k.priv.PublicKey, Algorithm: "ES256"}}
}

func goodJARMClaims(issuer string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": issuer, "aud": jarmClientID, "exp": time.Now().Add(time.Minute).Unix(),
		"code": "c-1", "state": "s-1",
	}
}

func verifyJARM(k *jarmKey, response string) (url.Values, error) {
	return VerifyAuthorizationResponse(context.Background(), &VerifyAuthorizationResponseRequest{
		Response: response, Issuer: "https://as.example", ClientID: jarmClientID, Keys: k.lookup(),
	})
}

func TestVerifyAuthorizationResponse_Good(t *testing.T) {
	k := newJARMKey(t)
	params, err := verifyJARM(k, k.sign(t, goodJARMClaims("https://as.example")))
	require.NoError(t, err)
	assert.Equal(t, "c-1", params.Get("code"))
	assert.Equal(t, "s-1", params.Get("state"))
	assert.Equal(t, "https://as.example", params.Get("iss"))
	assert.Empty(t, params.Get("aud"), "checked, so left out")
}

// Each of these is a response a client must refuse (JARM §2.4).
// See: https://openid.net/specs/oauth-v2-jarm.html#section-2.4
func TestVerifyAuthorizationResponse_Refusals(t *testing.T) {
	k := newJARMKey(t)
	other := newJARMKey(t)
	with := func(change func(jwt.MapClaims)) string {
		c := goodJARMClaims("https://as.example")
		change(c)
		return k.sign(t, c)
	}
	good := k.sign(t, goodJARMClaims("https://as.example"))
	parts := strings.Split(good, ".")
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"`+k.kid+`"}`)) + "." + parts[1] + "."
	hmac := jwt.NewWithClaims(jwt.SigningMethodHS256, goodJARMClaims("https://as.example"))
	hmac.Header["kid"] = k.kid
	hmacSigned, err := hmac.SignedString([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	foreign := other.sign(t, goodJARMClaims("https://as.example"))

	for name, response := range map[string]string{
		"another AS's iss (mix-up)": with(func(c jwt.MapClaims) { c["iss"] = "https://evil.example" }),
		"another client's aud":      with(func(c jwt.MapClaims) { c["aud"] = "someone-else" }),
		"expired":                   with(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }),
		"no exp":                    with(func(c jwt.MapClaims) { delete(c, "exp") }),
		"tampered payload":          parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://as.example","aud":"jarm-cli","code":"evil","exp":9999999999}`)) + "." + parts[2],
		"alg none":                  none,
		"HMAC":                      hmacSigned,
		"key not in the JWKS":       foreign,
		"not a JWT":                 "garbage",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := verifyJARM(k, response)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrUnverifiedAuthorizationResponse), "got %v", err)
		})
	}
}

// Keycloak 26 puts iss in its JARM JWT twice, with the same value. The
// last value wins, as encoding/json has it, so the response verifies.
func TestVerifyAuthorizationResponse_DuplicateIssClaim(t *testing.T) {
	k := newJARMKey(t)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT","kid":"` + k.kid + `"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"exp":%d,"iss":"https://as.example","aud":"jarm-cli","code":"c-1","iss":"https://as.example","state":"s-1"}`,
		time.Now().Add(time.Minute).Unix())))
	sig, err := jwt.SigningMethodES256.Sign(header+"."+payload, k.priv)
	require.NoError(t, err)
	params, err := verifyJARM(k, header+"."+payload+"."+base64.RawURLEncoding.EncodeToString(sig))
	require.NoError(t, err)
	assert.Equal(t, "c-1", params.Get("code"))
}

// jarmAS is an authorization server that answers every authorization
// request with a JARM response. mutate, when set, changes the claims
// before signing, to play a forger or a misbehaving AS.
type jarmAS struct {
	*httptest.Server
	key       *jarmKey
	mu        sync.Mutex
	challenge string
	mutate    func(claims jwt.MapClaims, q url.Values)
	plain     bool // answer with a plain ?code= instead of a JWT
}

func newJARMAS(t *testing.T) *jarmAS {
	t.Helper()
	as := &jarmAS{key: newJARMKey(t)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": as.URL, "authorization_endpoint": as.URL + "/authorize", "token_endpoint": as.URL + "/token",
			"jwks_uri": as.URL + "/jwks", "code_challenge_methods_supported": []string{"S256"},
			"response_modes_supported": []string{"query", "jwt", "query.jwt", "form_post.jwt"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk, err := utils.PublicKeyToJWK(as.key.kid, "ES256", &as.key.priv.PublicKey)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		as.mu.Lock()
		as.challenge = q.Get("code_challenge")
		as.mu.Unlock()
		cb, _ := url.Parse(q.Get("redirect_uri"))
		if as.plain {
			cb.RawQuery = url.Values{"code": {"code-1"}, "state": {q.Get("state")}}.Encode()
			http.Redirect(w, r, cb.String(), http.StatusFound)
			return
		}
		claims := jwt.MapClaims{"iss": as.URL, "aud": q.Get("client_id"), "exp": time.Now().Add(time.Minute).Unix(),
			"code": "code-1", "state": q.Get("state")}
		if as.mutate != nil {
			as.mutate(claims, q)
		}
		response := as.key.sign(t, claims)
		if q.Get("response_mode") == "form_post.jwt" {
			fmt.Fprintf(w, `<form method="post" action="%s"><input type="hidden" name="response" value="%s"></form>`,
				html.EscapeString(cb.String()), html.EscapeString(response))
			return
		}
		cb.RawQuery = url.Values{"response": {response}}.Encode()
		http.Redirect(w, r, cb.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		as.mu.Lock()
		ok := r.PostForm.Get("code") == "code-1" && base64.RawURLEncoding.EncodeToString(sum[:]) == as.challenge
		as.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at-1", "token_type": "Bearer", "expires_in": 300})
	})
	as.Server = httptest.NewServer(mux)
	t.Cleanup(as.Close)
	return as
}

var formPostRe = regexp.MustCompile(`action="([^"]+)"><input type="hidden" name="response" value="([^"]+)"`)

// jarmBrowser plays the browser: it follows the redirect to the
// loopback, or submits a form_post page to it.
func jarmBrowser(authURL string) error {
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Get(authURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		cb, err := http.Get(resp.Header.Get("Location"))
		if err == nil {
			cb.Body.Close()
		}
		return err
	}
	page, _ := io.ReadAll(resp.Body)
	m := formPostRe.FindSubmatch(page)
	if m == nil {
		return fmt.Errorf("no form_post page: %s", page)
	}
	cb, err := http.PostForm(html.UnescapeString(string(m[1])), url.Values{"response": {html.UnescapeString(string(m[2]))}})
	if err == nil {
		cb.Body.Close()
	}
	return err
}

func jarmLogin(t *testing.T, as *jarmAS, mode string) (*ServerCredential, error) {
	t.Helper()
	return NewAuthClient(as.URL, newMockCredentialStore()).LoginWithBrowser(context.Background(), &BrowserLoginRequest{
		ClientID: jarmClientID, ResponseMode: mode, Timeout: 5 * time.Second,
		OpenBrowser: func(u string) error { go jarmBrowser(u); return nil },
	})
}

func TestLoginWithBrowser_JARMLogsIn(t *testing.T) {
	for _, mode := range []string{"jwt", "query.jwt", "form_post.jwt"} {
		t.Run(mode, func(t *testing.T) {
			cred, err := jarmLogin(t, newJARMAS(t), mode)
			require.NoError(t, err)
			assert.Equal(t, "at-1", cred.AccessToken)
		})
	}
}

// A forged, replayed or stale response never reaches the token endpoint.
func TestLoginWithBrowser_JARMRefusesBadResponses(t *testing.T) {
	for name, mutate := range map[string]func(jwt.MapClaims, url.Values){
		"wrong iss":   func(c jwt.MapClaims, _ url.Values) { c["iss"] = "https://evil.example" },
		"wrong aud":   func(c jwt.MapClaims, _ url.Values) { c["aud"] = "someone-else" },
		"expired":     func(c jwt.MapClaims, _ url.Values) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"wrong state": func(c jwt.MapClaims, _ url.Values) { c["state"] = "attacker-state" },
	} {
		t.Run(name, func(t *testing.T) {
			as := newJARMAS(t)
			as.mutate = mutate
			_, err := jarmLogin(t, as, "jwt")
			require.Error(t, err)
			if name == "wrong state" {
				assert.Contains(t, err.Error(), "state mismatch")
				return
			}
			assert.True(t, errors.Is(err, ErrUnverifiedAuthorizationResponse), "got %v", err)
		})
	}
}

// An AS that ignores response_mode=jwt and answers with a plain code would
// otherwise get an unsigned response accepted.
// See: https://openid.net/specs/oauth-v2-jarm.html#section-4.4
func TestLoginWithBrowser_JARMRefusesAPlainCode(t *testing.T) {
	as := newJARMAS(t)
	as.plain = true
	_, err := jarmLogin(t, as, "jwt")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnverifiedAuthorizationResponse), "got %v", err)
}

// An error inside a verified response is the AS's answer, so it comes
// back as a *CallbackError, like a denial in a plain response.
func TestLoginWithBrowser_JARMErrorIsACallbackError(t *testing.T) {
	as := newJARMAS(t)
	as.mutate = func(c jwt.MapClaims, _ url.Values) {
		delete(c, "code")
		c["error"], c["error_description"] = "access_denied", "user said no"
	}
	_, err := jarmLogin(t, as, "jwt")
	var cbErr *CallbackError
	require.True(t, errors.As(err, &cbErr), "got %v", err)
	assert.Equal(t, "access_denied", cbErr.Code)
	assert.Equal(t, "user said no", cbErr.Description)
	assert.False(t, errors.Is(err, ErrUnverifiedAuthorizationResponse))
}

// A fragment never reaches the loopback server, so a fragment mode fails
// before the browser opens instead of timing out.
func TestLoginWithBrowser_FragmentModesFailFast(t *testing.T) {
	for _, mode := range []string{"fragment", "fragment.jwt"} {
		opened := false
		_, err := NewAuthClient(newJARMAS(t).URL, newMockCredentialStore()).LoginWithBrowser(context.Background(), &BrowserLoginRequest{
			ClientID: jarmClientID, ResponseMode: mode, Timeout: 5 * time.Second,
			OpenBrowser: func(string) error { opened = true; return nil },
		})
		require.Error(t, err, mode)
		assert.Contains(t, err.Error(), "fragment", mode)
		assert.False(t, opened, mode)
	}
}

// JARM needs the issuer and JWKS. A login that can't find them fails
// before the browser opens.
func TestLoginWithBrowser_JARMNeedsIssuerAndJWKS(t *testing.T) {
	as := newJARMAS(t)
	opened := false
	_, err := NewAuthClient(as.URL, newMockCredentialStore(), WithASMetadata(&ASMetadata{
		AuthorizationEndpoint: as.URL + "/authorize", TokenEndpoint: as.URL + "/token",
		CodeChallengeMethodsSupported: []string{"S256"},
	})).LoginWithBrowser(context.Background(), &BrowserLoginRequest{
		ClientID: jarmClientID, ResponseMode: "jwt", Timeout: 5 * time.Second,
		OpenBrowser: func(string) error { opened = true; return nil },
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jwks_uri")
	assert.False(t, opened)
}

var _ keys.KeyLookup = staticKeys{}
