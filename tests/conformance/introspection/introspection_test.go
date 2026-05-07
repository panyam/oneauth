package introspection_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/testutil"
)

// resourceServerClient registers an HMAC-keyed client in the AS keystore
// so it can authenticate to the introspection endpoint. RFC 7662 §2.1
// requires the introspection endpoint authenticate the caller; OneAuth
// looks the credentials up in its client KeyStore.
func resourceServerClient(t *testing.T, srv *testutil.TestAuthServer) (clientID, secret string) {
	t.Helper()
	clientID = "rs-client"
	secret = "rs-secret"
	if err := srv.KeyStore.PutKey(&keys.KeyRecord{
		ClientID:  clientID,
		Key:       []byte(secret),
		Algorithm: "HS256",
	}); err != nil {
		t.Fatalf("register resource server client: %v", err)
	}
	return clientID, secret
}

func introspectURL(srv *testutil.TestAuthServer) string {
	return srv.URL() + "/oauth/introspect"
}

// postForm sends an application/x-www-form-urlencoded POST to the
// introspection endpoint. Caller controls Authorization header (or sets
// none) by passing setAuth.
func postForm(t *testing.T, endpoint string, body url.Values, setAuth func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body.Encode()))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if setAuth != nil {
		setAuth(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", endpoint, err)
	}
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var out map[string]any
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode JSON (%q): %v", string(body), err)
	}
	return out
}

// TestIntrospectClientAuth covers RFC 7662 §2.1 caller authentication.
// The introspection endpoint MUST authenticate the caller; AS metadata
// (RFC 8414 §2 token_endpoint_auth_methods_supported) declares which
// methods the AS accepts, and consumers expect any advertised method
// to work uniformly across token / introspection / revocation endpoints.
func TestIntrospectClientAuth(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)
	rsID, rsSecret := resourceServerClient(t, srv)
	token, err := srv.MintToken("user-1", []string{"read"})
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	t.Run("basic_auth_accepted", func(t *testing.T) {
		resp := postForm(t, introspectURL(srv), url.Values{"token": {token}}, func(r *http.Request) {
			r.SetBasicAuth(rsID, rsSecret)
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d, want 200", resp.StatusCode)
		}
		body := decodeJSON(t, resp)
		if active, _ := body["active"].(bool); !active {
			t.Errorf("active=%v, want true", body["active"])
		}
	})

	t.Run("post_auth_accepted", func(t *testing.T) {
		// RFC 6749 §2.3.1 client_secret_post: client_id + client_secret in
		// the form body. RFC 8414's token_endpoint_auth_methods_supported
		// advertises which methods the AS accepts; OneAuth declares
		// "client_secret_post" alongside "client_secret_basic" but the
		// introspection endpoint currently only honors basic.
		body := url.Values{
			"token":         {token},
			"client_id":     {rsID},
			"client_secret": {rsSecret},
		}
		resp := postForm(t, introspectURL(srv), body, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d, want 200 (client_secret_post should be accepted)", resp.StatusCode)
		}
		decoded := decodeJSON(t, resp)
		if active, _ := decoded["active"].(bool); !active {
			t.Errorf("active=%v, want true", decoded["active"])
		}
	})

	t.Run("missing_credentials_rejected", func(t *testing.T) {
		resp := postForm(t, introspectURL(srv), url.Values{"token": {token}}, nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status=%d, want 401", resp.StatusCode)
		}
	})

	t.Run("wrong_secret_rejected", func(t *testing.T) {
		resp := postForm(t, introspectURL(srv), url.Values{"token": {token}}, func(r *http.Request) {
			r.SetBasicAuth(rsID, "not-the-real-secret")
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status=%d, want 401", resp.StatusCode)
		}
	})
}

// TestIntrospectActiveResponse covers the response shape for valid
// tokens per RFC 7662 §2.2.
func TestIntrospectActiveResponse(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)
	rsID, rsSecret := resourceServerClient(t, srv)

	scopes := []string{"read", "write"}
	token, err := srv.MintToken("user-42", scopes)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	resp := postForm(t, introspectURL(srv), url.Values{"token": {token}}, func(r *http.Request) {
		r.SetBasicAuth(rsID, rsSecret)
	})
	body := decodeJSON(t, resp)

	t.Run("active_true", func(t *testing.T) {
		if active, _ := body["active"].(bool); !active {
			t.Errorf("active=%v, want true", body["active"])
		}
	})

	t.Run("sub_present", func(t *testing.T) {
		if sub, _ := body["sub"].(string); sub != "user-42" {
			t.Errorf("sub=%q, want %q", body["sub"], "user-42")
		}
	})

	t.Run("scope_is_space_separated_string", func(t *testing.T) {
		// RFC 7662 §2.2: "scope" OPTIONAL. A JSON string containing a
		// space-separated list of scopes associated with this token.
		raw, ok := body["scope"]
		if !ok {
			t.Fatalf("scope missing from active response")
		}
		s, ok := raw.(string)
		if !ok {
			t.Fatalf("scope=%v (%T), want string", raw, raw)
		}
		got := strings.Fields(s)
		want := scopes
		if len(got) != len(want) {
			t.Fatalf("scope=%q, want fields %v", s, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("scope[%d]=%q, want %q", i, got[i], want[i])
			}
		}
	})
}

// TestIntrospectInactiveResponse covers RFC 7662 §2.2 inactive response.
// "If the introspection call is properly authorized but the token is not
// active, ... the authorization server MUST return an introspection
// response with the 'active' field set to 'false'." Other members
// describe the active token; they have no meaning when the token is
// inactive and SHOULD NOT be present.
func TestIntrospectInactiveResponse(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)
	rsID, rsSecret := resourceServerClient(t, srv)

	cases := map[string]string{
		"active_false_for_invalid_token": "not-a-real-token",
		"active_false_for_expired_token": mintExpired(t, srv),
	}

	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			resp := postForm(t, introspectURL(srv), url.Values{"token": {tok}}, func(r *http.Request) {
				r.SetBasicAuth(rsID, rsSecret)
			})
			body := decodeJSON(t, resp)
			active, ok := body["active"].(bool)
			if !ok {
				t.Fatalf("active missing or wrong type: %v", body["active"])
			}
			if active {
				t.Errorf("active=true, want false")
			}
		})
	}

	t.Run("inactive_response_minimal", func(t *testing.T) {
		// Defense in depth: an inactive response that includes sub/scope/exp
		// would let an attacker confirm whether a guessed token ever existed.
		// Keep the response to exactly one key.
		resp := postForm(t, introspectURL(srv), url.Values{"token": {"definitely-not-a-token"}}, func(r *http.Request) {
			r.SetBasicAuth(rsID, rsSecret)
		})
		body := decodeJSON(t, resp)
		for k := range body {
			if k != "active" {
				t.Errorf("inactive response leaks field %q (value=%v)", k, body[k])
			}
		}
	})
}

func mintExpired(t *testing.T, srv *testutil.TestAuthServer) string {
	t.Helper()
	tok, err := srv.MintTokenWithClaims(jwt.MapClaims{
		"sub": "user-1",
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("mint expired token: %v", err)
	}
	return tok
}

// TestIntrospectHeaders covers RFC 7662 §4 caching/transport requirements.
func TestIntrospectHeaders(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)
	rsID, rsSecret := resourceServerClient(t, srv)
	token, _ := srv.MintToken("user-1", nil)

	resp := postForm(t, introspectURL(srv), url.Values{"token": {token}}, func(r *http.Request) {
		r.SetBasicAuth(rsID, rsSecret)
	})
	defer resp.Body.Close()

	t.Run("cache_control_no_store", func(t *testing.T) {
		// RFC 7662 §4: introspection responses contain authorization data
		// and MUST NOT be cached by intermediaries.
		cc := resp.Header.Get("Cache-Control")
		if !strings.Contains(cc, "no-store") {
			t.Errorf("Cache-Control=%q, want contains no-store", cc)
		}
	})

	t.Run("content_type_json", func(t *testing.T) {
		ct := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type=%q, want application/json", ct)
		}
	})
}

// TestIntrospectMethod — RFC 7662 §2.1: "The introspection endpoint MUST
// be served over HTTPS, and MUST be a POST request."
func TestIntrospectMethod(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)

	t.Run("get_rejected", func(t *testing.T) {
		resp, err := http.Get(introspectURL(srv))
		if err != nil {
			t.Fatalf("GET introspect: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("GET returned 200, want 4xx/405")
		}
	})
}

// TestIntrospectTokenTypeHint covers RFC 7662 §2.1 token_type_hint.
// "OPTIONAL. A hint about the type of the token submitted ... [the
// server] MAY use it to optimize the token lookup. If the server is
// unable to locate the token using the given hint, it MUST extend its
// search ... server SHOULD NOT reject the request."
func TestIntrospectTokenTypeHint(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)
	rsID, rsSecret := resourceServerClient(t, srv)
	token, _ := srv.MintToken("user-1", nil)

	cases := []string{"access_token", "refresh_token", "totally_unknown_hint"}
	for _, hint := range cases {
		t.Run("accepts_"+hint, func(t *testing.T) {
			body := url.Values{"token": {token}, "token_type_hint": {hint}}
			resp := postForm(t, introspectURL(srv), body, func(r *http.Request) {
				r.SetBasicAuth(rsID, rsSecret)
			})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("hint=%s status=%d, want 200 (server SHOULD NOT reject unknown hints)", hint, resp.StatusCode)
			}
			decoded := decodeJSON(t, resp)
			// access_token hint with a real access token → active.
			// refresh_token / unknown hints with an access token: server may
			// fall back to access_token lookup and still find it. Either way,
			// the request must not be rejected.
			if _, ok := decoded["active"]; !ok {
				t.Errorf("response missing active field: %v", decoded)
			}
		})
	}
}

// TestIntrospectRARecho covers RFC 9396 §11 — when an introspected token
// carries authorization_details (RAR), the active introspection response
// echoes them so resource servers can enforce fine-grained authorization
// without parsing the JWT themselves.
func TestIntrospectRARecho(t *testing.T) {
	srv := testutil.NewTestAuthServer(t)
	rsID, rsSecret := resourceServerClient(t, srv)

	rar := []map[string]any{
		{
			"type":      "payment_initiation",
			"actions":   []string{"initiate"},
			"locations": []string{"https://example.com/payments"},
		},
	}
	token, err := srv.MintTokenWithClaims(jwt.MapClaims{
		"sub":                   "user-1",
		"authorization_details": rar,
	})
	if err != nil {
		t.Fatalf("mint RAR token: %v", err)
	}

	resp := postForm(t, introspectURL(srv), url.Values{"token": {token}}, func(r *http.Request) {
		r.SetBasicAuth(rsID, rsSecret)
	})
	body := decodeJSON(t, resp)

	t.Run("authorization_details_echoed", func(t *testing.T) {
		raw, ok := body["authorization_details"]
		if !ok {
			t.Fatalf("authorization_details missing from active response")
		}
		// JSON round-trip turns the slice of maps into []any of map[string]any.
		arr, ok := raw.([]any)
		if !ok || len(arr) != 1 {
			t.Fatalf("authorization_details=%v, want array of 1", raw)
		}
		entry, ok := arr[0].(map[string]any)
		if !ok {
			t.Fatalf("authorization_details[0]=%v (%T), want object", arr[0], arr[0])
		}
		if entry["type"] != "payment_initiation" {
			t.Errorf("authorization_details[0].type=%v, want payment_initiation", entry["type"])
		}
	})
}
