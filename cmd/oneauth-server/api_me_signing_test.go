package main

// The server's own /api/* routes accept the access tokens its token
// endpoint issues, whatever jwt.signing_alg says. Before issue 438 the
// middleware knew only the HS256 secret, so with RS256 or ES256 signing
// every call answered 401 "unexpected signing method".
//
// See: https://www.rfc-editor.org/rfc/rfc9068#section-4
// See: https://github.com/panyam/oneauth/issues/438

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIMe_AcceptsTheServersOwnTokens(t *testing.T) {
	for name, jwtExtra := range map[string]string{
		"HS256": "",
		"RS256": "  signing_alg: RS256\n  ephemeral_signing_key: true",
	} {
		t.Run(name, func(t *testing.T) {
			f := newLoginFixtureWith(t, jwtExtra)
			resp, err := f.http.PostForm(f.url+"/api/token", url.Values{
				"grant_type": {"password"}, "username": {loginTestEmail}, "password": {loginTestPassword},
			})
			require.NoError(t, err)
			var tok struct {
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
			resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			req, _ := http.NewRequest(http.MethodGet, f.url+"/api/me", nil)
			req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
			resp, err = f.http.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			var me map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&me)
			require.Equal(t, http.StatusOK, resp.StatusCode, "/api/me: %v", me)
			assert.NotEmpty(t, me["user_id"])
		})
	}
}
