package client

// Automatic refresh presents the client the credential was issued to. The
// AS redeems a refresh token only for that client, so sending a fixed
// client_id breaks refresh for every token not issued to it.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-6

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAutoRefresh_PresentsTheIssuedClient(t *testing.T) {
	for name, tc := range map[string]struct{ stored, want string }{
		"credential records its client": {stored: "my-app", want: "my-app"},
		"older credential without one":  {stored: "", want: "cli"},
	} {
		t.Run(name, func(t *testing.T) {
			var sent string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req OAuth2TokenRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				sent = req.ClientID
				_ = json.NewEncoder(w).Encode(OAuth2TokenResponse{
					AccessToken: "new-access", RefreshToken: "new-refresh", TokenType: "Bearer", ExpiresIn: 3600,
				})
			}))
			defer server.Close()

			store := newMockCredentialStore()
			store.creds[server.URL] = &ServerCredential{
				AccessToken: "old-access", RefreshToken: "old-refresh", ClientID: tc.stored,
				ExpiresAt: time.Now().Add(time.Minute),
			}

			token, err := NewAuthClient(server.URL, store).GetToken()
			require.NoError(t, err)
			assert.Equal(t, "new-access", token)
			assert.Equal(t, tc.want, sent)
			assert.Equal(t, tc.want, store.creds[server.URL].ClientID, "the refreshed credential keeps its client")
		})
	}
}
