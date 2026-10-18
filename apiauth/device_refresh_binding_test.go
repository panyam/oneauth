package apiauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The device grant binds a refresh token to the proof key only for a public
// client; a confidential client's is constrained by its authentication.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-5
func TestDeviceGrant_RefreshBindingFollowsClientType(t *testing.T) {
	cnf := &core.Confirmation{JKT: "device-proof-jkt"}
	for _, tc := range []struct {
		name     string
		setup    func(*testing.T) (*apiAuthFixture, core.DeviceAuthorizationStore)
		clientID string
		secret   string
		wantJKT  string
	}{
		{"confidential client gets an unbound refresh token", setupConfidentialDevice, "client-conf", "conf-secret", ""},
		{"public client gets a bound refresh token", setupDevice, "client-1", "", cnf.JKT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth, store := tc.setup(t)
			devHandler := &apiauth.DeviceAuthorizationHandler{Store: store, VerificationURI: "https://auth.example/device"}
			deviceCode, userCode := runDeviceAuthorize(t, devHandler, tc.clientID)
			require.NoError(t, auth.ApproveDeviceAuthorization(httptest.NewRequest(http.MethodPost, "/", nil), userCode, "alice", nil))
			_, _ = store.UpdatePollingState(context.Background(), &core.UpdatePollingStateRequest{
				DeviceCode: deviceCode,
				PolledAt:   time.Now().Add(-time.Hour),
			})

			resp, err := auth.OneAuth.DeviceCodeGranter.DeviceCodeGrant(context.Background(), &apiauth.DeviceCodeGrantRequest{
				DeviceCode:   deviceCode,
				ClientID:     tc.clientID,
				ClientSecret: tc.secret,
				Confirmation: cnf,
			})
			require.NoError(t, err)
			require.NotEmpty(t, resp.Tokens.RefreshToken)

			stored, err := auth.OneAuth.RefreshStore.GetRefreshToken(context.Background(), &core.GetRefreshTokenRequest{Token: resp.Tokens.RefreshToken})
			require.NoError(t, err)
			if tc.wantJKT == "" {
				assert.True(t, stored.Token.Confirmation.IsEmpty(), "a confidential client's refresh token must not be key-bound")
				return
			}
			require.NotNil(t, stored.Token.Confirmation)
			assert.Equal(t, tc.wantJKT, stored.Token.Confirmation.JKT)
		})
	}
}
