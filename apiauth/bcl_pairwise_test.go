package apiauth

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A logout token names the user by the sub that client knows: pairwise
// for a pairwise client (OIDC Back-Channel Logout §2.4, OIDC Core §8.1).
// When the mapping fails the client gets no logout token, rather than one
// carrying the user's own ID.
//
// See: https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
// See: https://github.com/panyam/oneauth/issues/507
func TestBCLDispatcher_LogoutTokenUsesTheClientsSubject(t *testing.T) {
	rx := &captureReceiver{}
	srv := httptest.NewServer(rx.handler())
	defer srv.Close()
	d := newDispatcherFixture(t, map[string]*core.AppRegistration{
		"pairwise-client": {ClientID: "pairwise-client", BackchannelLogoutURI: srv.URL},
		"broken-client":   {ClientID: "broken-client", BackchannelLogoutURI: srv.URL},
	}, nil)
	d.SubjectForClient = func(_ context.Context, clientID, subject string) (string, error) {
		if clientID == "broken-client" {
			return "", errors.New("no salt")
		}
		return "pw-" + subject, nil
	}
	_, err := d.Dispatch(context.Background(), &DispatchRequest{Subject: "alice", SID: "sid-1", ClientIDs: []string{"pairwise-client", "broken-client"}})
	require.NoError(t, err)

	require.Equal(t, int32(1), rx.hitCount(), "the client whose sub can't be mapped gets nothing")
	rx.mu.Lock()
	defer rx.mu.Unlock()
	form, err := url.ParseQuery(rx.form[0])
	require.NoError(t, err)
	parsed, err := jwt.Parse(form.Get("logout_token"), func(*jwt.Token) (any, error) { return []byte(testBCLSecret), nil })
	require.NoError(t, err)
	assert.Equal(t, "pw-alice", parsed.Claims.(jwt.MapClaims)["sub"])
}
