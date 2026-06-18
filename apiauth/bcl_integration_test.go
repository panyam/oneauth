package apiauth

// Integration coverage for OIDC Back-Channel Logout 1.0 push: the
// /api/logout-all handler must fire OnSubjectRevoked, and the BCL dispatcher
// wired into that hook must POST a valid logout_token to every registered
// receiver. This sits between the unit tests (logout_token / dispatcher in
// isolation) and the cross-package e2e in tests/e2e — it exercises the real
// HandleLogoutAll path without spinning up a full AS.
//
// See: https://openid.net/specs/openid-connect-backchannel-1_0.html
// See: https://github.com/panyam/oneauth/issues/261

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/core"
)

func TestBCL_HandleLogoutAll_FiresDispatchesToRegisteredReceivers(t *testing.T) {
	// Two RS-side receivers — one per client. Both should be POSTed by the
	// time HandleLogoutAll returns (SyncForTest=true).
	var rxAHits, rxBHits int32
	var rxABody, rxBBody string
	rxA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rxABody = string(b)
		atomic.AddInt32(&rxAHits, 1)
	}))
	defer rxA.Close()
	rxB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rxBBody = string(b)
		atomic.AddInt32(&rxBHits, 1)
	}))
	defer rxB.Close()

	// Two registered clients with BCL URIs + one with none.
	apps := map[string]*core.AppRegistration{
		"client-a":  {ClientID: "client-a", BackchannelLogoutURI: rxA.URL},
		"client-b":  {ClientID: "client-b", BackchannelLogoutURI: rxB.URL},
		"client-no": {ClientID: "client-no"},
	}

	// Refresh store: alice has active grants on all three clients.
	store := newFakeRefreshStore()
	store.add(&core.RefreshToken{Token: "t1", Subject: "alice", ClientID: "client-a", Family: "fam-1"})
	store.add(&core.RefreshToken{Token: "t2", Subject: "alice", ClientID: "client-b", Family: "fam-2"})
	store.add(&core.RefreshToken{Token: "t3", Subject: "alice", ClientID: "client-no", Family: "fam-3"})

	dispatcher := &BCLDispatcher{
		Issuer:            newTestLogoutIssuer(t),
		Apps:              &stubAppLookup{apps: apps},
		RefreshStore:      store,
		SyncForTest:       true,
		AllowPrivateHosts: true, // httptest binds to 127.0.0.1
	}

	sessions := NewSessionsHandler(store, TokenHooks{
		OnSubjectRevoked: func(subject, sid string, clientIDs []string) {
			dispatcher.Dispatch(context.Background(), &DispatchRequest{
				Subject:   subject,
				SID:       sid,
				ClientIDs: clientIDs,
			})
		},
	})

	// Build an authenticated request — HandleLogoutAll reads the subject
	// from context, mirroring middleware that authenticates and stamps the
	// user ID before dispatch.
	req := httptest.NewRequest(http.MethodPost, "/api/logout-all", nil)
	ctx := core.SetSubjectInContext(req.Context(), "alice")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	sessions.HandleLogoutAll(rr, req)
	require.Equal(t, http.StatusNoContent, rr.Code, rr.Body.String())

	// Both RSes with a BCL URI must have received exactly one POST.
	require.Equal(t, int32(1), atomic.LoadInt32(&rxAHits))
	require.Equal(t, int32(1), atomic.LoadInt32(&rxBHits))

	// Body shape: application/x-www-form-urlencoded with logout_token=<jwt>.
	for _, body := range []string{rxABody, rxBBody} {
		require.True(t, len(body) > len("logout_token="), body)
		token := body[len("logout_token="):]
		parsed, err := jwt.Parse(token, func(tok *jwt.Token) (any, error) {
			return []byte(testBCLSecret), nil
		})
		require.NoError(t, err)
		require.True(t, parsed.Valid)
		claims := parsed.Claims.(jwt.MapClaims)
		assert.Equal(t, "alice", claims["sub"])
		_, hasEvents := claims["events"]
		assert.True(t, hasEvents)
	}
}

func TestBCL_HandleLogout_FiresOnTokenRevokedWithCapturedSubject(t *testing.T) {
	store := newFakeRefreshStore()
	store.add(&core.RefreshToken{
		Token:    "rt-1",
		Subject:  "alice",
		ClientID: "client-a",
		Family:   "fam-1",
	})

	var sub, sid, cid string
	sessions := NewSessionsHandler(store, TokenHooks{
		OnTokenRevoked: func(s, ssid, c string) {
			sub, sid, cid = s, ssid, c
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/logout", strings.NewReader(`{"refresh_token":"rt-1"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	sessions.HandleLogout(rr, req)
	require.Equal(t, http.StatusNoContent, rr.Code, rr.Body.String())

	// Wait briefly for the hook to fire (it's synchronous, but the io path
	// gives the linter no reason to wait).
	deadline := time.Now().Add(time.Second)
	for sub == "" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	assert.Equal(t, "alice", sub)
	assert.Equal(t, "fam-1", sid)
	assert.Equal(t, "client-a", cid)
}
