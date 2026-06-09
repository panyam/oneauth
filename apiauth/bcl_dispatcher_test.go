package apiauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/core"
)

// See: https://openid.net/specs/openid-connect-backchannel-1_0.html

// fakeRefreshStore is a minimal RefreshTokenStore — only the methods the BCL
// dispatcher actually calls (GetSubjectTokens) are non-trivial; the rest exist
// to satisfy the interface.
type fakeRefreshStore struct {
	bySubject map[string][]*core.RefreshToken
	byToken   map[string]*core.RefreshToken
}

func newFakeRefreshStore() *fakeRefreshStore {
	return &fakeRefreshStore{
		bySubject: map[string][]*core.RefreshToken{},
		byToken:   map[string]*core.RefreshToken{},
	}
}

func (s *fakeRefreshStore) add(t *core.RefreshToken) {
	s.bySubject[t.Subject] = append(s.bySubject[t.Subject], t)
	if t.Token != "" {
		s.byToken[t.Token] = t
	}
}

func (s *fakeRefreshStore) GetSubjectTokens(_ context.Context, req *core.GetSubjectTokensRequest) (*core.GetSubjectTokensResponse, error) {
	return &core.GetSubjectTokensResponse{Tokens: s.bySubject[req.Subject]}, nil
}

func (s *fakeRefreshStore) CreateRefreshToken(_ context.Context, _ *core.CreateRefreshTokenRequest) (*core.CreateRefreshTokenResponse, error) {
	return nil, nil
}
func (s *fakeRefreshStore) GetRefreshToken(_ context.Context, req *core.GetRefreshTokenRequest) (*core.GetRefreshTokenResponse, error) {
	if t, ok := s.byToken[req.Token]; ok {
		return &core.GetRefreshTokenResponse{Token: t}, nil
	}
	return nil, core.ErrTokenNotFound
}
func (s *fakeRefreshStore) RotateRefreshToken(_ context.Context, _ *core.RotateRefreshTokenRequest) (*core.RotateRefreshTokenResponse, error) {
	return nil, nil
}
func (s *fakeRefreshStore) RevokeRefreshToken(_ context.Context, _ *core.RevokeRefreshTokenRequest) (*core.RevokeRefreshTokenResponse, error) {
	return &core.RevokeRefreshTokenResponse{}, nil
}
func (s *fakeRefreshStore) RevokeSubjectTokens(_ context.Context, _ *core.RevokeSubjectTokensRequest) (*core.RevokeSubjectTokensResponse, error) {
	return &core.RevokeSubjectTokensResponse{}, nil
}
func (s *fakeRefreshStore) RevokeTokenFamily(_ context.Context, _ *core.RevokeTokenFamilyRequest) (*core.RevokeTokenFamilyResponse, error) {
	return &core.RevokeTokenFamilyResponse{}, nil
}
func (s *fakeRefreshStore) CleanupExpiredTokens(_ context.Context, _ *core.CleanupExpiredTokensRequest) (*core.CleanupExpiredTokensResponse, error) {
	return &core.CleanupExpiredTokensResponse{}, nil
}

// stubAppLookup is a minimal AppRegistrationLookup so the dispatcher tests
// don't have to bring up the admin package.
type stubAppLookup struct {
	apps map[string]*core.AppRegistration
}

func (s *stubAppLookup) GetAppRegistration(_ context.Context, clientID string) (*core.AppRegistration, bool) {
	reg, ok := s.apps[clientID]
	if !ok {
		return nil, false
	}
	clone := *reg
	return &clone, true
}

// captureReceiver records every POST as (form values, status) so tests can
// verify the wire format independently.
type captureReceiver struct {
	mu     sync.Mutex
	hits   int32
	form   []string
	status int // status to return (0 → 200)
}

func (r *captureReceiver) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&r.hits, 1)
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.form = append(r.form, string(b))
		r.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		if r.status != 0 {
			w.WriteHeader(r.status)
		}
	}
}

func (r *captureReceiver) hitCount() int32 { return atomic.LoadInt32(&r.hits) }

func newDispatcherFixture(t *testing.T, apps map[string]*core.AppRegistration, refresh core.RefreshTokenStore) *BCLDispatcher {
	t.Helper()
	// httptest.NewServer binds to 127.0.0.1; the dial-time SSRF guard
	// rejects loopback by default. Tests opt in.
	return &BCLDispatcher{
		Issuer:            newTestLogoutIssuer(t),
		Apps:              &stubAppLookup{apps: apps},
		RefreshStore:      refresh,
		SyncForTest:       true,
		AllowPrivateHosts: true,
	}
}

func TestBCLDispatcher_PostsOnlyToClientsWithBCLURI(t *testing.T) {
	rxA := &captureReceiver{}
	srvA := httptest.NewServer(rxA.handler())
	defer srvA.Close()
	rxB := &captureReceiver{}
	srvB := httptest.NewServer(rxB.handler())
	defer srvB.Close()

	apps := map[string]*core.AppRegistration{
		"client-a": {ClientID: "client-a", BackchannelLogoutURI: srvA.URL},
		"client-b": {ClientID: "client-b", BackchannelLogoutURI: srvB.URL},
		"client-c": {ClientID: "client-c"}, // no BCL URI — must not be hit
	}

	store := newFakeRefreshStore()
	store.add(&core.RefreshToken{Token: "t1", Subject: "alice", ClientID: "client-a", Family: "fam-1"})
	store.add(&core.RefreshToken{Token: "t2", Subject: "alice", ClientID: "client-b", Family: "fam-2"})
	store.add(&core.RefreshToken{Token: "t3", Subject: "alice", ClientID: "client-c", Family: "fam-3"})

	d := newDispatcherFixture(t, apps, store)
	_, err := d.Dispatch(context.Background(), &DispatchRequest{Subject: "alice"})
	require.NoError(t, err)

	assert.Equal(t, int32(1), rxA.hitCount(), "client-a registered BCL URI must receive POST")
	assert.Equal(t, int32(1), rxB.hitCount(), "client-b registered BCL URI must receive POST")
}

func TestBCLDispatcher_PostBodyAndClaims(t *testing.T) {
	rx := &captureReceiver{}
	srv := httptest.NewServer(rx.handler())
	defer srv.Close()

	apps := map[string]*core.AppRegistration{
		"client-a": {ClientID: "client-a", BackchannelLogoutURI: srv.URL},
	}
	d := newDispatcherFixture(t, apps, nil)

	_, err := d.Dispatch(context.Background(), &DispatchRequest{
		Subject:   "alice",
		SID:       "fam-1",
		ClientIDs: []string{"client-a"},
	})
	require.NoError(t, err)
	require.Equal(t, int32(1), rx.hitCount())

	rx.mu.Lock()
	defer rx.mu.Unlock()
	require.Len(t, rx.form, 1)
	body := rx.form[0]
	require.True(t, len(body) > len("logout_token="))
	const prefix = "logout_token="
	require.Equal(t, prefix, body[:len(prefix)])
	encoded := body[len(prefix):]

	parsed, err := jwt.Parse(encoded, func(tok *jwt.Token) (any, error) {
		return []byte(testBCLSecret), nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "client-a", claims["aud"])
	assert.Equal(t, "alice", claims["sub"])
	assert.Equal(t, "fam-1", claims["sid"])
}

func TestBCLDispatcher_SessionRequired_SkipsWithoutSID(t *testing.T) {
	rx := &captureReceiver{}
	srv := httptest.NewServer(rx.handler())
	defer srv.Close()

	apps := map[string]*core.AppRegistration{
		"client-a": {
			ClientID:                         "client-a",
			BackchannelLogoutURI:             srv.URL,
			BackchannelLogoutSessionRequired: true,
		},
	}
	d := newDispatcherFixture(t, apps, nil)
	_, err := d.Dispatch(context.Background(), &DispatchRequest{
		Subject:   "alice",
		ClientIDs: []string{"client-a"},
		// SID intentionally empty.
	})
	require.NoError(t, err)
	assert.Equal(t, int32(0), rx.hitCount(), "session_required must skip when sid is absent")
}

func TestBCLDispatcher_ReceiverNon2xx_NoCrash(t *testing.T) {
	rx := &captureReceiver{status: http.StatusInternalServerError}
	srv := httptest.NewServer(rx.handler())
	defer srv.Close()

	apps := map[string]*core.AppRegistration{
		"client-a": {ClientID: "client-a", BackchannelLogoutURI: srv.URL},
	}
	d := newDispatcherFixture(t, apps, nil)
	_, err := d.Dispatch(context.Background(), &DispatchRequest{
		Subject:   "alice",
		ClientIDs: []string{"client-a"},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(1), rx.hitCount())
}

func TestBCLDispatcher_NoClients_NoOp(t *testing.T) {
	apps := map[string]*core.AppRegistration{}
	d := newDispatcherFixture(t, apps, newFakeRefreshStore())
	_, err := d.Dispatch(context.Background(), &DispatchRequest{Subject: "nobody"})
	require.NoError(t, err)
}

func TestBCLDispatcher_RejectsLoopbackByDefault(t *testing.T) {
	// Receiver bound to 127.0.0.1; dispatcher without AllowPrivateHosts must
	// refuse to dial it. SSRF guard.
	rx := &captureReceiver{}
	srv := httptest.NewServer(rx.handler())
	defer srv.Close()

	apps := map[string]*core.AppRegistration{
		"client-a": {ClientID: "client-a", BackchannelLogoutURI: srv.URL},
	}
	d := &BCLDispatcher{
		Issuer:      newTestLogoutIssuer(t),
		Apps:        &stubAppLookup{apps: apps},
		SyncForTest: true,
		// AllowPrivateHosts intentionally false.
	}
	_, err := d.Dispatch(context.Background(), &DispatchRequest{
		Subject:   "alice",
		ClientIDs: []string{"client-a"},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(0), rx.hitCount(), "dial-time guard must block loopback when AllowPrivateHosts is false")
}

func TestBCLDispatcher_DoesNotFollowRedirects(t *testing.T) {
	// A 3xx response from the registered receiver must NOT be followed —
	// that would re-open the SSRF surface by letting the receiver bounce
	// the AS at an arbitrary URL.
	var redirectTargetHit int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&redirectTargetHit, 1)
	}))
	defer target.Close()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer primary.Close()

	apps := map[string]*core.AppRegistration{
		"client-a": {ClientID: "client-a", BackchannelLogoutURI: primary.URL},
	}
	d := newDispatcherFixture(t, apps, nil)
	_, err := d.Dispatch(context.Background(), &DispatchRequest{
		Subject:   "alice",
		ClientIDs: []string{"client-a"},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(0), atomic.LoadInt32(&redirectTargetHit), "dispatcher must not follow 3xx to a redirect target")
}

func TestBCLDispatcher_Async_WaitDrainsInFlight(t *testing.T) {
	rx := &captureReceiver{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		rx.handler()(w, r)
	}))
	defer srv.Close()

	apps := map[string]*core.AppRegistration{
		"client-a": {ClientID: "client-a", BackchannelLogoutURI: srv.URL},
	}
	d := &BCLDispatcher{
		Issuer:            newTestLogoutIssuer(t),
		Apps:              &stubAppLookup{apps: apps},
		SyncForTest:       false,
		AllowPrivateHosts: true,
	}
	_, err := d.Dispatch(context.Background(), &DispatchRequest{
		Subject:   "alice",
		ClientIDs: []string{"client-a"},
	})
	require.NoError(t, err)
	d.Wait()
	assert.Equal(t, int32(1), rx.hitCount())
}
