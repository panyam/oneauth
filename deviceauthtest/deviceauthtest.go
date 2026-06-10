// Package deviceauthtest provides a shared contract test suite for all
// core.DeviceAuthorizationStore implementations (RFC 8628). Each backend
// — in-memory, fs, gorm, gae — exercises the same ~10 behavioral scenarios
// by handing this package a Factory closure and calling RunAll. Mirrors
// the existing appstoretest / keystoretest precedent.
//
// Why a shared suite: the per-backend test files had started to drift in
// small ways (wording on error messages, scope-override coverage,
// LastPolledAt persistence). Pulling the scenarios into one place enforces
// the contract uniformly and makes adding a fifth backend a one-line
// RunAll invocation.
package deviceauthtest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Backend is the per-test fixture handed to every scenario. Store is the
// initial handle the test exercises; Reopen returns a fresh handle bound
// to the same backing storage so the RestartPersists scenario can
// simulate a process restart.
//
// For persistent backends (fs / gorm / gae) Reopen constructs a new
// store rooted at the same dir / DB connection / namespace. For the
// in-memory backend Reopen returns the same instance — there is no
// underlying storage to reconnect to and the property the scenario
// pins ("data survives a fresh handle") is trivially true.
type Backend struct {
	Store  core.DeviceAuthorizationStore
	Reopen func() core.DeviceAuthorizationStore
}

// Factory creates a Backend per scenario. Persistent backends MUST close
// over per-test state (a tempdir from t.TempDir(), a *gorm.DB, a
// datastore namespace) so Store and Reopen both resolve to the same
// underlying storage within one scenario.
type Factory func(t *testing.T) Backend

// RunAll runs the complete DeviceAuthorizationStore contract suite against
// the provided factory. Each scenario gets a fresh Backend via factory(t)
// so state cannot leak between cases.
func RunAll(t *testing.T, factory Factory) {
	t.Run("CreateAndGet", func(t *testing.T) { TestCreateAndGet(t, factory) })
	t.Run("NotFound", func(t *testing.T) { TestNotFound(t, factory) })
	t.Run("Collision", func(t *testing.T) { TestCollision(t, factory) })
	t.Run("ApproveBindsSubjectAndOverridesScopes", func(t *testing.T) { TestApproveBindsSubjectAndOverridesScopes(t, factory) })
	t.Run("ApproveTwice_Rejects", func(t *testing.T) { TestApproveTwiceRejects(t, factory) })
	t.Run("DenyTransitions", func(t *testing.T) { TestDenyTransitions(t, factory) })
	t.Run("UpdatePollingBumpsInterval", func(t *testing.T) { TestUpdatePollingBumpsInterval(t, factory) })
	t.Run("DeleteRemovesUserCodeIndex", func(t *testing.T) { TestDeleteRemovesUserCodeIndex(t, factory) })
	t.Run("CleanupExpired", func(t *testing.T) { TestCleanupExpired(t, factory) })
	t.Run("RestartPersists", func(t *testing.T) { TestRestartPersists(t, factory) })
}

// newAuth returns the canonical sample DeviceAuthorization used across
// scenarios. The user_code "WDJB-MJHT" exercises the case- and
// dash-insensitive lookup contract enforced via core.UpperUserCode.
func newAuth() *core.DeviceAuthorization {
	return &core.DeviceAuthorization{
		DeviceCode:      "dc-abc",
		UserCode:        "WDJB-MJHT",
		ClientID:        "client-x",
		Scopes:          []string{"read"},
		Status:          core.DeviceAuthorizationStatusPending,
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(5 * time.Minute),
		IntervalSeconds: 5,
	}
}

func createDeviceAuth(t *testing.T, s core.DeviceAuthorizationStore, a *core.DeviceAuthorization) {
	t.Helper()
	_, err := s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: a})
	require.NoError(t, err)
}

// TestCreateAndGet pins the happy-path round-trip via both lookup keys
// and verifies user_code lookup is case- and dash-insensitive.
func TestCreateAndGet(t *testing.T, factory Factory) {
	s := factory(t).Store
	createDeviceAuth(t, s, newAuth())

	g, err := s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	require.NoError(t, err)
	assert.Equal(t, "dc-abc", g.Authorization.DeviceCode)
	assert.Equal(t, "client-x", g.Authorization.ClientID)
	assert.Equal(t, []string{"read"}, g.Authorization.Scopes, "Scopes slice MUST round-trip through the backend's serialization")

	u, err := s.GetByUserCode(context.Background(), &core.GetByUserCodeRequest{UserCode: "wdjbmjht"})
	require.NoError(t, err, "user_code lookup MUST be case- and dash-insensitive")
	assert.Equal(t, "dc-abc", u.Authorization.DeviceCode)
}

// TestNotFound pins that both lookup keys return ErrDeviceAuthorizationNotFound
// (not a generic error) when the record does not exist.
func TestNotFound(t *testing.T, factory Factory) {
	s := factory(t).Store
	_, err := s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "missing"})
	require.True(t, errors.Is(err, core.ErrDeviceAuthorizationNotFound))
	_, err = s.GetByUserCode(context.Background(), &core.GetByUserCodeRequest{UserCode: "ABCD-EFGH"})
	require.True(t, errors.Is(err, core.ErrDeviceAuthorizationNotFound))
}

// TestCollision pins that re-creating a device_code is rejected. The
// device_code is the AS-issued unique handle the client polls on; a
// silently-overwritten record would let a second client hijack the
// first's pending authorization.
func TestCollision(t *testing.T, factory Factory) {
	s := factory(t).Store
	createDeviceAuth(t, s, newAuth())
	_, err := s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newAuth()})
	require.Error(t, err, "device_code + user_code collision MUST be rejected")
}

// TestApproveBindsSubjectAndOverridesScopes pins the contract that the
// approving user's GrantedScopes REPLACE the originally-requested scopes
// (down-scope at consent, RFC 8628 §3.3-adjacent behavior matching the
// authorization-code grant's scope semantics).
func TestApproveBindsSubjectAndOverridesScopes(t *testing.T, factory Factory) {
	s := factory(t).Store
	createDeviceAuth(t, s, newAuth())

	_, err := s.ApproveDeviceAuthorization(context.Background(), &core.ApproveDeviceAuthorizationRequest{
		UserCode:        "WDJBMJHT",
		ApprovedSubject: "alice",
		GrantedScopes:   []string{"read", "write"},
	})
	require.NoError(t, err)

	g, _ := s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	assert.Equal(t, core.DeviceAuthorizationStatusApproved, g.Authorization.Status)
	assert.Equal(t, "alice", g.Authorization.ApprovedSubject)
	assert.Equal(t, []string{"read", "write"}, g.Authorization.Scopes)
}

// TestApproveTwiceRejects pins that a second approval looks like
// not-found, not a noisy state-transition error — once the record is
// approved the user_code is functionally consumed and any further
// lookup-by-user_code MUST be indistinguishable from "no such code,"
// otherwise the verification UI leaks pending-state information.
func TestApproveTwiceRejects(t *testing.T, factory Factory) {
	s := factory(t).Store
	createDeviceAuth(t, s, newAuth())

	_, err := s.ApproveDeviceAuthorization(context.Background(), &core.ApproveDeviceAuthorizationRequest{
		UserCode: "WDJB-MJHT", ApprovedSubject: "alice",
	})
	require.NoError(t, err)
	_, err = s.ApproveDeviceAuthorization(context.Background(), &core.ApproveDeviceAuthorizationRequest{
		UserCode: "WDJB-MJHT", ApprovedSubject: "alice",
	})
	require.True(t, errors.Is(err, core.ErrDeviceAuthorizationNotFound),
		"second approval of an already-approved record MUST look like not-found")
}

// TestDenyTransitions pins that Deny moves the record into the Denied
// terminal state; the subsequent poll at /api/token will then map this
// to RFC 8628 §3.5 access_denied.
func TestDenyTransitions(t *testing.T, factory Factory) {
	s := factory(t).Store
	createDeviceAuth(t, s, newAuth())

	_, err := s.DenyDeviceAuthorization(context.Background(), &core.DenyDeviceAuthorizationRequest{UserCode: "WDJB-MJHT"})
	require.NoError(t, err)
	g, _ := s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	assert.Equal(t, core.DeviceAuthorizationStatusDenied, g.Authorization.Status)
}

// TestUpdatePollingBumpsInterval pins RFC 8628 §3.5 slow_down handling:
// when the AS observes the client polled faster than the advertised
// interval, the next poll MUST receive an interval bumped by 5 seconds.
// Also pins that LastPolledAt is persisted so the next poll can do its
// own interval check.
func TestUpdatePollingBumpsInterval(t *testing.T, factory Factory) {
	s := factory(t).Store
	createDeviceAuth(t, s, newAuth())
	_, err := s.UpdatePollingState(context.Background(), &core.UpdatePollingStateRequest{
		DeviceCode: "dc-abc", PolledAt: time.Now(), SlowDown: true,
	})
	require.NoError(t, err)
	g, _ := s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	assert.Equal(t, 10, g.Authorization.IntervalSeconds, "slow_down MUST bump interval by 5 per RFC 8628 §3.5")
	assert.False(t, g.Authorization.LastPolledAt.IsZero(), "LastPolledAt MUST be persisted")
}

// TestDeleteRemovesUserCodeIndex pins that Delete clears BOTH lookup
// paths. The user_code index is a denormalized secondary key; backends
// that forget to clean it leak a record reachable by user_code but not
// by device_code.
func TestDeleteRemovesUserCodeIndex(t *testing.T, factory Factory) {
	s := factory(t).Store
	createDeviceAuth(t, s, newAuth())
	_, err := s.DeleteDeviceAuthorization(context.Background(), &core.DeleteDeviceAuthorizationRequest{DeviceCode: "dc-abc"})
	require.NoError(t, err)
	_, err = s.GetByUserCode(context.Background(), &core.GetByUserCodeRequest{UserCode: "WDJB-MJHT"})
	require.True(t, errors.Is(err, core.ErrDeviceAuthorizationNotFound),
		"delete MUST clear the user_code lookup path too")
}

// TestCleanupExpired pins that CleanupExpired removes only expired
// records and reports the count. The non-expired record MUST survive —
// a naive "delete all" would prematurely cancel pending authorizations.
func TestCleanupExpired(t *testing.T, factory Factory) {
	s := factory(t).Store
	live := newAuth()
	live.DeviceCode = "dc-live"
	live.UserCode = "AAAA-BBBB"
	stale := newAuth()
	stale.DeviceCode = "dc-stale"
	stale.UserCode = "CCCC-DDDD"
	stale.ExpiresAt = time.Now().Add(-time.Minute)
	createDeviceAuth(t, s, live)
	createDeviceAuth(t, s, stale)

	resp, err := s.CleanupExpired(context.Background(), &core.CleanupExpiredDeviceAuthsRequest{})
	require.NoError(t, err)
	assert.Equal(t, 1, resp.Removed)
	_, err = s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-live"})
	require.NoError(t, err, "non-expired record MUST survive cleanup")
}

// TestRestartPersists pins that a record written via the initial Store
// handle is visible via a freshly-opened handle over the same backing
// storage. For persistent backends this is the property the backend
// exists to provide; for in-memory it degenerates to a same-handle
// round-trip (Reopen returns the receiver) which is trivially true and
// kept as a no-op so the scenario set is identical across all backends.
func TestRestartPersists(t *testing.T, factory Factory) {
	b := factory(t)
	createDeviceAuth(t, b.Store, newAuth())
	_, err := b.Store.ApproveDeviceAuthorization(context.Background(), &core.ApproveDeviceAuthorizationRequest{
		UserCode: "WDJB-MJHT", ApprovedSubject: "alice",
	})
	require.NoError(t, err)

	s2 := b.Reopen()
	g, err := s2.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	require.NoError(t, err)
	assert.Equal(t, core.DeviceAuthorizationStatusApproved, g.Authorization.Status)
	assert.Equal(t, "alice", g.Authorization.ApprovedSubject)
}
