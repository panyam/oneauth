//go:build !wasm
// +build !wasm

// Tests for the GORM-backed DeviceAuthorizationStore — runs against
// SQLite by default, against PostgreSQL when ONEAUTH_TEST_PGDB is set
// (same pattern as the other GORM-backend tests).
//
// Mirrors the scenario set from core/device_authorization_test.go so
// every store implementation is verified against the same behavioral
// contract.

package gorm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newDeviceAuth() *core.DeviceAuthorization {
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

func TestGORMDeviceAuthStore_CreateAndGet(t *testing.T) {
	s := NewDeviceAuthStore(setupTestDB(t))
	_, err := s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	require.NoError(t, err)

	g, err := s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	require.NoError(t, err)
	assert.Equal(t, "dc-abc", g.Authorization.DeviceCode)
	assert.Equal(t, []string{"read"}, g.Authorization.Scopes, "json-serialized slice MUST round-trip")

	u, err := s.GetByUserCode(context.Background(), &core.GetByUserCodeRequest{UserCode: "wdjbmjht"})
	require.NoError(t, err, "user_code lookup MUST be case- and dash-insensitive")
	assert.Equal(t, "dc-abc", u.Authorization.DeviceCode)
}

func TestGORMDeviceAuthStore_NotFound(t *testing.T) {
	s := NewDeviceAuthStore(setupTestDB(t))
	_, err := s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "missing"})
	require.True(t, errors.Is(err, core.ErrDeviceAuthorizationNotFound))
	_, err = s.GetByUserCode(context.Background(), &core.GetByUserCodeRequest{UserCode: "ABCD-EFGH"})
	require.True(t, errors.Is(err, core.ErrDeviceAuthorizationNotFound))
}

func TestGORMDeviceAuthStore_Collision(t *testing.T) {
	s := NewDeviceAuthStore(setupTestDB(t))
	_, err := s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	require.NoError(t, err)
	_, err = s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	require.Error(t, err, "device_code + user_code collision MUST be rejected")
}

func TestGORMDeviceAuthStore_ApproveBindsSubjectAndOverridesScopes(t *testing.T) {
	s := NewDeviceAuthStore(setupTestDB(t))
	_, err := s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	require.NoError(t, err)

	_, err = s.ApproveDeviceAuthorization(context.Background(), &core.ApproveDeviceAuthorizationRequest{
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

func TestGORMDeviceAuthStore_ApproveTwice_Rejects(t *testing.T) {
	s := NewDeviceAuthStore(setupTestDB(t))
	_, _ = s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	_, err := s.ApproveDeviceAuthorization(context.Background(), &core.ApproveDeviceAuthorizationRequest{
		UserCode: "WDJB-MJHT", ApprovedSubject: "alice",
	})
	require.NoError(t, err)
	_, err = s.ApproveDeviceAuthorization(context.Background(), &core.ApproveDeviceAuthorizationRequest{
		UserCode: "WDJB-MJHT", ApprovedSubject: "alice",
	})
	require.True(t, errors.Is(err, core.ErrDeviceAuthorizationNotFound),
		"second approval of an already-approved record MUST look like not-found, not a noisy state transition")
}

func TestGORMDeviceAuthStore_DenyTransitions(t *testing.T) {
	s := NewDeviceAuthStore(setupTestDB(t))
	_, _ = s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	_, err := s.DenyDeviceAuthorization(context.Background(), &core.DenyDeviceAuthorizationRequest{UserCode: "WDJB-MJHT"})
	require.NoError(t, err)
	g, _ := s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	assert.Equal(t, core.DeviceAuthorizationStatusDenied, g.Authorization.Status)
}

func TestGORMDeviceAuthStore_UpdatePollingBumpsInterval(t *testing.T) {
	s := NewDeviceAuthStore(setupTestDB(t))
	_, _ = s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	now := time.Now()
	_, err := s.UpdatePollingState(context.Background(), &core.UpdatePollingStateRequest{
		DeviceCode: "dc-abc", PolledAt: now, SlowDown: true,
	})
	require.NoError(t, err)
	g, _ := s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	assert.Equal(t, 10, g.Authorization.IntervalSeconds, "slow_down MUST bump interval by 5 per RFC 8628 §3.5")
	assert.False(t, g.Authorization.LastPolledAt.IsZero(), "LastPolledAt MUST be persisted")
}

func TestGORMDeviceAuthStore_DeleteRemovesUserCodeIndex(t *testing.T) {
	s := NewDeviceAuthStore(setupTestDB(t))
	_, _ = s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	_, err := s.DeleteDeviceAuthorization(context.Background(), &core.DeleteDeviceAuthorizationRequest{DeviceCode: "dc-abc"})
	require.NoError(t, err)
	_, err = s.GetByUserCode(context.Background(), &core.GetByUserCodeRequest{UserCode: "WDJB-MJHT"})
	require.True(t, errors.Is(err, core.ErrDeviceAuthorizationNotFound),
		"delete MUST clear the user_code lookup path too")
}

func TestGORMDeviceAuthStore_CleanupExpired(t *testing.T) {
	s := NewDeviceAuthStore(setupTestDB(t))
	live := newDeviceAuth()
	live.DeviceCode = "dc-live"
	live.UserCode = "AAAA-BBBB"
	stale := newDeviceAuth()
	stale.DeviceCode = "dc-stale"
	stale.UserCode = "CCCC-DDDD"
	stale.ExpiresAt = time.Now().Add(-time.Minute)
	_, _ = s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: live})
	_, _ = s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: stale})

	resp, err := s.CleanupExpired(context.Background(), &core.CleanupExpiredDeviceAuthsRequest{})
	require.NoError(t, err)
	assert.Equal(t, 1, resp.Removed)
	_, err = s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-live"})
	require.NoError(t, err, "non-expired record MUST survive cleanup")
}

func TestGORMDeviceAuthStore_RestartPersists(t *testing.T) {
	// Restart parity: when the process restarts and a fresh store opens
	// over the same DB, the device authorization (and its status) MUST
	// still be there. This is the property the in-memory store cannot
	// satisfy and is the main reason this backend exists.
	db := setupTestDB(t)
	s := NewDeviceAuthStore(db)
	_, err := s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	require.NoError(t, err)
	_, err = s.ApproveDeviceAuthorization(context.Background(), &core.ApproveDeviceAuthorizationRequest{
		UserCode: "WDJB-MJHT", ApprovedSubject: "alice",
	})
	require.NoError(t, err)

	// Fresh store over the same DB connection — same as a new process
	// opening the same database file.
	s2 := NewDeviceAuthStore(db)
	g, err := s2.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	require.NoError(t, err)
	assert.Equal(t, core.DeviceAuthorizationStatusApproved, g.Authorization.Status)
	assert.Equal(t, "alice", g.Authorization.ApprovedSubject)
}
