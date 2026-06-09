package fs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newFSAuth() *core.DeviceAuthorization {
	return &core.DeviceAuthorization{
		DeviceCode:      "dc-fs-1",
		UserCode:        "WDJB-MJHT",
		ClientID:        "client-x",
		Scopes:          []string{"read"},
		Status:          core.DeviceAuthorizationStatusPending,
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(5 * time.Minute),
		IntervalSeconds: 5,
	}
}

func TestFSDeviceAuthStore_CreateGetDelete(t *testing.T) {
	s := NewFSDeviceAuthorizationStore(t.TempDir())
	a := newFSAuth()
	_, err := s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: a})
	require.NoError(t, err)

	g, err := s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-fs-1"})
	require.NoError(t, err)
	assert.Equal(t, "client-x", g.Authorization.ClientID)

	u, err := s.GetByUserCode(context.Background(), &core.GetByUserCodeRequest{UserCode: "wdjbmjht"})
	require.NoError(t, err)
	assert.Equal(t, "dc-fs-1", u.Authorization.DeviceCode)

	_, err = s.DeleteDeviceAuthorization(context.Background(), &core.DeleteDeviceAuthorizationRequest{DeviceCode: "dc-fs-1"})
	require.NoError(t, err)
	_, err = s.GetByUserCode(context.Background(), &core.GetByUserCodeRequest{UserCode: "WDJB-MJHT"})
	require.True(t, errors.Is(err, core.ErrDeviceAuthorizationNotFound))
}

func TestFSDeviceAuthStore_ApproveAndPersist(t *testing.T) {
	dir := t.TempDir()
	s := NewFSDeviceAuthorizationStore(dir)
	_, err := s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newFSAuth()})
	require.NoError(t, err)

	_, err = s.ApproveDeviceAuthorization(context.Background(), &core.ApproveDeviceAuthorizationRequest{
		UserCode:        "WDJB-MJHT",
		ApprovedSubject: "alice",
	})
	require.NoError(t, err)

	// Open a fresh store rooted at the same dir — simulate restart. The
	// approval MUST survive.
	s2 := NewFSDeviceAuthorizationStore(dir)
	g, err := s2.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-fs-1"})
	require.NoError(t, err)
	assert.Equal(t, core.DeviceAuthorizationStatusApproved, g.Authorization.Status)
	assert.Equal(t, "alice", g.Authorization.ApprovedSubject)
}

func TestFSDeviceAuthStore_CleanupExpired(t *testing.T) {
	s := NewFSDeviceAuthorizationStore(t.TempDir())
	live := newFSAuth()
	stale := newFSAuth()
	stale.DeviceCode = "dc-stale"
	stale.UserCode = "AAAA-BBBB"
	stale.ExpiresAt = time.Now().Add(-time.Minute)
	_, _ = s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: live})
	_, _ = s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: stale})

	resp, err := s.CleanupExpired(context.Background(), &core.CleanupExpiredDeviceAuthsRequest{})
	require.NoError(t, err)
	assert.Equal(t, 1, resp.Removed)
	_, err = s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-stale"})
	require.True(t, errors.Is(err, core.ErrDeviceAuthorizationNotFound))
	_, err = s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-fs-1"})
	require.NoError(t, err)
}
