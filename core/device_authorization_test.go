package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newAuth(t *testing.T) *DeviceAuthorization {
	t.Helper()
	return &DeviceAuthorization{
		DeviceCode:      "dc-abc",
		UserCode:        "WDJB-MJHT",
		ClientID:        "client-x",
		Scopes:          []string{"read"},
		Status:          DeviceAuthorizationStatusPending,
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(5 * time.Minute),
		IntervalSeconds: 5,
	}
}

func TestInMemoryDeviceAuthStore_CreateAndGet(t *testing.T) {
	s := NewInMemoryDeviceAuthorizationStore()
	a := newAuth(t)
	_, err := s.CreateDeviceAuthorization(context.Background(), &CreateDeviceAuthorizationRequest{Authorization: a})
	require.NoError(t, err)

	g, err := s.GetByDeviceCode(context.Background(), &GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	require.NoError(t, err)
	require.Equal(t, "dc-abc", g.Authorization.DeviceCode)

	// user_code lookup is case-insensitive and dash-insensitive.
	u, err := s.GetByUserCode(context.Background(), &GetByUserCodeRequest{UserCode: "wdjbmjht"})
	require.NoError(t, err)
	require.Equal(t, "dc-abc", u.Authorization.DeviceCode)
}

func TestInMemoryDeviceAuthStore_NotFound(t *testing.T) {
	s := NewInMemoryDeviceAuthorizationStore()
	_, err := s.GetByDeviceCode(context.Background(), &GetByDeviceCodeRequest{DeviceCode: "missing"})
	require.True(t, errors.Is(err, ErrDeviceAuthorizationNotFound))
	_, err = s.GetByUserCode(context.Background(), &GetByUserCodeRequest{UserCode: "ABCD-EFGH"})
	require.True(t, errors.Is(err, ErrDeviceAuthorizationNotFound))
}

func TestInMemoryDeviceAuthStore_Collision(t *testing.T) {
	s := NewInMemoryDeviceAuthorizationStore()
	a := newAuth(t)
	_, err := s.CreateDeviceAuthorization(context.Background(), &CreateDeviceAuthorizationRequest{Authorization: a})
	require.NoError(t, err)
	_, err = s.CreateDeviceAuthorization(context.Background(), &CreateDeviceAuthorizationRequest{Authorization: a})
	require.Error(t, err)
}

func TestInMemoryDeviceAuthStore_ApproveBindsSubjectAndOverridesScopes(t *testing.T) {
	s := NewInMemoryDeviceAuthorizationStore()
	a := newAuth(t)
	_, err := s.CreateDeviceAuthorization(context.Background(), &CreateDeviceAuthorizationRequest{Authorization: a})
	require.NoError(t, err)

	_, err = s.ApproveDeviceAuthorization(context.Background(), &ApproveDeviceAuthorizationRequest{
		UserCode:        "WDJBMJHT",
		ApprovedSubject: "alice",
		GrantedScopes:   []string{"read", "write"},
	})
	require.NoError(t, err)

	g, _ := s.GetByDeviceCode(context.Background(), &GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	assert.Equal(t, DeviceAuthorizationStatusApproved, g.Authorization.Status)
	assert.Equal(t, "alice", g.Authorization.ApprovedSubject)
	assert.Equal(t, []string{"read", "write"}, g.Authorization.Scopes)
}

func TestInMemoryDeviceAuthStore_ApproveTwice_Rejects(t *testing.T) {
	s := NewInMemoryDeviceAuthorizationStore()
	_, _ = s.CreateDeviceAuthorization(context.Background(), &CreateDeviceAuthorizationRequest{Authorization: newAuth(t)})
	_, err := s.ApproveDeviceAuthorization(context.Background(), &ApproveDeviceAuthorizationRequest{
		UserCode: "WDJB-MJHT", ApprovedSubject: "alice",
	})
	require.NoError(t, err)
	_, err = s.ApproveDeviceAuthorization(context.Background(), &ApproveDeviceAuthorizationRequest{
		UserCode: "WDJB-MJHT", ApprovedSubject: "alice",
	})
	require.True(t, errors.Is(err, ErrDeviceAuthorizationNotFound),
		"second approval of an already-approved record must look like not-found, not a noisy state transition")
}

func TestInMemoryDeviceAuthStore_DenyTransitions(t *testing.T) {
	s := NewInMemoryDeviceAuthorizationStore()
	_, _ = s.CreateDeviceAuthorization(context.Background(), &CreateDeviceAuthorizationRequest{Authorization: newAuth(t)})
	_, err := s.DenyDeviceAuthorization(context.Background(), &DenyDeviceAuthorizationRequest{UserCode: "WDJB-MJHT"})
	require.NoError(t, err)
	g, _ := s.GetByDeviceCode(context.Background(), &GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	assert.Equal(t, DeviceAuthorizationStatusDenied, g.Authorization.Status)
}

func TestInMemoryDeviceAuthStore_UpdatePollingBumpsInterval(t *testing.T) {
	s := NewInMemoryDeviceAuthorizationStore()
	_, _ = s.CreateDeviceAuthorization(context.Background(), &CreateDeviceAuthorizationRequest{Authorization: newAuth(t)})
	_, err := s.UpdatePollingState(context.Background(), &UpdatePollingStateRequest{
		DeviceCode: "dc-abc", PolledAt: time.Now(), SlowDown: true,
	})
	require.NoError(t, err)
	g, _ := s.GetByDeviceCode(context.Background(), &GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	assert.Equal(t, 10, g.Authorization.IntervalSeconds, "slow_down bumps interval by 5 per RFC 8628 §3.5")
}

func TestInMemoryDeviceAuthStore_DeleteRemovesUserCodeIndex(t *testing.T) {
	s := NewInMemoryDeviceAuthorizationStore()
	_, _ = s.CreateDeviceAuthorization(context.Background(), &CreateDeviceAuthorizationRequest{Authorization: newAuth(t)})
	_, err := s.DeleteDeviceAuthorization(context.Background(), &DeleteDeviceAuthorizationRequest{DeviceCode: "dc-abc"})
	require.NoError(t, err)
	_, err = s.GetByUserCode(context.Background(), &GetByUserCodeRequest{UserCode: "WDJB-MJHT"})
	require.True(t, errors.Is(err, ErrDeviceAuthorizationNotFound), "delete must clear the user_code index too")
}

func TestInMemoryDeviceAuthStore_CleanupExpired(t *testing.T) {
	s := NewInMemoryDeviceAuthorizationStore()
	live := newAuth(t)
	live.DeviceCode = "dc-live"
	live.UserCode = "AAAA-BBBB"
	stale := newAuth(t)
	stale.DeviceCode = "dc-stale"
	stale.UserCode = "CCCC-DDDD"
	stale.ExpiresAt = time.Now().Add(-time.Minute)
	_, _ = s.CreateDeviceAuthorization(context.Background(), &CreateDeviceAuthorizationRequest{Authorization: live})
	_, _ = s.CreateDeviceAuthorization(context.Background(), &CreateDeviceAuthorizationRequest{Authorization: stale})

	resp, err := s.CleanupExpired(context.Background(), &CleanupExpiredDeviceAuthsRequest{})
	require.NoError(t, err)
	assert.Equal(t, 1, resp.Removed)
	_, err = s.GetByDeviceCode(context.Background(), &GetByDeviceCodeRequest{DeviceCode: "dc-live"})
	require.NoError(t, err, "non-expired record must survive cleanup")
}

func TestDeviceAuthorization_IsExpired(t *testing.T) {
	now := time.Now()
	a := &DeviceAuthorization{ExpiresAt: now.Add(time.Minute)}
	assert.False(t, a.IsExpired(now))
	a.ExpiresAt = now.Add(-time.Second)
	assert.True(t, a.IsExpired(now))
}

func TestUpperUserCode_NormalizesCaseAndStripsDashes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"WDJB-MJHT", "WDJBMJHT"},
		{"wdjb mjht", "WDJBMJHT"},
		{"WdJb-MjHt", "WDJBMJHT"},
		{"", ""},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, UpperUserCode(tc.in), tc.in)
	}
}
