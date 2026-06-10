//go:build !wasm
// +build !wasm

// Tests for the Datastore-backed DeviceAuthorizationStore.
//
// Same env contract as the other GAE backend tests — skips unless
// DATASTORE_PROJECT_ID is set, so plain `go test ./...` on a dev
// machine without the emulator running doesn't spuriously fail.
//
// To run against the Datastore emulator:
//
//	make upds && make testds
//
// Or manually:
//
//	export DATASTORE_EMULATOR_HOST=localhost:8081
//	export DATASTORE_PROJECT_ID=test-project
//	GOWORK=off go test -v ./stores/gae/...

package gae

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option" //nolint:staticcheck // WithCredentialsFile is simpler for test use
)

func setupDeviceAuthStore(t *testing.T) (*GAEDeviceAuthStore, *datastore.Client, string) {
	t.Helper()
	projectID := os.Getenv("DATASTORE_PROJECT_ID")
	if projectID == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping GAE DeviceAuthStore tests")
	}
	namespace := os.Getenv("DATASTORE_TEST_NAMESPACE")
	if namespace == "" {
		namespace = "oneauth-deviceauth-test"
	}
	ctx := context.Background()
	var opts []option.ClientOption
	if credsFile := os.Getenv("DATASTORE_CREDENTIALS_FILE"); credsFile != "" {
		opts = append(opts, option.WithCredentialsFile(credsFile))
	}
	client, err := datastore.NewClient(ctx, projectID, opts...)
	if err != nil {
		t.Fatalf("Failed to create Datastore client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	cleanup := func() {
		q := datastore.NewQuery(KindDeviceAuthorization).KeysOnly().Namespace(namespace)
		keys, err := client.GetAll(ctx, q, nil)
		if err != nil {
			t.Logf("cleanup query: %v", err)
			return
		}
		if len(keys) > 0 {
			if err := client.DeleteMulti(ctx, keys); err != nil {
				t.Logf("cleanup delete: %v", err)
			}
		}
	}
	cleanup()
	t.Cleanup(cleanup)
	return NewDeviceAuthStore(client, namespace), client, namespace
}

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

func TestGAEDeviceAuthStore_CreateAndGet(t *testing.T) {
	s, _, _ := setupDeviceAuthStore(t)
	_, err := s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	require.NoError(t, err)

	g, err := s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	require.NoError(t, err)
	assert.Equal(t, "dc-abc", g.Authorization.DeviceCode)
	assert.Equal(t, []string{"read"}, g.Authorization.Scopes, "Scopes slice MUST round-trip through Datastore")

	u, err := s.GetByUserCode(context.Background(), &core.GetByUserCodeRequest{UserCode: "wdjbmjht"})
	require.NoError(t, err, "user_code lookup MUST be case- and dash-insensitive")
	assert.Equal(t, "dc-abc", u.Authorization.DeviceCode)
}

func TestGAEDeviceAuthStore_NotFound(t *testing.T) {
	s, _, _ := setupDeviceAuthStore(t)
	_, err := s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "missing"})
	require.True(t, errors.Is(err, core.ErrDeviceAuthorizationNotFound))
	_, err = s.GetByUserCode(context.Background(), &core.GetByUserCodeRequest{UserCode: "ABCD-EFGH"})
	require.True(t, errors.Is(err, core.ErrDeviceAuthorizationNotFound))
}

func TestGAEDeviceAuthStore_Collision(t *testing.T) {
	s, _, _ := setupDeviceAuthStore(t)
	_, err := s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	require.NoError(t, err)
	_, err = s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	require.Error(t, err, "device_code + user_code collision MUST be rejected")
}

func TestGAEDeviceAuthStore_ApproveBindsSubjectAndOverridesScopes(t *testing.T) {
	s, _, _ := setupDeviceAuthStore(t)
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

func TestGAEDeviceAuthStore_ApproveTwice_Rejects(t *testing.T) {
	s, _, _ := setupDeviceAuthStore(t)
	_, _ = s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
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

func TestGAEDeviceAuthStore_DenyTransitions(t *testing.T) {
	s, _, _ := setupDeviceAuthStore(t)
	_, _ = s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	_, err := s.DenyDeviceAuthorization(context.Background(), &core.DenyDeviceAuthorizationRequest{UserCode: "WDJB-MJHT"})
	require.NoError(t, err)
	g, _ := s.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	assert.Equal(t, core.DeviceAuthorizationStatusDenied, g.Authorization.Status)
}

func TestGAEDeviceAuthStore_UpdatePollingBumpsInterval(t *testing.T) {
	s, _, _ := setupDeviceAuthStore(t)
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

func TestGAEDeviceAuthStore_DeleteRemovesUserCodeIndex(t *testing.T) {
	s, _, _ := setupDeviceAuthStore(t)
	_, _ = s.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	_, err := s.DeleteDeviceAuthorization(context.Background(), &core.DeleteDeviceAuthorizationRequest{DeviceCode: "dc-abc"})
	require.NoError(t, err)
	_, err = s.GetByUserCode(context.Background(), &core.GetByUserCodeRequest{UserCode: "WDJB-MJHT"})
	require.True(t, errors.Is(err, core.ErrDeviceAuthorizationNotFound),
		"delete MUST clear the user_code lookup path too")
}

func TestGAEDeviceAuthStore_CleanupExpired(t *testing.T) {
	s, _, _ := setupDeviceAuthStore(t)
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

func TestGAEDeviceAuthStore_RestartPersists(t *testing.T) {
	s1, client, namespace := setupDeviceAuthStore(t)
	_, err := s1.CreateDeviceAuthorization(context.Background(), &core.CreateDeviceAuthorizationRequest{Authorization: newDeviceAuth()})
	require.NoError(t, err)
	_, err = s1.ApproveDeviceAuthorization(context.Background(), &core.ApproveDeviceAuthorizationRequest{
		UserCode: "WDJB-MJHT", ApprovedSubject: "alice",
	})
	require.NoError(t, err)

	// Fresh store over the same Datastore namespace — what a process
	// restart would see. Datastore is the shared source of truth.
	s2 := NewDeviceAuthStore(client, namespace)
	g, err := s2.GetByDeviceCode(context.Background(), &core.GetByDeviceCodeRequest{DeviceCode: "dc-abc"})
	require.NoError(t, err)
	assert.Equal(t, core.DeviceAuthorizationStatusApproved, g.Authorization.Status)
	assert.Equal(t, "alice", g.Authorization.ApprovedSubject)
}

func TestGAEUpperUserCode_NormalizesCaseAndStripsDashes(t *testing.T) {
	// Drift catch — this helper duplicates the rule in core + stores/fs +
	// stores/gorm. Any divergence breaks the GetByUserCode contract
	// loudly. Consolidation tracked as a follow-up to issue 270.
	cases := []struct{ in, want string }{
		{"WDJB-MJHT", "WDJBMJHT"},
		{"wdjb mjht", "WDJBMJHT"},
		{"WdJb-MjHt", "WDJBMJHT"},
		{"", ""},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, upperUserCode(tc.in), tc.in)
	}
}
