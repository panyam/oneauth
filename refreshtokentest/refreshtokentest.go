// Package refreshtokentest is the shared contract suite for
// core.RefreshTokenStore's access-token bookkeeping: RecordAccessToken
// and the access tokens RevokeTokenFamily hands back. Revoking a refresh
// token has to take the access tokens issued from the same grant with it
// (RFC 7009 §2.1), and the store is the only place that knows which
// those are, so every backend runs these scenarios through RunAll.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2
package refreshtokentest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Factory returns a store over fresh (or at least isolated) storage for
// one scenario.
type Factory func(t *testing.T) core.RefreshTokenStore

// RunAll runs every scenario against the factory's backend.
func RunAll(t *testing.T, factory Factory) {
	t.Run("RevokeFamilyReturnsEveryGeneration", func(t *testing.T) { TestRevokeFamilyReturnsEveryGeneration(t, factory) })
	t.Run("SeveralAccessTokensOnOneRecord", func(t *testing.T) { TestSeveralAccessTokensOnOneRecord(t, factory) })
	t.Run("ExpiredAccessTokensDropped", func(t *testing.T) { TestExpiredAccessTokensDropped(t, factory) })
	t.Run("RecordOnRevokedReportsRevoked", func(t *testing.T) { TestRecordOnRevokedReportsRevoked(t, factory) })
	t.Run("RecordOnMissingToken", func(t *testing.T) { TestRecordOnMissingToken(t, factory) })
	t.Run("FamiliesAreIsolated", func(t *testing.T) { TestFamiliesAreIsolated(t, factory) })
	t.Run("RevokeUnknownFamily", func(t *testing.T) { TestRevokeUnknownFamily(t, factory) })
	t.Run("ConcurrentRecordsAllKept", func(t *testing.T) { TestConcurrentRecordsAllKept(t, factory) })
}

func create(t *testing.T, s core.RefreshTokenStore) *core.RefreshToken {
	t.Helper()
	resp, err := s.CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{Subject: "alice", ClientID: "client-x"})
	require.NoError(t, err)
	return resp.Token
}

func record(t *testing.T, s core.RefreshTokenStore, token, jti string, exp time.Time) *core.RecordAccessTokenResponse {
	t.Helper()
	resp, err := s.RecordAccessToken(context.Background(), &core.RecordAccessTokenRequest{Token: token, TokenID: jti, ExpiresAt: exp})
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func revokeFamily(t *testing.T, s core.RefreshTokenStore, family string) []string {
	t.Helper()
	resp, err := s.RevokeTokenFamily(context.Background(), &core.RevokeTokenFamilyRequest{Family: family})
	require.NoError(t, err)
	require.NotNil(t, resp)
	var ids []string
	for _, a := range resp.AccessTokens {
		ids = append(ids, a.TokenID)
	}
	sort.Strings(ids)
	return ids
}

func revoked(t *testing.T, s core.RefreshTokenStore, token string) bool {
	t.Helper()
	resp, err := s.GetRefreshToken(context.Background(), &core.GetRefreshTokenRequest{Token: token})
	require.NoError(t, err)
	return resp.Token.Revoked
}

// TestRevokeFamilyReturnsEveryGeneration: an access token issued with the
// first refresh token is still live after rotation, and revoking the
// family through the newer token has to return it along with the
// newer one.
func TestRevokeFamilyReturnsEveryGeneration(t *testing.T, factory Factory) {
	s := factory(t)
	ctx := context.Background()
	exp := time.Now().Add(15 * time.Minute)

	first := create(t, s)
	assert.False(t, record(t, s, first.Token, "at-1", exp).Revoked)
	rot, err := s.RotateRefreshToken(ctx, &core.RotateRefreshTokenRequest{OldToken: first.Token})
	require.NoError(t, err)
	assert.False(t, record(t, s, rot.Token.Token, "at-2", exp).Revoked)

	got, err := s.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: rot.Token.Token})
	require.NoError(t, err)
	require.Len(t, got.Token.AccessTokens, 1, "recorded access tokens read back")
	assert.Equal(t, "at-2", got.Token.AccessTokens[0].TokenID)
	assert.WithinDuration(t, exp, got.Token.AccessTokens[0].ExpiresAt, time.Second)

	assert.Equal(t, []string{"at-1", "at-2"}, revokeFamily(t, s, first.Family))
	assert.True(t, revoked(t, s, rot.Token.Token))
}

// TestSeveralAccessTokensOnOneRecord: with rotation off (FAPI 2.0) one
// refresh token mints an access token per refresh.
func TestSeveralAccessTokensOnOneRecord(t *testing.T, factory Factory) {
	s := factory(t)
	exp := time.Now().Add(15 * time.Minute)
	rt := create(t, s)
	record(t, s, rt.Token, "at-1", exp)
	record(t, s, rt.Token, "at-2", exp)
	record(t, s, rt.Token, "at-3", exp)
	assert.Equal(t, []string{"at-1", "at-2", "at-3"}, revokeFamily(t, s, rt.Family))
}

// TestExpiredAccessTokensDropped: an expired access token needs no
// blacklist entry, and a record that is refreshed for days must not grow
// without bound.
func TestExpiredAccessTokensDropped(t *testing.T, factory Factory) {
	s := factory(t)
	ctx := context.Background()
	rt := create(t, s)
	record(t, s, rt.Token, "at-old", time.Now().Add(-time.Minute))
	record(t, s, rt.Token, "at-new", time.Now().Add(15*time.Minute))

	got, err := s.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: rt.Token})
	require.NoError(t, err)
	require.Len(t, got.Token.AccessTokens, 1, "expired entry pruned on record")
	assert.Equal(t, []string{"at-new"}, revokeFamily(t, s, rt.Family))
}

// TestRecordOnRevokedReportsRevoked: a revocation that landed before the
// access token was recorded never saw it, so the caller has to be told.
func TestRecordOnRevokedReportsRevoked(t *testing.T, factory Factory) {
	s := factory(t)
	rt := create(t, s)
	revokeFamily(t, s, rt.Family)
	assert.True(t, record(t, s, rt.Token, "at-late", time.Now().Add(15*time.Minute)).Revoked)
}

// TestRecordOnMissingToken maps an unknown token to core.ErrTokenNotFound.
func TestRecordOnMissingToken(t *testing.T, factory Factory) {
	s := factory(t)
	_, err := s.RecordAccessToken(context.Background(), &core.RecordAccessTokenRequest{
		Token: "no-such-token", TokenID: "at-1", ExpiresAt: time.Now().Add(time.Minute),
	})
	assert.True(t, errors.Is(err, core.ErrTokenNotFound), "got %v", err)
}

// TestFamiliesAreIsolated: revoking one session leaves another alone.
func TestFamiliesAreIsolated(t *testing.T, factory Factory) {
	s := factory(t)
	exp := time.Now().Add(15 * time.Minute)
	a := create(t, s)
	b := create(t, s)
	record(t, s, a.Token, "at-a", exp)
	record(t, s, b.Token, "at-b", exp)

	assert.Equal(t, []string{"at-a"}, revokeFamily(t, s, a.Family))
	assert.False(t, revoked(t, s, b.Token))
}

// TestRevokeUnknownFamily is a no-op, not an error.
func TestRevokeUnknownFamily(t *testing.T, factory Factory) {
	s := factory(t)
	assert.Empty(t, revokeFamily(t, s, "no-such-family"))
}

// TestConcurrentRecordsAllKept: parallel refreshes on one unrotated
// token each append; a lost update would leave an access token that
// revocation can't find.
func TestConcurrentRecordsAllKept(t *testing.T, factory Factory) {
	s := factory(t)
	rt := create(t, s)
	exp := time.Now().Add(15 * time.Minute)

	const n = 5
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.RecordAccessToken(context.Background(), &core.RecordAccessTokenRequest{
				Token: rt.Token, TokenID: fmt.Sprintf("at-%d", i), ExpiresAt: exp,
			})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Len(t, revokeFamily(t, s, rt.Family), n)
}
