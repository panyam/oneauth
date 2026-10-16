package authcodetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func consume(s core.AuthorizationCodeStore, code string) (*core.ConsumeAuthorizationCodeResponse, error) {
	return s.ConsumeAuthorizationCode(context.Background(), &core.ConsumeAuthorizationCodeRequest{Code: code})
}

func record(t *testing.T, s core.AuthorizationCodeStore, code string, tokenExpiry time.Time) *core.RecordAuthorizationCodeTokensResponse {
	t.Helper()
	resp, err := s.RecordAuthorizationCodeTokens(context.Background(), &core.RecordAuthorizationCodeTokensRequest{
		Code:           code,
		TokenID:        "jti-1",
		TokenExpiresAt: tokenExpiry,
		RefreshFamily:  "family-1",
	})
	require.NoError(t, err)
	return resp
}

// TestConsumeOnce pins the single-use gate: the first consume succeeds
// and returns the unused record, and every later one returns
// ErrAuthorizationCodeUsed with the tokens the first redemption recorded,
// which the caller revokes.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.5
func TestConsumeOnce(t *testing.T, factory Factory) {
	s := factory(t).Store
	createCode(t, s, newCode())

	first, err := consume(s, "code-abc")
	require.NoError(t, err)
	assert.False(t, first.Code.IsUsed(), "the first consume returns the record as it was before")
	assert.Equal(t, "user-1", first.Code.Subject)

	tokenExpiry := time.Now().Add(time.Hour).Truncate(time.Second)
	assert.False(t, record(t, s, "code-abc", tokenExpiry).ReuseDetected)

	second, err := consume(s, "code-abc")
	require.True(t, errors.Is(err, core.ErrAuthorizationCodeUsed), "a second consume MUST fail: %v", err)
	require.NotNil(t, second, "the used record comes back with the error")
	assert.True(t, second.Code.IsUsed())
	assert.Equal(t, "jti-1", second.Code.IssuedTokenID)
	assert.Equal(t, "family-1", second.Code.IssuedRefreshFamily)
	assert.True(t, tokenExpiry.Equal(second.Code.IssuedTokenExpiresAt), "token expiry round-trips: %v", second.Code.IssuedTokenExpiresAt)

	_, err = consume(s, "missing")
	assert.True(t, errors.Is(err, core.ErrAuthorizationCodeNotFound))
}

// TestReuseBeforeRecord pins the race: a second redemption that lands
// between the first one's consume and its record finds no tokens to
// revoke, so the record step must report the reuse and the first
// redemption revokes its own tokens.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2
// See: https://cwe.mitre.org/data/definitions/367.html
func TestReuseBeforeRecord(t *testing.T, factory Factory) {
	s := factory(t).Store
	createCode(t, s, newCode())

	_, err := consume(s, "code-abc")
	require.NoError(t, err)

	second, err := consume(s, "code-abc")
	require.True(t, errors.Is(err, core.ErrAuthorizationCodeUsed))
	assert.Empty(t, second.Code.IssuedTokenID, "nothing recorded yet")

	assert.True(t, record(t, s, "code-abc", time.Now().Add(time.Hour)).ReuseDetected,
		"recording after a reuse MUST report it, or the first redemption's tokens stay valid")
}

// TestCleanupKeepsUsedUntilTokenExpiry pins retention: a used code
// outlives its own expiry until the access token it produced expires,
// so a late reuse can still find that token.
func TestCleanupKeepsUsedUntilTokenExpiry(t *testing.T, factory Factory) {
	s := factory(t).Store
	now := time.Now()

	retained := newCode()
	retained.Code = "retained"
	retained.ExpiresAt = now.Add(-time.Minute)
	createCode(t, s, retained)
	_, err := consume(s, "retained")
	require.NoError(t, err)
	record(t, s, "retained", now.Add(time.Hour))

	spent := newCode()
	spent.Code = "spent"
	spent.ExpiresAt = now.Add(-2 * time.Minute)
	createCode(t, s, spent)
	_, err = consume(s, "spent")
	require.NoError(t, err)
	record(t, s, "spent", now.Add(-time.Minute))

	resp, err := s.CleanupExpired(context.Background(), &core.CleanupExpiredAuthorizationCodesRequest{})
	require.NoError(t, err)
	assert.Equal(t, 1, resp.Removed)

	_, err = s.GetAuthorizationCode(context.Background(), &core.GetAuthorizationCodeRequest{Code: "retained"})
	assert.NoError(t, err, "a used code whose token is still live MUST survive cleanup")
	_, err = s.GetAuthorizationCode(context.Background(), &core.GetAuthorizationCodeRequest{Code: "spent"})
	assert.True(t, errors.Is(err, core.ErrAuthorizationCodeNotFound), "a used code whose token expired is removed")
}
