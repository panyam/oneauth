package fs

// The FS refresh token store keeps only a token's hash at rest, as the
// GORM and GAE stores do, so reading the store's directory yields no
// usable refresh token (issue 526).
//
// References:
//   - RFC 6819 §5.1.4.1.3 (https://www.rfc-editor.org/rfc/rfc6819#section-5.1.4.1.3): store hashes of tokens
//   - See: https://github.com/panyam/oneauth/issues/526

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/core"
)

// storeFilesContain reports which of the store's files contain secret.
func storeFilesContain(t *testing.T, s *FSRefreshTokenStore, secret string) []string {
	t.Helper()
	var hits []string
	entries, err := os.ReadDir(s.getTokenDir())
	require.NoError(t, err)
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(s.getTokenDir(), e.Name()))
		require.NoError(t, err)
		if strings.Contains(string(data), secret) {
			hits = append(hits, e.Name())
		}
	}
	return hits
}

// See: https://www.rfc-editor.org/rfc/rfc6819#section-5.1.4.1.3
func TestFSRefreshTokens_OnlyHashesAtRest(t *testing.T) {
	ctx := context.Background()
	s := NewFSRefreshTokenStore(t.TempDir())

	created, err := s.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{Subject: "alice", ClientID: "app"})
	require.NoError(t, err)
	first := created.Token.Token
	require.NotEmpty(t, first, "the caller still gets the token it hands to the client")
	assert.Empty(t, storeFilesContain(t, s, first), "a new token's file must not hold the token")

	got, err := s.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: first})
	require.NoError(t, err)
	assert.Equal(t, first, got.Token.Token, "a lookup still returns the token it was asked about")
	assert.Equal(t, "alice", got.Token.Subject)

	rotated, err := s.RotateRefreshToken(ctx, &core.RotateRefreshTokenRequest{OldToken: first})
	require.NoError(t, err)
	second := rotated.Token.Token
	assert.Empty(t, storeFilesContain(t, s, first), "rotation rewrites the old record without the token")
	assert.Empty(t, storeFilesContain(t, s, second), "the successor's file must not hold the token")

	_, err = s.RevokeTokenFamily(ctx, &core.RevokeTokenFamilyRequest{Family: rotated.Token.Family})
	require.NoError(t, err)
	assert.Empty(t, storeFilesContain(t, s, second))
	got, err = s.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: second})
	require.NoError(t, err)
	assert.True(t, got.Token.Revoked, "revoking by family still finds the hash-only record")
}

// A file written before the fix still holds the token. It stays readable,
// and the next rewrite drops the plaintext.
func TestFSRefreshTokens_LegacyPlaintextFileIsReadableAndScrubbedOnRewrite(t *testing.T) {
	ctx := context.Background()
	s := NewFSRefreshTokenStore(t.TempDir())
	created, err := s.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{Subject: "alice", ClientID: "app"})
	require.NoError(t, err)
	token := created.Token.Token

	legacy := *created.Token
	data, err := json.Marshal(&legacy)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(s.getTokenPath(token), data, 0600))
	require.NotEmpty(t, storeFilesContain(t, s, token), "fixture: the legacy file holds the token")

	got, err := s.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: token})
	require.NoError(t, err)
	assert.Equal(t, "alice", got.Token.Subject)

	_, err = s.RevokeRefreshToken(ctx, &core.RevokeRefreshTokenRequest{Token: token})
	require.NoError(t, err)
	assert.Empty(t, storeFilesContain(t, s, token), "the rewrite drops the legacy plaintext")
}
