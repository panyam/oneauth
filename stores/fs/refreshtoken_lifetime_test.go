package fs

// Rotation hands out a new refresh token but keeps the family's expiry, so
// a stolen token family can't be kept alive forever by refreshing it.
//
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2
// See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
)

func TestFSRefreshTokenStore_RotationKeepsTheFamilyExpiry(t *testing.T) {
	ctx := context.Background()
	store := NewFSRefreshTokenStore(t.TempDir())
	created, err := store.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{Subject: "alice", ClientID: "c"})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	rotated, err := store.RotateRefreshToken(ctx, &core.RotateRefreshTokenRequest{OldToken: created.Token.Token})
	if err != nil {
		t.Fatal(err)
	}
	if d := rotated.Token.ExpiresAt.Sub(created.Token.ExpiresAt); d > 5*time.Millisecond || d < -5*time.Millisecond {
		t.Fatalf("rotated token expires %v after the family's original expiry, want the same instant", d)
	}
}
