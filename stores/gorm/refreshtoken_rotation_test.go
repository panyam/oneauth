//go:build !wasm
// +build !wasm

// Refresh rotation in the GORM store: a token rotates once even when two
// requests read it before either writes, and rotation keeps the family's
// expiry.
//
// References:
//   - RFC 9700 §4.14.2 (https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2)
//   - CWE-367 (https://cwe.mitre.org/data/definitions/367.html)
//   - See: https://github.com/panyam/oneauth/issues/88
package gorm

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/panyam/oneauth/core"
)

// Another request rotating the same token commits between this one's read
// and its write. The callback plays that request: it marks the row revoked
// just before this transaction's update runs.
func TestRefreshTokenStore_RotationRaceHasOneWinner(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	store := NewRefreshTokenStore(db)
	created, err := store.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{Subject: "alice", ClientID: "c"})
	if err != nil {
		t.Fatal(err)
	}

	fired := false
	if err := db.Callback().Update().Before("gorm:update").Register("test:concurrent-rotation", func(tx *gorm.DB) {
		if fired || tx.Statement.Table != "refresh_tokens" {
			return
		}
		fired = true
		tx.Session(&gorm.Session{NewDB: true}).Exec("UPDATE refresh_tokens SET revoked = ? WHERE token_hash = ?", true, store.hashToken(created.Token.Token))
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Callback().Update().Remove("test:concurrent-rotation") })

	_, err = store.RotateRefreshToken(ctx, &core.RotateRefreshTokenRequest{OldToken: created.Token.Token})
	if !fired {
		t.Fatal("the concurrent-rotation callback never ran")
	}
	if !errors.Is(err, core.ErrTokenReused) {
		t.Fatalf("rotating a token another request already rotated: got %v, want ErrTokenReused", err)
	}
}

func TestRefreshTokenStore_RotationKeepsTheFamilyExpiry(t *testing.T) {
	ctx := context.Background()
	store := NewRefreshTokenStore(setupTestDB(t))
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
