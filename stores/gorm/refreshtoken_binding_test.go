//go:build !wasm
// +build !wasm

// Tests that a DPoP sender-constraint survives the GORM refresh-token
// round trip. The binding lives in its own column rather than inside the
// existing JSON blobs, so a mapping mistake would silently drop it — and a
// dropped binding turns a sender-constrained refresh token back into a
// bearer token that any thief can redeem.
//
// References:
//   - RFC 9449 §5 (https://www.rfc-editor.org/rfc/rfc9449#section-5)
//   - See: https://github.com/panyam/oneauth/issues/336
package gorm

import (
	"context"
	"testing"

	"github.com/panyam/oneauth/core"
)

const testJKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

func TestRefreshTokenStore_ConfirmationSurvivesReadAndRotation(t *testing.T) {
	ctx := context.Background()
	store := NewRefreshTokenStore(setupTestDB(t))

	created, err := store.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{
		Subject:      "user-1",
		ClientID:     "client-1",
		Scopes:       []string{"read"},
		Confirmation: &core.Confirmation{JKT: testJKT},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: created.Token.Token})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Token.Confirmation == nil || got.Token.Confirmation.JKT != testJKT {
		t.Fatalf("read back %#v, want jkt %q", got.Token.Confirmation, testJKT)
	}

	rotated, err := store.RotateRefreshToken(ctx, &core.RotateRefreshTokenRequest{OldToken: created.Token.Token})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.Token.Confirmation == nil || rotated.Token.Confirmation.JKT != testJKT {
		t.Fatalf("rotated %#v, want jkt %q", rotated.Token.Confirmation, testJKT)
	}
}

// An unbound token must read back as nil, not as an empty Confirmation: an
// empty binding would name no key and make the token unredeemable by anyone.
func TestRefreshTokenStore_UnboundTokenStaysUnbound(t *testing.T) {
	ctx := context.Background()
	store := NewRefreshTokenStore(setupTestDB(t))

	created, err := store.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{Subject: "user-2"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := store.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: created.Token.Token})
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if got.Token.Confirmation != nil {
		t.Fatalf("unbound token read back as %#v, want nil", got.Token.Confirmation)
	}
}
