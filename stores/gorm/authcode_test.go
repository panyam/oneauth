//go:build !wasm
// +build !wasm

// Tests for the GORM-backed AuthorizationCodeStore. Runs the shared
// authcodetest contract suite against SQLite (default) or PostgreSQL
// when ONEAUTH_TEST_PGDB is set, mirroring the GORMAppStore /
// GORMDeviceAuthStore test setup.
package gorm

import (
	"context"
	"testing"
	"time"

	"github.com/panyam/oneauth/authcodetest"
	"github.com/panyam/oneauth/core"
)

// TestGORMAuthorizationCodeStore_Contract runs the shared
// AuthorizationCodeStore contract suite against the GORM backend.
// Each scenario gets a fresh database; Reopen constructs a new store
// over the same *gorm.DB so RestartPersists simulates a fresh process
// opening the same database.
func TestGORMAuthorizationCodeStore_Contract(t *testing.T) {
	authcodetest.RunAll(t, func(t *testing.T) authcodetest.Backend {
		db := setupTestDB(t)
		return authcodetest.Backend{
			Store:  NewAuthorizationCodeStore(db),
			Reopen: func() core.AuthorizationCodeStore { return NewAuthorizationCodeStore(db) },
		}
	})
}

// A code bound to a DPoP key (RFC 9449 §10) must read back with that binding
// intact. The thumbprint lives in its own column rather than inside an
// existing JSON blob, so a mapping mistake would drop it silently and turn a
// key-bound code back into one any interceptor can redeem.
//
// See: https://github.com/panyam/oneauth/issues/374
func TestGORMAuthorizationCodeStore_DPoPJKTRoundTrip(t *testing.T) {
	const jkt = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	ctx := context.Background()
	store := NewAuthorizationCodeStore(setupTestDB(t))

	_, err := store.CreateAuthorizationCode(ctx, &core.CreateAuthorizationCodeRequest{
		Code: &core.AuthorizationCode{
			Code:        "code-bound",
			ClientID:    "client-1",
			RedirectURI: "https://app.example/cb",
			Subject:     "user-1",
			DPoPJKT:     jkt,
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(time.Minute),
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.GetAuthorizationCode(ctx, &core.GetAuthorizationCodeRequest{Code: "code-bound"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Code.DPoPJKT != jkt {
		t.Fatalf("read back dpop_jkt %q, want %q", got.Code.DPoPJKT, jkt)
	}
}

// An unbound code reads back with an empty thumbprint, which is what keeps
// the enforcement branch off for every client that does not send dpop_jkt.
func TestGORMAuthorizationCodeStore_UnboundCodeHasNoJKT(t *testing.T) {
	ctx := context.Background()
	store := NewAuthorizationCodeStore(setupTestDB(t))

	_, err := store.CreateAuthorizationCode(ctx, &core.CreateAuthorizationCodeRequest{
		Code: &core.AuthorizationCode{
			Code: "code-plain", ClientID: "client-1", RedirectURI: "https://app.example/cb",
			Subject: "user-1", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.GetAuthorizationCode(ctx, &core.GetAuthorizationCodeRequest{Code: "code-plain"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Code.DPoPJKT != "" {
		t.Fatalf("unbound code read back with dpop_jkt %q", got.Code.DPoPJKT)
	}
}
