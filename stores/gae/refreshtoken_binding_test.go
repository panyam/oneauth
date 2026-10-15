//go:build !wasm
// +build !wasm

// Tests that a DPoP sender-constraint survives the Datastore refresh-token
// round trip, mirroring stores/gorm/refreshtoken_binding_test.go. A dropped
// binding turns a sender-constrained refresh token back into a bearer token
// that any thief can redeem. Skips unless DATASTORE_PROJECT_ID is set; run
// with `make testds`.
//
// References:
//   - RFC 9449 §5 (https://www.rfc-editor.org/rfc/rfc9449#section-5)
//   - See: https://github.com/panyam/oneauth/issues/88

package gae

import (
	"context"
	"os"
	"testing"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/core"
	"google.golang.org/api/option" //nolint:staticcheck // WithCredentialsFile is simpler for test use
)

const testJKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

func newTestRefreshTokenStore(t *testing.T) *RefreshTokenStore {
	t.Helper()
	projectID := os.Getenv("DATASTORE_PROJECT_ID")
	if projectID == "" {
		t.Skip("DATASTORE_PROJECT_ID not set, skipping GAE RefreshTokenStore tests")
	}
	var opts []option.ClientOption
	if credsFile := os.Getenv("DATASTORE_CREDENTIALS_FILE"); credsFile != "" {
		opts = append(opts, option.WithCredentialsFile(credsFile))
	}
	client, err := datastore.NewClient(context.Background(), projectID, opts...)
	if err != nil {
		t.Fatalf("Failed to create Datastore client: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return NewRefreshTokenStore(client, "oneauth-refresh-binding-test")
}

func TestGAERefreshTokenStore_ConfirmationSurvivesReadAndRotation(t *testing.T) {
	ctx := context.Background()
	store := newTestRefreshTokenStore(t)

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

// An unbound token reads back as nil, not as an empty Confirmation naming no
// key, which would make it unredeemable by anyone.
func TestGAERefreshTokenStore_UnboundTokenStaysUnbound(t *testing.T) {
	ctx := context.Background()
	store := newTestRefreshTokenStore(t)

	created, err := store.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{Subject: "user-1", ClientID: "client-1"})
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
