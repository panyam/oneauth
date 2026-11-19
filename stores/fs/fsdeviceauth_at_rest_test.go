package fs_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/stores/fs"
)

const atRestDeviceCode = "6f8e2d4c1b3a59786a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f"

func sampleDeviceAuth() *core.DeviceAuthorization {
	return &core.DeviceAuthorization{
		DeviceCode: atRestDeviceCode, UserCode: "WDJB-MJHT", ClientID: "c", Scopes: []string{"read"},
		Status: core.DeviceAuthorizationStatusPending, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute), IntervalSeconds: 5,
	}
}

// A copy of the directory must not let anyone poll for the device's
// tokens, before or after the user approves.
// See: https://www.rfc-editor.org/rfc/rfc8628#section-5.2
// See: https://cwe.mitre.org/data/definitions/312.html
func TestFSDeviceAuthStore_DeviceCodeNeverOnDisk(t *testing.T) {
	dir := t.TempDir()
	s := fs.NewFSDeviceAuthorizationStore(dir)
	ctx := context.Background()
	if _, err := s.CreateDeviceAuthorization(ctx, &core.CreateDeviceAuthorizationRequest{Authorization: sampleDeviceAuth()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveDeviceAuthorization(ctx, &core.ApproveDeviceAuthorizationRequest{UserCode: "wdjbmjht", ApprovedSubject: "u"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdatePollingState(ctx, &core.UpdatePollingStateRequest{DeviceCode: atRestDeviceCode, PolledAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	requireNotOnDisk(t, dir, atRestDeviceCode)
}

// Files written before issue 473 hold the device code in the record and
// in the user_code pointer. They keep working, and the first rewrite
// drops the plaintext.
func TestFSDeviceAuthStore_LegacyFilesStillWork(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "device_authorizations")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	dsum := sha256.Sum256([]byte(atRestDeviceCode))
	usum := sha256.Sum256([]byte(core.UpperUserCode("WDJB-MJHT")))
	write := func(name string, v any) {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(sub, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("dc-"+hex.EncodeToString(dsum[:])+".json", sampleDeviceAuth())
	write("uc-"+hex.EncodeToString(usum[:])+".json", map[string]string{"device_code": atRestDeviceCode})

	s := fs.NewFSDeviceAuthorizationStore(dir)
	ctx := context.Background()
	if _, err := s.ApproveDeviceAuthorization(ctx, &core.ApproveDeviceAuthorizationRequest{UserCode: "WDJB-MJHT", ApprovedSubject: "u"}); err != nil {
		t.Fatalf("approve through a legacy pointer: %v", err)
	}
	got, err := s.GetByDeviceCode(ctx, &core.GetByDeviceCodeRequest{DeviceCode: atRestDeviceCode})
	if err != nil || got.Authorization.Status != core.DeviceAuthorizationStatusApproved {
		t.Fatalf("legacy record after approve: %v %v", got, err)
	}
	b, _ := os.ReadFile(filepath.Join(sub, "dc-"+hex.EncodeToString(dsum[:])+".json"))
	if len(b) == 0 || strings.Contains(string(b), atRestDeviceCode) {
		t.Fatal("rewriting a legacy record kept the plaintext device code")
	}
	if _, err := s.DeleteDeviceAuthorization(ctx, &core.DeleteDeviceAuthorizationRequest{DeviceCode: atRestDeviceCode}); err != nil {
		t.Fatalf("delete legacy record: %v", err)
	}
}
