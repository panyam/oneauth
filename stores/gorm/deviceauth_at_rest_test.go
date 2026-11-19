//go:build !wasm
// +build !wasm

package gorm

import (
	"context"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
)

const atRestDeviceCode = "6f8e2d4c1b3a59786a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f"

// See: https://www.rfc-editor.org/rfc/rfc8628#section-5.2
// See: https://cwe.mitre.org/data/definitions/312.html
func TestGORMDeviceAuth_StoresOnlyADigest(t *testing.T) {
	db := setupTestDB(t)
	s := NewDeviceAuthStore(db)
	ctx := context.Background()
	if _, err := s.CreateDeviceAuthorization(ctx, &core.CreateDeviceAuthorizationRequest{Authorization: &core.DeviceAuthorization{
		DeviceCode: atRestDeviceCode, UserCode: "WDJB-MJHT", ClientID: "c", Status: core.DeviceAuthorizationStatusPending,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute), IntervalSeconds: 5,
	}}); err != nil {
		t.Fatal(err)
	}
	var rows []DeviceAuthorizationModel
	if err := db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].DeviceCode != core.AtRestKey(atRestDeviceCode) {
		t.Fatalf("stored key = %q, want the digest", rows[0].DeviceCode)
	}
}

// A row written before issue 473 (plaintext key) still polls, approves
// and deletes.
func TestGORMDeviceAuth_LegacyPlaintextRowStillWorks(t *testing.T) {
	db := setupTestDB(t)
	s := NewDeviceAuthStore(db)
	ctx := context.Background()
	if err := db.Create(&DeviceAuthorizationModel{
		DeviceCode: atRestDeviceCode, UserCode: "WDJB-MJHT", UserCodeUpper: core.UpperUserCode("WDJB-MJHT"), ClientID: "c",
		Status: string(core.DeviceAuthorizationStatusPending), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute), IntervalSeconds: 5,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveDeviceAuthorization(ctx, &core.ApproveDeviceAuthorizationRequest{UserCode: "WDJB-MJHT", ApprovedSubject: "u"}); err != nil {
		t.Fatalf("approve legacy row: %v", err)
	}
	got, err := s.UpdatePollingState(ctx, &core.UpdatePollingStateRequest{DeviceCode: atRestDeviceCode, PolledAt: time.Now()})
	if err != nil || got.Authorization.Status != core.DeviceAuthorizationStatusApproved || got.Authorization.DeviceCode != atRestDeviceCode {
		t.Fatalf("poll legacy row: %+v %v", got, err)
	}
	if _, err := s.DeleteDeviceAuthorization(ctx, &core.DeleteDeviceAuthorizationRequest{DeviceCode: atRestDeviceCode}); err != nil {
		t.Fatalf("delete legacy row: %v", err)
	}
}
