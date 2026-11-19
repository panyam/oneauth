//go:build !wasm
// +build !wasm

package gae

import (
	"context"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/panyam/oneauth/core"
)

const atRestDeviceCode = "6f8e2d4c1b3a59786a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f"

// No entity key or property may hold the device code, before or after
// approval.
// See: https://www.rfc-editor.org/rfc/rfc8628#section-5.2
// See: https://cwe.mitre.org/data/definitions/312.html
func TestGAEDeviceAuth_DeviceCodeNeverStored(t *testing.T) {
	const ns = "oneauth-device-atrest-test"
	client, _ := emulatorClient(t, KindDeviceAuthorization, ns)
	s := NewDeviceAuthStore(client, ns)
	ctx := context.Background()
	if _, err := s.CreateDeviceAuthorization(ctx, &core.CreateDeviceAuthorizationRequest{Authorization: &core.DeviceAuthorization{
		DeviceCode: atRestDeviceCode, UserCode: "WDJB-MJHT", ClientID: "c", Status: core.DeviceAuthorizationStatusPending,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute), IntervalSeconds: 5,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveDeviceAuthorization(ctx, &core.ApproveDeviceAuthorizationRequest{UserCode: "WDJB-MJHT", ApprovedSubject: "u"}); err != nil {
		t.Fatal(err)
	}
	var es []DeviceAuthorizationEntity
	keys, err := client.GetAll(ctx, datastore.NewQuery(KindDeviceAuthorization).Namespace(ns), &es)
	if err != nil || len(keys) != 1 {
		t.Fatalf("entities: %d, %v", len(keys), err)
	}
	if strings.Contains(keys[0].Name, atRestDeviceCode) || es[0].DeviceCode != "" {
		t.Fatal("the device code is stored in plaintext")
	}
}

// An entity written before issue 473 (keyed by the plaintext code, with a
// device_code property) still approves, polls and deletes, and the first
// rewrite drops the property.
func TestGAEDeviceAuth_LegacyEntityStillWorks(t *testing.T) {
	const ns = "oneauth-device-legacy-test"
	client, _ := emulatorClient(t, KindDeviceAuthorization, ns)
	s := NewDeviceAuthStore(client, ns)
	ctx := context.Background()
	legacy := s.legacyDeviceKey(atRestDeviceCode)
	if _, err := client.Put(ctx, legacy, &DeviceAuthorizationEntity{
		DeviceCode: atRestDeviceCode, UserCode: "WDJB-MJHT", UserCodeUpper: core.UpperUserCode("WDJB-MJHT"), ClientID: "c",
		Status: string(core.DeviceAuthorizationStatusPending), CreatedAt: time.Now().UnixNano(), ExpiresAt: time.Now().Add(5 * time.Minute).UnixNano(), IntervalSeconds: 5,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveDeviceAuthorization(ctx, &core.ApproveDeviceAuthorizationRequest{UserCode: "WDJB-MJHT", ApprovedSubject: "u"}); err != nil {
		t.Fatalf("approve legacy entity: %v", err)
	}
	got, err := s.UpdatePollingState(ctx, &core.UpdatePollingStateRequest{DeviceCode: atRestDeviceCode, PolledAt: time.Now()})
	if err != nil || got.Authorization.Status != core.DeviceAuthorizationStatusApproved {
		t.Fatalf("poll legacy entity: %+v %v", got, err)
	}
	var e DeviceAuthorizationEntity
	if err := client.Get(ctx, legacy, &e); err != nil || e.DeviceCode != "" {
		t.Fatalf("legacy entity after rewrite: device_code=%q err=%v", e.DeviceCode, err)
	}
	if _, err := s.DeleteDeviceAuthorization(ctx, &core.DeleteDeviceAuthorizationRequest{DeviceCode: atRestDeviceCode}); err != nil {
		t.Fatalf("delete legacy entity: %v", err)
	}
}
