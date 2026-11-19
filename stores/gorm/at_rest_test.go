//go:build !wasm
// +build !wasm

package gorm

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
)

const atRestCode = "f3a1c9e07d5b4a2896c1e8d7b0a4f6e2c9d1b3a5e7f9081726354a6b8c0d2e4f"

// A copy of the table (a backup, a replica, a leaked dump) must not hold
// a redeemable code.
// See: https://cwe.mitre.org/data/definitions/312.html
// See: https://www.rfc-editor.org/rfc/rfc9700#section-4.14
func TestGORMAuthorizationCode_StoresOnlyADigest(t *testing.T) {
	db := setupTestDB(t)
	s := NewAuthorizationCodeStore(db)
	ctx := context.Background()
	if _, err := s.CreateAuthorizationCode(ctx, &core.CreateAuthorizationCodeRequest{Code: &core.AuthorizationCode{
		Code: atRestCode, ClientID: "c", RedirectURI: "https://app/cb", Subject: "u", ExpiresAt: time.Now().Add(time.Minute),
	}}); err != nil {
		t.Fatal(err)
	}
	var rows []AuthorizationCodeModel
	if err := db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Code != core.AtRestKey(atRestCode) {
		t.Fatalf("stored key = %q, want the digest", rows[0].Code)
	}
	got, err := s.GetAuthorizationCode(ctx, &core.GetAuthorizationCodeRequest{Code: atRestCode})
	if err != nil || got.Code.Code != atRestCode {
		t.Fatalf("lookup by plaintext: %v %v", got, err)
	}
}

// A row written before hashing (plaintext key) still redeems once and is
// then reported used, so an upgrade doesn't break codes in flight or
// reuse detection on recently used ones.
func TestGORMAuthorizationCode_LegacyPlaintextRowStillWorks(t *testing.T) {
	db := setupTestDB(t)
	s := NewAuthorizationCodeStore(db)
	ctx := context.Background()
	if err := db.Create(&AuthorizationCodeModel{Code: atRestCode, ClientID: "c", RedirectURI: "https://app/cb", Subject: "u", ExpiresAt: time.Now().Add(time.Minute)}).Error; err != nil {
		t.Fatal(err)
	}
	first, err := s.ConsumeAuthorizationCode(ctx, &core.ConsumeAuthorizationCodeRequest{Code: atRestCode})
	if err != nil || first.Code.Subject != "u" {
		t.Fatalf("consume legacy row: %v %v", first, err)
	}
	if _, err := s.ConsumeAuthorizationCode(ctx, &core.ConsumeAuthorizationCodeRequest{Code: atRestCode}); !errors.Is(err, core.ErrAuthorizationCodeUsed) {
		t.Fatalf("second consume of legacy row: %v", err)
	}
}

// See: https://cwe.mitre.org/data/definitions/312.html
// See: https://www.rfc-editor.org/rfc/rfc9126#section-2.2
func TestGORMPushedRequest_StoresOnlyADigest(t *testing.T) {
	db := setupTestDB(t)
	s := NewPushedAuthorizationRequestStore(db)
	ctx := context.Background()
	uri := core.PushedRequestURIPrefix + atRestCode
	if _, err := s.CreatePushedAuthorizationRequest(ctx, &core.CreatePushedAuthorizationRequestRequest{Request: &core.PushedAuthorizationRequest{
		RequestURI: uri, ClientID: "c", Payload: url.Values{"scope": {"openid"}}, ExpiresAt: time.Now().Add(time.Minute),
	}}); err != nil {
		t.Fatal(err)
	}
	var rows []PushedAuthorizationRequestModel
	if err := db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].RequestURI != core.AtRestKey(uri) {
		t.Fatalf("stored key = %q, want the digest", rows[0].RequestURI)
	}
	got, err := s.GetPushedAuthorizationRequest(ctx, &core.GetPushedAuthorizationRequestRequest{RequestURI: uri})
	if err != nil || got.Request.RequestURI != uri {
		t.Fatalf("lookup by plaintext: %v %v", got, err)
	}
}

func TestGORMPushedRequest_LegacyPlaintextRowStillWorks(t *testing.T) {
	db := setupTestDB(t)
	s := NewPushedAuthorizationRequestStore(db)
	ctx := context.Background()
	uri := core.PushedRequestURIPrefix + atRestCode
	if err := db.Create(&PushedAuthorizationRequestModel{RequestURI: uri, ClientID: "c", Payload: url.Values{"scope": {"openid"}}, ExpiresAt: time.Now().Add(time.Minute)}).Error; err != nil {
		t.Fatal(err)
	}
	resp, err := s.ConsumePushedAuthorizationRequest(ctx, &core.ConsumePushedAuthorizationRequestRequest{RequestURI: uri})
	if err != nil || !resp.Consumed {
		t.Fatalf("consume legacy row: %v %v", resp, err)
	}
}
