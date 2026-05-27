//go:build !wasm
// +build !wasm

// Tests for the GORM SQL-based KidStorage implementation (SQLite and PostgreSQL).

package gorm

import (
	"context"
	"testing"
	"time"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/kidstoretest"
)

func TestGORMKidStore(t *testing.T) {
	kidstoretest.RunAll(t, func(t *testing.T) keys.KidStorage {
		return NewKidStore(setupTestDB(t))
	})
}

func TestGORMKidStorePersistsAcrossInstances(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	writer := NewKidStore(db)
	if _, err := writer.Add(ctx, &keys.AddKidRequest{Kid: "kid-grace", Key: []byte("retired-secret"), Algorithm: "HS256", ClientID: "app-1", ExpiresAt: time.Now().Add(1 * time.Hour)}); err != nil {
		t.Fatalf("writer.Add failed: %v", err)
	}

	reader := NewKidStore(db)
	resp, err := reader.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "kid-grace"})
	if err != nil {
		t.Fatalf("reader.GetKeyByKid failed: %v", err)
	}
	if string(resp.Record.Key.([]byte)) != "retired-secret" {
		t.Errorf("key material mismatch across instances: got %q", resp.Record.Key)
	}
}
