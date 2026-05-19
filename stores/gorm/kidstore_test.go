//go:build !wasm
// +build !wasm

// Tests for the GORM SQL-based KidStorage implementation (SQLite and PostgreSQL).

package gorm

import (
	"testing"
	"time"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/kidstoretest"
)

// TestGORMKidStore runs the shared KidStorage conformance suite against
// the GORM-backed implementation (SQLite by default, PostgreSQL when
// ONEAUTH_TEST_PGDB is set — same env contract as TestGORMKeyStore).
func TestGORMKidStore(t *testing.T) {
	kidstoretest.RunAll(t, func(t *testing.T) keys.KidStorage {
		return NewKidStore(setupTestDB(t))
	})
}

// TestGORMKidStorePersistsAcrossInstances mirrors the FS cross-instance
// restart test: two KidStore values over the same *gorm.DB see each
// other's writes, proving the substrate (not just the in-memory handle)
// holds the grace entry.
func TestGORMKidStorePersistsAcrossInstances(t *testing.T) {
	db := setupTestDB(t)

	writer := NewKidStore(db)
	if err := writer.Add("kid-grace", []byte("retired-secret"), "HS256", "app-1", time.Now().Add(1*time.Hour)); err != nil {
		t.Fatalf("writer.Add failed: %v", err)
	}

	reader := NewKidStore(db)
	rec, err := reader.GetKeyByKid("kid-grace")
	if err != nil {
		t.Fatalf("reader.GetKeyByKid failed: %v", err)
	}
	if string(rec.Key.([]byte)) != "retired-secret" {
		t.Errorf("key material mismatch across instances: got %q", rec.Key)
	}
}
