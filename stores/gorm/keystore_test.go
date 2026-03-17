//go:build !wasm
// +build !wasm

// Tests for the GORM SQL-based WritableKeyStore implementation (SQLite and PostgreSQL).

package gorm

import (
	"fmt"
	"os"
	"strings"
	"testing"

	oa "github.com/panyam/oneauth"
	"github.com/panyam/oneauth/keystoretest"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// sanitizeSchemaName creates a safe PostgreSQL schema name from a test name.
func sanitizeSchemaName(name string) string {
	r := strings.NewReplacer("/", "_", " ", "_", "-", "_", ".", "_")
	s := r.Replace(strings.ToLower(name))
	if len(s) > 50 {
		s = s[:50]
	}
	return "test_" + s
}

// setupTestDB returns a GORM DB for testing.
// If ONEAUTH_TEST_PGDB is set, uses PostgreSQL with per-test schema isolation.
// Otherwise falls back to SQLite in-memory.
func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	pgDB := os.Getenv("ONEAUTH_TEST_PGDB")
	if pgDB != "" {
		return setupPostgresDB(t, pgDB)
	}
	return setupSQLiteDB(t)
}

func setupSQLiteDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open SQLite: %v", err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("Failed to migrate: %v", err)
	}
	return db
}

func setupPostgresDB(t *testing.T, dbName string) *gorm.DB {
	t.Helper()

	port := os.Getenv("ONEAUTH_TEST_PGPORT")
	if port == "" {
		port = "5432"
	}
	user := os.Getenv("ONEAUTH_TEST_PGUSER")
	if user == "" {
		user = "postgres"
	}
	password := os.Getenv("ONEAUTH_TEST_PGPASSWORD")
	if password == "" {
		password = "testpassword"
	}
	host := os.Getenv("ONEAUTH_TEST_PGHOST")
	if host == "" {
		host = "localhost"
	}

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbName)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open PostgreSQL: %v", err)
	}

	// Create isolated schema per test
	schema := sanitizeSchemaName(t.Name())
	sqlDB, _ := db.DB()
	sqlDB.Exec("CREATE SCHEMA IF NOT EXISTS " + schema)
	sqlDB.Exec("SET search_path TO " + schema)

	// Re-open with search_path set
	dsnWithSchema := dsn + " search_path=" + schema
	db, err = gorm.Open(postgres.Open(dsnWithSchema), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open PostgreSQL with schema: %v", err)
	}

	if err := AutoMigrate(db); err != nil {
		t.Fatalf("Failed to migrate: %v", err)
	}

	t.Cleanup(func() {
		sqlDB, _ := db.DB()
		sqlDB.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
		sqlDB.Close()
	})

	return db
}

// TestGORMKeyStore runs the shared WritableKeyStore test suite against the GORM-backed implementation.
func TestGORMKeyStore(t *testing.T) {
	keystoretest.RunAll(t, func(t *testing.T) oa.WritableKeyStore {
		return NewKeyStore(setupTestDB(t))
	})
}
