package fs

// Tests for the filesystem-based KidStorage implementation. The shared
// conformance suite is in kidstoretest; the cross-instance restart test
// below is FS-specific — it's the headline proof that grace-period kids
// survive a process restart.

import (
	"testing"
	"time"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/kidstoretest"
)

func TestFSKidStore(t *testing.T) {
	kidstoretest.RunAll(t, func(t *testing.T) keys.KidStorage {
		return NewFSKidStore(t.TempDir())
	})
}

// TestFSKidStorePersistsAcrossInstances exercises the actual gap this
// backend closes: a second store instance opened over the same directory
// must see kids written by the first. Without this, "survives a process
// restart" is only an interface-level claim, not a verified behavior.
func TestFSKidStorePersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()

	writer := NewFSKidStore(dir)
	if err := writer.Add("kid-grace", []byte("retired-secret"), "HS256", "app-1", time.Now().Add(1*time.Hour)); err != nil {
		t.Fatalf("writer.Add failed: %v", err)
	}

	// Fresh instance over the same backing directory — simulates a process restart.
	reader := NewFSKidStore(dir)
	rec, err := reader.GetKeyByKid("kid-grace")
	if err != nil {
		t.Fatalf("reader.GetKeyByKid failed after restart: %v", err)
	}
	if string(rec.Key.([]byte)) != "retired-secret" {
		t.Errorf("key material did not survive restart: got %q", rec.Key)
	}
	if rec.ClientID != "app-1" {
		t.Errorf("clientID did not survive restart: got %s", rec.ClientID)
	}
}
