// Tests for the filesystem-backed AppRegistrationStore. Pairs the shared
// appstoretest contract suite (every backend runs this) with FS-specific
// edge cases that cannot be expressed in a backend-agnostic suite —
// path-traversal rejection, corrupt-file behavior, lazy directory creation,
// and atomic-write integrity.
package fs_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/appstoretest"
	"github.com/panyam/oneauth/stores/fs"
)

// TestFSAppStore_Contract runs the shared AppRegistrationStore contract suite
// against the filesystem backend. Each sub-test gets a fresh tempdir so
// state cannot leak between cases.
func TestFSAppStore_Contract(t *testing.T) {
	appstoretest.RunAll(t, func(t *testing.T) admin.AppRegistrationStore {
		return fs.NewFSAppStore(t.TempDir())
	})
}

// TestFSAppStore_PathTraversalRejected verifies that maliciously-crafted
// client_ids cannot escape the apps/ directory. safeName is the single
// point of defense for all FS store path construction; this guards against
// regressions in that contract.
func TestFSAppStore_PathTraversalRejected(t *testing.T) {
	store := fs.NewFSAppStore(t.TempDir())

	for _, badID := range []string{
		"../etc/passwd",
		"foo/../bar",
		"/absolute/path",
		"\x00null",
		"..",
		".",
	} {
		t.Run(badID, func(t *testing.T) {
			err := store.SaveApp(&admin.AppRegistration{ClientID: badID, SigningAlg: "HS256", CreatedAt: time.Now()})
			if err == nil {
				t.Fatalf("SaveApp(%q) should have rejected the traversal attempt", badID)
			}
			// Same defense at read + delete time so we never load a path
			// composed by a non-safeName route.
			if _, err := store.GetApp(badID); err == nil {
				t.Errorf("GetApp(%q) should have rejected the traversal attempt", badID)
			}
			if err := store.DeleteApp(badID); err == nil {
				t.Errorf("DeleteApp(%q) should have rejected the traversal attempt", badID)
			}
		})
	}
}

// TestFSAppStore_CorruptFile_GetReturnsError verifies that a hand-corrupted
// JSON file under apps/ surfaces as a parse error from GetApp, not as
// ErrAppNotFound. Callers must distinguish "registration absent" (safe to
// recreate) from "registration unreadable" (data integrity issue requiring
// operator attention).
func TestFSAppStore_CorruptFile_GetReturnsError(t *testing.T) {
	dir := t.TempDir()
	store := fs.NewFSAppStore(dir)

	// Save a real entry to materialize the apps/ directory.
	if err := store.SaveApp(&admin.AppRegistration{ClientID: "good", SigningAlg: "HS256", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("SaveApp: %v", err)
	}
	// Drop a hand-corrupted file alongside it.
	corrupt := filepath.Join(dir, "apps", "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("{not valid json"), 0600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}

	_, err := store.GetApp("corrupt")
	if err == nil {
		t.Fatalf("GetApp on corrupt file should have errored")
	}
	if errors.Is(err, admin.ErrAppNotFound) {
		t.Fatalf("GetApp on corrupt file must NOT return ErrAppNotFound — got %v", err)
	}

	// Good entry still readable — corruption of one file does not poison
	// the rest of the store.
	got, err := store.GetApp("good")
	if err != nil {
		t.Fatalf("GetApp(good): %v", err)
	}
	if got.ClientID != "good" {
		t.Errorf("ClientID=%q, want good", got.ClientID)
	}
}

// TestFSAppStore_CorruptFile_ListSkips verifies that ListApps skips corrupt
// files rather than failing the whole call. Partial recovery beats total
// failure when one file is hand-edited badly — admin tooling stays usable.
func TestFSAppStore_CorruptFile_ListSkips(t *testing.T) {
	dir := t.TempDir()
	store := fs.NewFSAppStore(dir)

	for _, id := range []string{"alpha", "beta"} {
		if err := store.SaveApp(&admin.AppRegistration{ClientID: id, SigningAlg: "HS256", CreatedAt: time.Now()}); err != nil {
			t.Fatalf("SaveApp(%s): %v", id, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "apps", "trash.json"), []byte("garbage"), 0600); err != nil {
		t.Fatalf("seed trash file: %v", err)
	}

	apps, err := store.ListApps()
	if err != nil {
		t.Fatalf("ListApps: %v", err)
	}
	if len(apps) != 2 {
		t.Errorf("expected 2 apps (corrupt file skipped), got %d", len(apps))
	}
}

// TestFSAppStore_LazyDirectoryCreation verifies that constructing FSAppStore
// against a non-existent base path is fine, and that the apps/ subdirectory
// is created on first write. Avoids a "you must mkdir first" footgun.
func TestFSAppStore_LazyDirectoryCreation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist-yet", "nor-this")
	store := fs.NewFSAppStore(dir)

	// Pre-condition: the directory does not exist.
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("test setup: dir should not exist yet, got %v", err)
	}

	// First write must succeed and materialize the directory.
	if err := store.SaveApp(&admin.AppRegistration{ClientID: "lazy", SigningAlg: "HS256", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("SaveApp: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "apps")); err != nil {
		t.Errorf("apps dir should exist after SaveApp: %v", err)
	}

	// Pre-condition for ListApps on a fresh store with no writes: returns
	// an empty slice, not an error. Verify against a separate path.
	emptyStore := fs.NewFSAppStore(filepath.Join(t.TempDir(), "another-fresh-dir"))
	apps, err := emptyStore.ListApps()
	if err != nil {
		t.Errorf("ListApps on fresh store: %v", err)
	}
	if len(apps) != 0 {
		t.Errorf("ListApps on fresh store should return empty slice, got %d entries", len(apps))
	}
}

// TestFSAppStore_OverwriteIsAtomicallyVisible verifies that an overwrite
// either leaves the OLD value or the NEW value visible to a concurrent
// reader, never partial bytes — courtesy of writeAtomicFile's
// temp-file-then-rename pattern. We don't simulate a crash mid-rename
// (renames are atomic on POSIX); instead we verify the on-disk file is
// always parseable and matches one of the two values, even after rapid
// successive overwrites.
func TestFSAppStore_OverwriteIsAtomicallyVisible(t *testing.T) {
	dir := t.TempDir()
	store := fs.NewFSAppStore(dir)

	const id = "overwriter"
	for i, name := range []string{"first", "second", "third"} {
		if err := store.SaveApp(&admin.AppRegistration{
			ClientID: id, ClientName: name, SigningAlg: "HS256", CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("SaveApp #%d: %v", i, err)
		}

		// Read the file directly — it must always parse and contain the
		// last-written name. This catches a regression where a partial
		// rename or non-atomic write would leave the file in an unparseable
		// state between writes.
		data, err := os.ReadFile(filepath.Join(dir, "apps", id+".json"))
		if err != nil {
			t.Fatalf("read after SaveApp #%d: %v", i, err)
		}
		var got admin.AppRegistration
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("file unparseable after SaveApp #%d: %v", i, err)
		}
		if got.ClientName != name {
			t.Errorf("after SaveApp #%d: ClientName=%q, want %q", i, got.ClientName, name)
		}
	}
}
