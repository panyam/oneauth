package fs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/panyam/oneauth/client"
)

func TestFSCredentialStore_GetSetCredential(t *testing.T) {
	// Use temp directory
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")

	store, err := NewFSCredentialStore(path, "")
	if err != nil {
		t.Fatalf("NewFSCredentialStore() error = %v", err)
	}

	// Initially empty
	cred, err := store.GetCredential("http://localhost:8080")
	if err != nil {
		t.Fatalf("GetCredential() error = %v", err)
	}
	if cred != nil {
		t.Errorf("expected nil credential, got %+v", cred)
	}

	// Set a credential
	testCred := &client.ServerCredential{
		AccessToken:  "test-token",
		RefreshToken: "refresh-token",
		UserEmail:    "user@example.com",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
	}

	if err := store.SetCredential("http://localhost:8080", testCred); err != nil {
		t.Fatalf("SetCredential() error = %v", err)
	}

	// Get it back
	cred, err = store.GetCredential("http://localhost:8080")
	if err != nil {
		t.Fatalf("GetCredential() error = %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential, got nil")
	}
	if cred.AccessToken != "test-token" {
		t.Errorf("AccessToken = %v, want test-token", cred.AccessToken)
	}
	if cred.RefreshToken != "refresh-token" {
		t.Errorf("RefreshToken = %v, want refresh-token", cred.RefreshToken)
	}
}

func TestFSCredentialStore_URLNormalization(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")

	store, err := NewFSCredentialStore(path, "")
	if err != nil {
		t.Fatalf("NewFSCredentialStore() error = %v", err)
	}

	testCred := &client.ServerCredential{
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	// Set with full URL
	store.SetCredential("http://localhost:8080/api/v1", testCred)

	// Should find with normalized URL
	cred, _ := store.GetCredential("http://localhost:8080")
	if cred == nil {
		t.Error("expected to find credential with normalized URL")
	}

	// Should find with different path
	cred, _ = store.GetCredential("http://localhost:8080/different/path")
	if cred == nil {
		t.Error("expected to find credential with different path")
	}
}

func TestFSCredentialStore_RemoveCredential(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")

	store, err := NewFSCredentialStore(path, "")
	if err != nil {
		t.Fatalf("NewFSCredentialStore() error = %v", err)
	}

	testCred := &client.ServerCredential{
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	store.SetCredential("http://localhost:8080", testCred)
	store.SetCredential("http://localhost:9090", testCred)

	// Remove one
	if err := store.RemoveCredential("http://localhost:8080"); err != nil {
		t.Fatalf("RemoveCredential() error = %v", err)
	}

	// First should be gone
	cred, _ := store.GetCredential("http://localhost:8080")
	if cred != nil {
		t.Error("credential should be removed")
	}

	// Second should still exist
	cred, _ = store.GetCredential("http://localhost:9090")
	if cred == nil {
		t.Error("other credential should still exist")
	}
}

func TestFSCredentialStore_ListServers(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")

	store, err := NewFSCredentialStore(path, "")
	if err != nil {
		t.Fatalf("NewFSCredentialStore() error = %v", err)
	}

	testCred := &client.ServerCredential{
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	store.SetCredential("http://localhost:8080", testCred)
	store.SetCredential("http://localhost:9090", testCred)
	store.SetCredential("https://example.com", testCred)

	servers, err := store.ListServers()
	if err != nil {
		t.Fatalf("ListServers() error = %v", err)
	}

	if len(servers) != 3 {
		t.Errorf("len(servers) = %d, want 3", len(servers))
	}
}

func TestFSCredentialStore_SaveAndReload(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")

	// Create store and add credential
	store1, err := NewFSCredentialStore(path, "")
	if err != nil {
		t.Fatalf("NewFSCredentialStore() error = %v", err)
	}

	testCred := &client.ServerCredential{
		AccessToken:  "persisted-token",
		RefreshToken: "refresh-token",
		UserEmail:    "user@example.com",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
	}

	store1.SetCredential("http://localhost:8080", testCred)

	if err := store1.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("credentials file not created")
	}

	// Create new store from same file
	store2, err := NewFSCredentialStore(path, "")
	if err != nil {
		t.Fatalf("NewFSCredentialStore() error = %v", err)
	}

	cred, err := store2.GetCredential("http://localhost:8080")
	if err != nil {
		t.Fatalf("GetCredential() error = %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential to be persisted")
	}
	if cred.AccessToken != "persisted-token" {
		t.Errorf("AccessToken = %v, want persisted-token", cred.AccessToken)
	}
	if cred.RefreshToken != "refresh-token" {
		t.Errorf("RefreshToken = %v, want refresh-token", cred.RefreshToken)
	}
}

func TestFSCredentialStore_FilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")

	store, err := NewFSCredentialStore(path, "")
	if err != nil {
		t.Fatalf("NewFSCredentialStore() error = %v", err)
	}

	testCred := &client.ServerCredential{
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	store.SetCredential("http://localhost:8080", testCred)
	store.Save()

	// Check file permissions (should be 0600)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("file permissions = %o, want 0600", mode)
	}
}

func TestFSCredentialStore_DefaultPath(t *testing.T) {
	// Test with empty path - should use default
	store, err := NewFSCredentialStore("", "testapp")
	if err != nil {
		t.Fatalf("NewFSCredentialStore() error = %v", err)
	}

	path := store.Path()
	if path == "" {
		t.Error("path should not be empty")
	}

	// Should contain app name in path
	if filepath.Base(filepath.Dir(path)) != "testapp" {
		t.Logf("path = %s (app name dir may vary by platform)", path)
	}
}
