package fs

import (
	"context"
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

func TestFSKidStorePersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	writer := NewFSKidStore(dir)
	if _, err := writer.Add(ctx, &keys.AddKidRequest{Kid: "kid-grace", Key: []byte("retired-secret"), Algorithm: "HS256", ClientID: "app-1", ExpiresAt: time.Now().Add(1 * time.Hour)}); err != nil {
		t.Fatalf("writer.Add failed: %v", err)
	}

	reader := NewFSKidStore(dir)
	resp, err := reader.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: "kid-grace"})
	if err != nil {
		t.Fatalf("reader.GetKeyByKid failed after restart: %v", err)
	}
	rec := resp.Record
	if string(rec.Key.([]byte)) != "retired-secret" {
		t.Errorf("key material did not survive restart: got %q", rec.Key)
	}
	if rec.ClientID != "app-1" {
		t.Errorf("clientID did not survive restart: got %s", rec.ClientID)
	}
}
